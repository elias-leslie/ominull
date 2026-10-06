"""Fixed LXC150 snapshot preparation; no caller-defined hosts or shell commands."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

import observer as obs

SOURCE = "ominull-production-state"
BACKUP_MOUNT = Path("/media/kasadis/Backups")
BACKUP_UUID = "068613B88613A769"
DESTINATION = BACKUP_MOUNT / SOURCE
NODE = "davion-gem"
GUEST = 150
DEADLINE_SECONDS = 3600
RESERVE_BYTES = 25 * 1024**3
REQUEST_KEYS = {"contract_version", "operation", "project", "source_id", "backup_id"}

# Each attempt has a newly-created private directory and immutable ownership
# marker. All remote operations are fixed Python programs, not supplied commands.
REMOTE_COMMON = r'''
import hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tarfile
attempt, backup_id = sys.argv[1:]
assert re.fullmatch(r"[0-9a-f]{32}", attempt)
assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", backup_id)
root = pathlib.Path("/var/lib/vz/dump")
directory = root / ("st-ominull-" + attempt)
assert root.resolve() == root and root.is_dir()
def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout
def api(*args):
    return json.loads(command("pvesh", *args, "--output-format", "json"))
def owned():
    assert directory.resolve() == directory and directory.is_dir()
    assert directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700
    marker = directory / "attempt.json"
    assert marker.is_file() and not marker.is_symlink()
    value = json.loads(marker.read_text())
    assert value["attempt"] == attempt and value["backup_id"] == backup_id and value["guest"] == 150
    return value
'''

REMOTE_CREATE = REMOTE_COMMON + r'''
assert command("hostname", "-s").strip() == "davion-gem"
config = api("get", "/nodes/davion-gem/lxc/150/config")
assert not any(re.fullmatch(r"mp\d+", k) for k in config), "Additional mount requires review"
assert config["rootfs"].split(",", 1)[0] == "local-lvm:vm-150-disk-0"
assert not config.get("lock") and not config.get("snapstate")
storage = api("get", "/storage/local")
assert storage["type"] == "dir" and storage["path"] == "/var/lib/vz"
assert "backup" in storage["content"].split(",")
used = int(command("pct", "exec", "150", "--", "python3", "-c", "import shutil;print(shutil.disk_usage('/').used)").strip())
assert shutil.disk_usage(root).free >= used + 10 * 1024**3, "Insufficient remote staging space"
directory.mkdir(mode=0o700)
marker = {"attempt": attempt, "backup_id": backup_id, "guest": 150}
with (directory / "attempt.json").open("x") as file:
    os.fchmod(file.fileno(), 0o600)
    json.dump(marker, file)
task = api("create", "/nodes/davion-gem/vzdump", "--vmid", "150", "--mode", "snapshot",
           "--dumpdir", str(directory), "--tmpdir", "/var/tmp", "--compress", "0", "--remove", "0")
assert isinstance(task, str) and task.startswith("UPID:davion-gem:")
marker["task"] = task
(directory / "attempt.json").write_text(json.dumps(marker))
print(json.dumps({"task": task, "used_bytes": used}))
'''

REMOTE_STATUS = REMOTE_COMMON + r'''
marker = owned()
state = api("get", "/nodes/davion-gem/tasks/" + marker["task"] + "/status")
print(json.dumps({k:state.get(k) for k in ["status", "exitstatus"]}))
'''

REMOTE_ARTIFACT = REMOTE_COMMON + r'''
marker = owned()
state = api("get", "/nodes/davion-gem/tasks/" + marker["task"] + "/status")
assert state.get("status") == "stopped" and state.get("exitstatus") == "OK"
archives = [p for p in directory.iterdir() if re.fullmatch(r"vzdump-lxc-150-[0-9_\-]+\.tar", p.name)]
assert len(archives) == 1
archive = archives[0]
info = archive.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size > 0
digest = hashlib.sha256()
with archive.open("rb") as file:
    for chunk in iter(lambda: file.read(1024*1024), b""):
        digest.update(chunk)
after = archive.lstat()
assert (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
required = {"var/lib/ominull/ominull.db",
            "var/lib/ominull/evidence.key", "var/lib/ominull/evidence/receipt.key",
            "var/lib/ominull-response-authority/authority.db",
            "var/lib/ominull-response-authority/secret.key",
            "opt/ominull/bin/certs/ca.key", "opt/ominull/bin/certs/ca.crt",
            "opt/ominull/bin/certs/server.key", "opt/ominull/bin/certs/server.crt",
            "etc/ominull/hub.env", "etc/ominull/response-authority.env", "etc/ominull/admin.key"}
optional_wal = {"var/lib/ominull/ominull.db-wal", "var/lib/ominull-response-authority/authority.db-wal"}
found = set()
wal_found = set()
with tarfile.open(archive, "r:") as tar:
    for member in tar:
        name = member.name.removeprefix("./")
        if name in required:
            assert member.isfile() and member.size > 0
            found.add(name)
        elif name in optional_wal:
            assert member.isfile(), "WAL must be a regular file when present"
            wal_found.add(name)
assert found == required, "Required production data missing from archive"
print(json.dumps({"path":str(archive), "size_bytes":info.st_size, "sha256":digest.hexdigest(),
                  "required_paths_verified":sorted(found), "wal_paths_verified":sorted(wal_found)}))
'''

REMOTE_CLEANUP = REMOTE_COMMON + r'''
marker = owned()
state = api("get", "/nodes/davion-gem/tasks/" + marker["task"] + "/status")
assert state.get("status") == "stopped" and state.get("exitstatus") == "OK"
# Refuse unexpected contents rather than recursively deleting a foreign tree.
children = list(directory.iterdir())
for child in children:
    assert child.is_file() and not child.is_symlink() and child.stat().st_uid == os.getuid()
    assert child.name == "attempt.json" or re.fullmatch(r"vzdump-lxc-150-[0-9_\-]+\.(tar(?:\.notes)?|log)", child.name)
for child in children:
    child.unlink()
directory.rmdir()
print(json.dumps({"cleaned":True}))
'''


def parse_request(raw):
    obs.require(len(raw.encode()) <= 16384, "request_too_large")
    request = obs.parse_json(raw)
    obs.require(isinstance(request, dict) and set(request) == REQUEST_KEYS, "request_fields")
    obs.require(type(request["contract_version"]) is int and request["contract_version"] == 1,
                "request_version")
    obs.require(request["operation"] == "prepare_backup" and request["project"] == "ominull"
                and request["source_id"] == SOURCE, "request_identity")
    obs.require(isinstance(request["backup_id"], str) and obs.IDENTIFIER.fullmatch(request["backup_id"]),
                "request_backup_id")
    return request


def ssh_argv(config, command):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o",
            "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "--", config["ssh_alias"], command]


def remote(config, script, attempt, backup_id):
    command = "python3 -c " + shlex.quote(script) + " " + shlex.quote(attempt) + " " + shlex.quote(backup_id)
    try:
        result = subprocess.run(ssh_argv(config, command), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise obs.ObservationError("backup_remote_unavailable") from exc
    obs.require(result.returncode == 0, "backup_remote_failed")
    obs.require(len(result.stdout) <= 16384, "backup_remote_output")
    return obs.parse_json(result.stdout)


def private_directory(path):
    obs.require(path.is_absolute() and path.resolve() == path, "backup_local_path")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    obs.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "backup_local_permissions")


def require_backup_mount():
    obs.require(BACKUP_MOUNT.resolve() == BACKUP_MOUNT, "backup_mount_path")
    try:
        result = subprocess.run(["findmnt", "--json", "--mountpoint", str(BACKUP_MOUNT),
                                 "--types", "ntfs,ntfs3,fuseblk", "--output", "TARGET,UUID,FSTYPE"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise obs.ObservationError("backup_mount_unavailable") from exc
    obs.require(result.returncode == 0 and len(result.stdout) <= 16384, "backup_mount_unavailable")
    mounts = obs.parse_json(result.stdout)
    rows = mounts.get("filesystems") if isinstance(mounts, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise obs.ObservationError("backup_mount_identity")
    obs.require(rows[0].get("target") == str(BACKUP_MOUNT)
                and isinstance(rows[0].get("uuid"), str) and rows[0]["uuid"].upper() == BACKUP_UUID
                and rows[0].get("fstype") in {"ntfs", "ntfs3", "fuseblk"}, "backup_mount_identity")


def fetch(config, artifact, destination):
    require_backup_mount()
    command = "cat -- " + shlex.quote(artifact["path"])
    try:
        with destination.open("xb") as file:
            os.fchmod(file.fileno(), 0o600)
            result = subprocess.run(ssh_argv(config, command), stdin=subprocess.DEVNULL,
                                    stdout=file, stderr=subprocess.PIPE, timeout=DEADLINE_SECONDS, check=False)
            file.flush()
            os.fsync(file.fileno())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise obs.ObservationError("backup_fetch_failed") from exc
    obs.require(result.returncode == 0, "backup_fetch_failed")
    obs.require(destination.stat().st_size == artifact["size_bytes"], "backup_fetch_size")
    obs.require(obs.sha256_file(destination) == artifact["sha256"], "backup_fetch_digest")


def publish(staging, response):
    current = DESTINATION / "current"
    if current.exists() or current.is_symlink():
        private_directory(current)
        obs.regular_file(current / "lxc-150.tar", private=True)
        prior = obs.parse_json(obs.regular_file(current / "manifest.json").read_bytes())
        obs.require(prior.get("status") == "completed" and prior.get("source_id") == SOURCE
                    and prior.get("archive_path") == str(current / "lxc-150.tar")
                    and set(p.name for p in current.iterdir()) == {"lxc-150.tar", "manifest.json"},
                    "backup_existing_publication")
    manifest = staging / "manifest.json"
    with manifest.open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(response, file, sort_keys=True)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if current.exists():
        # Linux rename exchange atomically replaces the complete generation.
        libc = ctypes.CDLL(None, use_errno=True)
        obs.require(libc.renameat2(-100, os.fsencode(staging), -100, os.fsencode(current), 2) == 0,
                    "backup_atomic_publication")
    else:
        staging.rename(current)
    descriptor = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    # After exchange staging contains only the validated previous publication.
    if staging.exists():
        shutil.rmtree(staging)


def prepare(request, root):
    config, digest = obs.load_config(root, require_deployment_inputs=False)
    obs.require(config["lxc_id"] == GUEST, "backup_protected_target")
    require_backup_mount()
    private_directory(DESTINATION)
    attempt = uuid.uuid4().hex
    staging = DESTINATION / (".attempt-" + attempt)
    staging.mkdir(mode=0o700)
    base = {"schema_version": 1, "project": "ominull", "source_id": SOURCE,
            "backup_id": request["backup_id"], "target_id": GUEST,
            "protected_config_sha256": digest, "backup_mode": "snapshot", "compression": "none"}
    published = False
    try:
        job = remote(config, REMOTE_CREATE, attempt, request["backup_id"])
        base["proxmox_task_id"] = job["task"]
        deadline = time.monotonic() + DEADLINE_SECONDS
        while True:
            state = remote(config, REMOTE_STATUS, attempt, request["backup_id"])
            if state.get("status") == "stopped":
                obs.require(state.get("exitstatus") == "OK", "backup_proxmox_task_failed")
                break
            obs.require(state.get("status") == "running" and time.monotonic() < deadline,
                        "backup_proxmox_task_timeout")
            time.sleep(5)
        artifact = remote(config, REMOTE_ARTIFACT, attempt, request["backup_id"])
        obs.require(type(artifact.get("size_bytes")) is int and artifact["size_bytes"] > 0
                    and isinstance(artifact.get("sha256"), str) and obs.DIGEST.fullmatch(artifact["sha256"])
                    and isinstance(artifact.get("path"), str)
                    and re.fullmatch(r"/var/lib/vz/dump/st-ominull-" + attempt
                                     + r"/vzdump-lxc-150-[0-9_\-]+\.tar", artifact["path"]),
                    "backup_remote_artifact")
        obs.require(shutil.disk_usage(DESTINATION).free >= artifact["size_bytes"] + RESERVE_BYTES,
                    "backup_local_capacity")
        fetch(config, artifact, staging / "lxc-150.tar")
        response = {**base, "status": "completed", "archive_path": str(DESTINATION / "current/lxc-150.tar"),
                    "manifest_path": str(DESTINATION / "current/manifest.json"),
                    "size_bytes": artifact["size_bytes"], "sha256": artifact["sha256"],
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "required_paths_verified": artifact["required_paths_verified"],
                    "wal_paths_verified": artifact["wal_paths_verified"]}
        publish(staging, response)
        published = True
        # Only our newly generated attempt is removed, after verified publication.
        cleanup = remote(config, REMOTE_CLEANUP, attempt, request["backup_id"])
        obs.require(cleanup == {"cleaned": True}, "backup_remote_cleanup")
        return response
    except (obs.ObservationError, OSError, ValueError, KeyError, TypeError) as exc:
        error = str(exc) if isinstance(exc, obs.ObservationError) else "backup_preparation_failed"
        failure = {**base, "status": "failed", "error": error, "attempt_id": attempt,
                   "publication_completed": published}
        # Preserve local/remote failed attempt data, never turn stale bytes into success.
        failure_path = DESTINATION / ("failure-" + attempt + ".json")
        with failure_path.open("x") as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(failure, file, sort_keys=True)
        return failure


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise obs.ObservationError("invalid_arguments")
    parser = Parser(description="Prepare the fixed LXC150 source; invoked by managed ST capture")
    parser.add_argument("--request", action="append")
    try:
        args = parser.parse_args(argv)
        obs.require(args.request is None or len(args.request) == 1, "multiple_requests")
        request = parse_request(args.request[0] if args.request else sys.stdin.read(16385))
        code_root = Path(__file__).resolve().parents[2]
        root = obs.context_root(os.environ.get("ST_EXTENSION_CONTEXT", ""), code_root)
        result = prepare(request, root)
    except (obs.ObservationError, OSError, ValueError) as exc:
        error = str(exc) if isinstance(exc, obs.ObservationError) else "backup_input_failed"
        print(json.dumps({"schema_version": 1, "status": "failed", "error": error}, separators=(",", ":")))
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] == "completed" else 1
