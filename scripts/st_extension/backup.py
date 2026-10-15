"""Fixed LXC150 snapshot preparation; no caller-defined hosts or shell commands."""
import argparse
import json
import os
import pwd
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
# The removable backup volume as udisks mounts it for the invoking user.
BACKUP_MOUNT = Path("/media") / pwd.getpwuid(os.getuid()).pw_name / "Backups"
BACKUP_UUID = "068613B88613A769"
DESTINATION = BACKUP_MOUNT / SOURCE
NODE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\Z")
GUEST = 150
DEADLINE_SECONDS = 3600
RESERVE_BYTES = 25 * 1024**3
EVIDENCE_KEEP = 20  # Newest failure/retirement/recovery markers kept per kind.
REQUEST_KEYS = {"contract_version", "operation", "project", "source_id", "backup_id"}

# Each attempt has a newly-created private directory and immutable ownership
# marker. Every remote operation is a fixed verb of pve_backup_dispatch.py:
# through backup_ssh_alias (a forced-command key root installs on Proxmox) the
# verb is all that crosses; until then the same file is sent over ssh_alias.
DISPATCHER = Path(__file__).with_name("pve_backup_dispatch.py")
REMOTE_CREATE, REMOTE_GUEST, REMOTE_STATUS = "create", "guest", "status"
REMOTE_ARTIFACT, REMOTE_CLEANUP, REMOTE_DISCARD = "artifact", "cleanup", "discard"
ARCHIVE_NAME, SECRETS_NAME = "lxc-150.tar", "lxc-150-secrets.tar.age"
SECRETS_KEYS = {"secrets_archive_path", "secrets_size_bytes", "secrets_sha256",
                "secrets_recipient_id", "secrets_members", "secrets_paths_verified"}


def parse_request(raw):
    obs.require(len(raw.encode()) <= 16384, "request_too_large")
    request = obs.parse_json(raw)
    obs.require(isinstance(request, dict) and set(request) in
                (REQUEST_KEYS, REQUEST_KEYS | {"qualified_previous"}), "request_fields")
    obs.require(type(request["contract_version"]) is int and request["contract_version"] == 1,
                "request_version")
    obs.require(request["operation"] == "prepare_backup" and request["project"] == "ominull"
                and request["source_id"] == SOURCE, "request_identity")
    obs.require(isinstance(request["backup_id"], str) and obs.IDENTIFIER.fullmatch(request["backup_id"]),
                "request_backup_id")
    qualification = request.get("qualified_previous")
    if qualification is not None:
        obs.require(isinstance(qualification, dict) and set(qualification) ==
                    {"backup_id", "sha256", "snapshot_id", "repository_id"}
                    and all(isinstance(qualification[key], str) and
                            obs.IDENTIFIER.fullmatch(qualification[key])
                            for key in ("backup_id", "snapshot_id", "repository_id"))
                    and isinstance(qualification["sha256"], str)
                    and obs.DIGEST.fullmatch(qualification["sha256"]), "request_qualification")
    return request


def ssh_argv(alias, command):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o",
            "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "--", alias, command]


def remote_argv(config, words):
    """The ssh call for one dispatcher verb; every word was validated here."""
    node = config.get("proxmox_node")
    obs.require(isinstance(node, str) and NODE_NAME.fullmatch(node), "backup_proxmox_node")
    words = [*words[:3], node, *words[3:]]
    obs.require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", word) for word in words), "backup_remote_words")
    if config.get("backup_ssh_alias"):
        return ssh_argv(config["backup_ssh_alias"], " ".join(words))
    source = DISPATCHER.read_text()
    return ssh_argv(config["ssh_alias"], "python3 -c " + shlex.quote(source) + " " + " ".join(words))


def remote(config, verb, attempt, backup_id):
    try:
        result = subprocess.run(remote_argv(config, [verb, attempt, backup_id]), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=DEADLINE_SECONDS if verb in (REMOTE_CREATE, REMOTE_ARTIFACT) else 300,
                                check=False)
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


def fetch(config, attempt, backup_id, which, expected, destination):
    """Copy one verified remote file (archive or secrets) into staging."""
    require_backup_mount()
    try:
        with destination.open("xb") as file:
            os.fchmod(file.fileno(), 0o600)
            result = subprocess.run(remote_argv(config, ["fetch", attempt, backup_id, which]),
                                    stdin=subprocess.DEVNULL, stdout=file, stderr=subprocess.PIPE,
                                    timeout=DEADLINE_SECONDS, check=False)
            file.flush()
            os.fsync(file.fileno())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise obs.ObservationError("backup_fetch_failed") from exc
    obs.require(result.returncode == 0, "backup_fetch_failed")
    obs.require(destination.stat().st_size == expected["size_bytes"], "backup_fetch_size")
    obs.require(obs.sha256_file(destination) == expected["sha256"], "backup_fetch_digest")


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with temporary.open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(value, file, sort_keys=True)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    temporary.replace(path)
    _sync_directory(path.parent)


def _generation(path, *, verify_hash=False):
    obs.require(path.is_dir() and not path.is_symlink(), "backup_existing_publication")
    private_directory(path)
    archive = obs.regular_file(path / ARCHIVE_NAME, private=True)
    value = obs.parse_json(obs.regular_file(path / "manifest.json", private=True).read_bytes())
    current = DESTINATION / "current"
    split = isinstance(value, dict) and "secrets_sha256" in value
    members = {ARCHIVE_NAME, "manifest.json"} | ({SECRETS_NAME} if split else set())
    obs.require(isinstance(value, dict) and value.get("status") == "completed" and value.get("project") == "ominull"
                and value.get("source_id") == SOURCE and value.get("target_id") == GUEST
                and value.get("archive_path") == str(current / "lxc-150.tar")
                and value.get("manifest_path") == str(current / "manifest.json")
                and type(value.get("size_bytes")) is int and value["size_bytes"] > 0
                and isinstance(value.get("sha256"), str) and obs.DIGEST.fullmatch(value["sha256"])
                and archive.stat().st_size == value["size_bytes"]
                and set(p.name for p in path.iterdir()) == members,
                "backup_existing_publication")
    if split:
        sealed = obs.regular_file(path / SECRETS_NAME, private=True)
        obs.require(SECRETS_KEYS <= set(value)
                    and value["secrets_archive_path"] == str(current / SECRETS_NAME)
                    and type(value["secrets_size_bytes"]) is int and value["secrets_size_bytes"] > 0
                    and isinstance(value["secrets_sha256"], str) and obs.DIGEST.fullmatch(value["secrets_sha256"])
                    and sealed.stat().st_size == value["secrets_size_bytes"], "backup_existing_publication")
    if verify_hash:
        obs.require(obs.sha256_file(archive) == value["sha256"], "backup_fetch_digest")
        if split:
            obs.require(obs.sha256_file(path / SECRETS_NAME) == value["secrets_sha256"], "backup_fetch_digest")
    return value


def recover_publication():
    """Recover ordinary rename boundaries under the existing source lease."""
    journal = DESTINATION / ".publication.json"
    if not journal.exists() and not journal.is_symlink():
        return None
    state = obs.parse_json(obs.regular_file(journal, private=True).read_bytes())
    obs.require(isinstance(state, dict) and set(state) == {"staging", "previous", "sha256", "qualified_previous"}
                and isinstance(state["staging"], str) and isinstance(state["previous"], str)
                and re.fullmatch(r"\.attempt-[0-9a-f]{32}", state["staging"])
                and re.fullmatch(r"\.previous-[0-9a-f]{32}", state["previous"]),
                "backup_publication_journal")
    staging, previous = DESTINATION / state["staging"], DESTINATION / state["previous"]
    current = DESTINATION / "current"
    if current.exists():
        value = _generation(current)
        if value["sha256"] == state["sha256"] and not staging.exists():
            # New generation was already durably installed; retain its predecessor.
            recovered = value
        else:
            obs.require(staging.exists() and not previous.exists(), "backup_publication_ambiguous")
            _generation(staging)
            recovered = None
    else:
        # Interrupted after moving current aside: restore it before any new work.
        obs.require(staging.exists(), "backup_publication_ambiguous")
        _generation(staging)
        if previous.exists():
            _generation(previous)
            previous.rename(current)
            recovered = None
        else:
            value = _generation(staging, verify_hash=True)
            obs.require(value["sha256"] == state["sha256"], "backup_publication_ambiguous")
            staging.rename(current)
            recovered = value
        _sync_directory(DESTINATION)
    if recovered is not None and state["qualified_previous"] is not None and previous.exists():
        _schedule_retirement(previous, state["qualified_previous"])
    journal.rename(DESTINATION / ("publication-recovered-" + uuid.uuid4().hex + ".json"))
    _sync_directory(DESTINATION)
    return recovered


def _schedule_retirement(previous, qualification):
    value = _generation(previous)
    obs.require(value["backup_id"] == qualification["backup_id"]
                and value["sha256"] == qualification["sha256"], "backup_retirement_qualification")
    _save_json(DESTINATION / ".retirement.json",
               {"previous": previous.name, "qualification": qualification, "size_bytes": value["size_bytes"]})


def retire_qualified_previous():
    """Resume removal only from a durable, positively qualified exact generation."""
    marker = DESTINATION / ".retirement.json"
    if not marker.exists() and not marker.is_symlink():
        return
    state = obs.parse_json(obs.regular_file(marker, private=True).read_bytes())
    obs.require(isinstance(state, dict) and set(state) == {"previous", "qualification", "size_bytes"}
                and isinstance(state["previous"], str)
                and type(state["size_bytes"]) is int and state["size_bytes"] > 0
                and re.fullmatch(r"\.previous-[0-9a-f]{32}", state["previous"]), "backup_retirement_marker")
    # Apply the public contract validation also to durable qualification evidence.
    obs.require(isinstance(state["qualification"], dict), "backup_retirement_marker")
    parse_request(json.dumps({"contract_version": 1, "operation": "prepare_backup", "project": "ominull",
                             "source_id": SOURCE, "backup_id": state["qualification"].get("backup_id"),
                             "qualified_previous": state["qualification"]}))
    previous = DESTINATION / state["previous"]
    if previous.exists() or previous.is_symlink():
        private_directory(previous)
        obs.require(set(p.name for p in previous.iterdir()) <= {ARCHIVE_NAME, SECRETS_NAME, "manifest.json"},
                    "backup_retirement_members")
        manifest, archive, sealed = previous / "manifest.json", previous / ARCHIVE_NAME, previous / SECRETS_NAME
        if manifest.exists() or manifest.is_symlink():
            value = obs.parse_json(obs.regular_file(manifest, private=True).read_bytes())
            obs.require(value["backup_id"] == state["qualification"]["backup_id"]
                        and value["sha256"] == state["qualification"]["sha256"]
                        and value["size_bytes"] == state["size_bytes"], "backup_retirement_qualification")
        else:
            obs.require(not archive.exists() and not archive.is_symlink()
                        and not sealed.exists() and not sealed.is_symlink(), "backup_retirement_manifest")
        if sealed.exists() or sealed.is_symlink():
            obs.regular_file(sealed, private=True).unlink()
            _sync_directory(previous)
        if archive.exists() or archive.is_symlink():
            obs.require(obs.regular_file(archive, private=True).stat().st_size == state["size_bytes"],
                        "backup_retirement_size")
            archive.unlink()
            _sync_directory(previous)
        if manifest.exists():
            manifest.unlink()
            _sync_directory(previous)
        previous.rmdir()
        _sync_directory(DESTINATION)
    marker.rename(DESTINATION / ("retirement-completed-" + uuid.uuid4().hex + ".json"))
    _sync_directory(DESTINATION)


def publish(staging, response, qualification=None):
    obs.require(staging.parent == DESTINATION and re.fullmatch(r"\.attempt-[0-9a-f]{32}", staging.name),
                "backup_publication_staging")
    private_directory(staging)
    current = DESTINATION / "current"
    if current.exists() or current.is_symlink():
        prior = _generation(current)
        if qualification is not None:
            obs.require(prior["backup_id"] == qualification["backup_id"]
                        and prior["sha256"] == qualification["sha256"], "backup_retirement_qualification")
    else:
        obs.require(qualification is None, "backup_retirement_qualification")
    obs.require(not (DESTINATION / ".publication.json").exists(), "backup_publication_recovery_required")
    _save_json(staging / "manifest.json", response)
    _generation(staging)
    previous = DESTINATION / (".previous-" + staging.name.removeprefix(".attempt-"))
    obs.require(not previous.exists() and not previous.is_symlink(), "backup_previous_exists")
    _save_json(DESTINATION / ".publication.json",
               {"staging": staging.name, "previous": previous.name, "sha256": response["sha256"],
                "qualified_previous": qualification})
    if current.exists():
        current.rename(previous)
        _sync_directory(DESTINATION)
    staging.rename(current)
    _sync_directory(DESTINATION)
    if qualification is not None:
        _schedule_retirement(previous, qualification)
    (DESTINATION / ".publication.json").unlink()
    _sync_directory(DESTINATION)
    retire_qualified_previous()
    # The previous generation may back a pending capture. Retirement requires
    # parent qualification; it is never recursively discarded by publication.


def _reusable_attempt(config_digest):
    current = DESTINATION / "current"
    current_time = _generation(current)["completed_at"] if current.exists() else ""
    candidates = []
    for staging in DESTINATION.glob(".attempt-*"):
        if not re.fullmatch(r"\.attempt-[0-9a-f]{32}", staging.name):
            continue
        failure_path = DESTINATION / ("failure-" + staging.name.removeprefix(".attempt-") + ".json")
        if not failure_path.exists() or not (staging / "manifest.json").exists():
            continue
        failure = obs.parse_json(obs.regular_file(failure_path, private=True).read_bytes())
        if failure.get("error") not in {"backup_atomic_publication", "backup_preparation_failed"} or failure.get("publication_completed") is not False:
            continue
        value = _generation(staging)
        if (value.get("protected_config_sha256") == config_digest
                and value.get("reused_from_backup_id", value["backup_id"]) == failure.get("backup_id")
                and value["completed_at"] > current_time):
            candidates.append((value["completed_at"], staging, value))
    if not candidates:
        return None
    _, staging, value = max(candidates, key=lambda item: (item[0], item[1].name))
    _generation(staging, verify_hash=True)
    return staging, value


def discard_unverified_attempts(config):
    """Remove failed attempts that never verified bytes; current/ stays untouched.

    An attempt without manifest.json holds at most a partial, unverified
    download, so it is never a good copy. Keeping it blocked every later run.
    """
    for staging in sorted(DESTINATION.glob(".attempt-*")):
        if not re.fullmatch(r"\.attempt-[0-9a-f]{32}", staging.name) or staging.is_symlink() or not staging.is_dir():
            continue
        if (staging / "manifest.json").exists() or (staging / "manifest.json").is_symlink():
            continue  # Verified bytes are reused or left for review.
        children = list(staging.iterdir())
        obs.require(all(child.name in {ARCHIVE_NAME, SECRETS_NAME} and child.is_file() and not child.is_symlink()
                        for child in children),
                    "backup_attempt_members")
        obs.require(remote(config, REMOTE_DISCARD, staging.name.removeprefix(".attempt-"), "discard") == {"discarded": True},
                    "backup_remote_discard")
        for child in children:
            child.unlink()
        staging.rmdir()
        _sync_directory(DESTINATION)


def trim_evidence_markers():
    """Bound small marker files; each kind keeps its newest entries."""
    for pattern in ("failure-*.json", "retirement-completed-*.json", "publication-recovered-*.json", "reuse-evidence-*.json"):
        markers = sorted((path for path in DESTINATION.glob(pattern) if path.is_file() and not path.is_symlink()),
                         key=lambda path: path.stat().st_mtime, reverse=True)
        for path in markers[EVIDENCE_KEEP:]:
            attempt = re.match(r"(?:failure|reuse-evidence)-([0-9a-f]{32})", path.name)
            if attempt and (DESTINATION / (".attempt-" + attempt.group(1))).exists():
                continue  # Still describes a retained attempt.
            path.unlink()


def prepare(request, root):
    config, digest = obs.load_config(root, require_deployment_inputs=False)
    obs.require(config["lxc_id"] == GUEST, "backup_protected_target")
    require_backup_mount()
    private_directory(DESTINATION)
    recovered = recover_publication()
    retire_qualified_previous()
    if recovered is not None:
        _generation(DESTINATION / "current", verify_hash=True)
        response = {**recovered, "backup_id": request["backup_id"],
                    "reused_from_backup_id": recovered.get("reused_from_backup_id", recovered["backup_id"]), "capture_fresh": False,
                    "prepared_at": datetime.now(timezone.utc).isoformat()}
        _save_json(DESTINATION / "current/manifest.json", response)
        return response
    # One retained predecessor is enough to recover an interrupted publication.
    # Never accumulate generations while parent qualification remains pending.
    obs.require(not any(DESTINATION.glob(".previous-*")), "backup_previous_qualification_required")
    qualification = request.get("qualified_previous")
    if qualification is not None:
        current = _generation(DESTINATION / "current")
        obs.require(current["backup_id"] == qualification["backup_id"]
                    and current["sha256"] == qualification["sha256"], "backup_retirement_qualification")
    discard_unverified_attempts(config)
    trim_evidence_markers()
    reusable = _reusable_attempt(digest)
    if not reusable:
        obs.require(not any(staging.is_symlink() or any(staging.iterdir())
                            for staging in DESTINATION.glob(".attempt-*") if staging.is_dir() or staging.is_symlink()),
                    "backup_failed_attempt_requires_review")
        # The owner powers the guest on and off at will. A stopped guest has
        # nothing new to capture, so report a skip without failure evidence.
        guest = remote(config, REMOTE_GUEST, uuid.uuid4().hex, request["backup_id"])
        if guest.get("guest_status") == "stopped":
            return {"schema_version": 1, "project": "ominull", "source_id": SOURCE,
                    "backup_id": request["backup_id"], "target_id": GUEST,
                    "status": "skipped", "reason": "guest_stopped"}
        obs.require(guest.get("guest_status") == "running", "backup_guest_state")
    attempt = reusable[0].name.removeprefix(".attempt-") if reusable else uuid.uuid4().hex
    staging = reusable[0] if reusable else DESTINATION / (".attempt-" + attempt)
    if not reusable:
        staging.mkdir(mode=0o700)
    base = {"schema_version": 1, "project": "ominull", "source_id": SOURCE,
            "backup_id": request["backup_id"], "target_id": GUEST,
            "protected_config_sha256": digest, "backup_mode": "snapshot", "compression": "none"}
    published = False
    try:
        if reusable:
            original = reusable[1]
            response = {**original, "backup_id": request["backup_id"],
                        "reused_from_backup_id": original.get("reused_from_backup_id", original["backup_id"]), "reused_attempt_id": attempt,
                        "capture_fresh": False, "prepared_at": datetime.now(timezone.utc).isoformat()}
            _save_json(DESTINATION / ("reuse-evidence-" + attempt + ".json"), original)
            publish(staging, response, request.get("qualified_previous"))
            # Recovery only publishes already verified bytes. Remote retirement
            # remains an explicitly qualified parent action, not a retry side effect.
            return response
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
        remote_dir = r"/var/lib/vz/dump/st-ominull-" + attempt
        obs.require(type(artifact.get("size_bytes")) is int and artifact["size_bytes"] > 0
                    and isinstance(artifact.get("sha256"), str) and obs.DIGEST.fullmatch(artifact["sha256"])
                    and isinstance(artifact.get("path"), str)
                    and re.fullmatch(remote_dir + r"/vzdump-lxc-150-[0-9_\-]+\.tar", artifact["path"]),
                    "backup_remote_artifact")
        secrets = artifact.get("secrets")
        # Under the forced-command key the secret members must be sealed; the
        # transitional root alias keeps the single tar until root installs the
        # recipient, so backups never stop in between.
        obs.require(secrets is not None or not config.get("backup_ssh_alias"), "backup_secrets_not_sealed")
        if secrets is not None:
            obs.require(isinstance(secrets, dict) and secrets.get("path") == remote_dir + "/secrets.tar.age"
                        and type(secrets.get("size_bytes")) is int and secrets["size_bytes"] > 0
                        and isinstance(secrets.get("sha256"), str) and obs.DIGEST.fullmatch(secrets["sha256"])
                        and isinstance(secrets.get("recipient_id"), str)
                        and re.fullmatch(r"age:[0-9a-f]{16}", secrets["recipient_id"])
                        and type(secrets.get("members")) is int and secrets["members"] > 0
                        and isinstance(secrets.get("paths_verified"), list)
                        and all(isinstance(path, str) for path in secrets["paths_verified"]), "backup_remote_artifact")
        sealed_bytes = secrets["size_bytes"] if secrets else 0
        obs.require(shutil.disk_usage(DESTINATION).free >= artifact["size_bytes"] + sealed_bytes + RESERVE_BYTES,
                    "backup_local_capacity")
        fetch(config, attempt, request["backup_id"], "archive", artifact, staging / ARCHIVE_NAME)
        if secrets:
            fetch(config, attempt, request["backup_id"], "secrets", secrets, staging / SECRETS_NAME)
        response = {**base, "status": "completed", "archive_path": str(DESTINATION / "current" / ARCHIVE_NAME),
                    "manifest_path": str(DESTINATION / "current/manifest.json"),
                    "size_bytes": artifact["size_bytes"], "sha256": artifact["sha256"],
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "required_paths_verified": artifact["required_paths_verified"],
                    "wal_paths_verified": artifact["wal_paths_verified"]}
        if secrets:
            response.update({"secrets_archive_path": str(DESTINATION / "current" / SECRETS_NAME),
                             "secrets_size_bytes": secrets["size_bytes"], "secrets_sha256": secrets["sha256"],
                             "secrets_recipient_id": secrets["recipient_id"], "secrets_members": secrets["members"],
                             "secrets_paths_verified": secrets["paths_verified"]})
        publish(staging, response, request.get("qualified_previous"))
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
        if failure_path.exists() or failure_path.is_symlink():
            failure_path = DESTINATION / ("failure-" + attempt + "-retry-" + uuid.uuid4().hex + ".json")
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
    except (obs.ObservationError, OSError, ValueError, KeyError, TypeError) as exc:
        error = str(exc) if isinstance(exc, obs.ObservationError) else "backup_input_failed"
        print(json.dumps({"schema_version": 1, "status": "failed", "error": error}, separators=(",", ":")))
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] in {"completed", "skipped"} else 1
