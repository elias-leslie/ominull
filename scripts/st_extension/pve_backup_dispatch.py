#!/usr/bin/env python3
"""Fixed Proxmox-side verbs for the OmniNull production backup (LXC 150).

Installed as root on the Proxmox host at /usr/local/sbin/ominull-backup-dispatch
and reached only through a forced-command key, so the workstation can run these
verbs and nothing else as root:

    restrict,command="/usr/local/sbin/ominull-backup-dispatch" ssh-ed25519 ...

The command line arrives in SSH_ORIGINAL_COMMAND as
"VERB ATTEMPT BACKUP_ID NODE [archive|secrets]". Until that key is installed the
backup hook sends this same file over its ordinary root alias (python3 -c), with
the words as arguments.

The artifact verb moves every secret-bearing member out of the vzdump tar into
an archive encrypted with age to an offline recipient (RECIPIENT_FILE, root
owned, public key only), and refuses to publish if any member under those
prefixes is left in the bulk tar. Plaintext secrets are never written to disk:
they stream from the vzdump tar into age. Under the forced command a missing
recipient refuses the backup; through the transitional alias the old single
plaintext tar is still produced, so backups keep running until root installs
the recipient.

fetch streams only what artifact verified and recorded in artifact.json: the
bulk tar after its secrets were moved out, or the sealed secrets. The unsplit
tar is never fetched under the forced command, nor once a recipient exists, so
the forced key cannot read the plaintext vzdump by skipping artifact.
"""
import hashlib
import json
import os
import pathlib
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = pathlib.Path("/var/lib/vz/dump")
RECIPIENT_FILE = pathlib.Path("/etc/ominull-backup/recipient")
RECIPIENT_OWNER = 0  # Only root may name who can read the secrets.
GUEST = 150
ARCHIVE = re.compile(r"vzdump-lxc-150-[0-9_\-]+\.tar")
SECRETS_NAME = "secrets.tar.age"
PUBLISHED = "artifact.json"
RECIPIENT = re.compile(r"age1[0-9a-z]{58}")

# Selected by prefix, so a key added later under these trees is covered too.
SECRET_PREFIXES = ("var/lib/ominull-response-authority/", "etc/ominull/", "var/lib/ominull/evidence/")
SECRET_FILES = {"var/lib/ominull/evidence.key"}
KEY_FILE_DIR = "opt/ominull/bin/certs/"

BULK_REQUIRED = {"var/lib/ominull/ominull.db", "opt/ominull/bin/certs/ca.crt", "opt/ominull/bin/certs/server.crt"}
SECRET_REQUIRED = {"var/lib/ominull/evidence.key", "var/lib/ominull/evidence/receipt.key",
                   "var/lib/ominull-response-authority/authority.db",
                   "var/lib/ominull-response-authority/secret.key",
                   "opt/ominull/bin/certs/ca.key", "opt/ominull/bin/certs/server.key",
                   "etc/ominull/hub.env", "etc/ominull/response-authority.env", "etc/ominull/admin.key"}
OPTIONAL_WAL = {"var/lib/ominull/ominull.db-wal", "var/lib/ominull-response-authority/authority.db-wal"}


class Refused(Exception):
    """A fixed precondition failed; nothing is published."""


def need(condition, why):
    if not condition:
        raise Refused(why)


def member_path(name):
    return name.removeprefix("./").rstrip("/")


def is_secret(name):
    path = member_path(name)
    if path in SECRET_FILES:
        return True
    if any(path.startswith(prefix) for prefix in SECRET_PREFIXES):
        return True
    return path.startswith(KEY_FILE_DIR) and path.endswith(".key")


def command(*args, timeout=60):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout


def api(*args, timeout=60, worker_result=False):
    output = command("pvesh", *args, "--output-format", "json", timeout=timeout)
    # CLI workers run synchronously and tee logs before the final JSON result.
    return json.loads(output.splitlines()[-1] if worker_result else output)


class Attempt:
    def __init__(self, attempt, backup_id, node):
        need(re.fullmatch(r"[0-9a-f]{32}", attempt), "attempt")
        need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", backup_id), "backup_id")
        need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", node), "node")
        self.attempt, self.backup_id, self.node = attempt, backup_id, node
        self.directory = ROOT / ("st-ominull-" + attempt)
        need(ROOT.resolve() == ROOT and ROOT.is_dir(), "dump root")

    def on_node(self):
        need(command("hostname", "-s").strip() == self.node, "node mismatch")

    def owned(self):
        directory = self.directory
        need(directory.resolve() == directory and directory.is_dir(), "attempt directory")
        need(directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, "attempt owner")
        marker = directory / "attempt.json"
        need(marker.is_file() and not marker.is_symlink(), "attempt marker")
        value = json.loads(marker.read_text())
        need(value["attempt"] == self.attempt and value["backup_id"] == self.backup_id and value["guest"] == GUEST,
             "attempt marker")
        return value

    def task_ok(self):
        marker = self.owned()
        state = api("get", "/nodes/" + self.node + "/tasks/" + marker["task"] + "/status")
        need(state.get("status") == "stopped" and state.get("exitstatus") == "OK", "task not finished")
        return marker

    def archive(self):
        archives = [p for p in self.directory.iterdir() if ARCHIVE.fullmatch(p.name)]
        need(len(archives) == 1, "archive count")
        return archives[0]


def create(a):
    a.on_node()
    config = api("get", "/nodes/" + a.node + "/lxc/150/config")
    need(not any(re.fullmatch(r"mp\d+", k) for k in config), "Additional mount requires review")
    need(config["rootfs"].split(",", 1)[0] == "local-lvm:vm-150-disk-0", "rootfs")
    need(not config.get("lock") and not config.get("snapstate"), "guest locked")
    storage = api("get", "/storage/local")
    need(storage["type"] == "dir" and storage["path"] == "/var/lib/vz", "storage")
    need("backup" in storage["content"].split(","), "storage content")
    used = int(command("pct", "exec", "150", "--", "python3", "-c", "import shutil;print(shutil.disk_usage('/').used)").strip())
    need(shutil.disk_usage(ROOT).free >= used + 10 * 1024**3, "Insufficient remote staging space")
    a.directory.mkdir(mode=0o700)
    marker = {"attempt": a.attempt, "backup_id": a.backup_id, "guest": GUEST}
    with (a.directory / "attempt.json").open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(marker, file)
    task = api("create", "/nodes/" + a.node + "/vzdump", "--vmid", "150", "--mode", "snapshot",
               "--dumpdir", str(a.directory), "--tmpdir", "/var/tmp", "--compress", "0", "--remove", "0",
               timeout=3600, worker_result=True)
    need(isinstance(task, str) and task.startswith("UPID:" + a.node + ":"), "task id")
    marker["task"] = task
    (a.directory / "attempt.json").write_text(json.dumps(marker))
    return {"task": task, "used_bytes": used}


def guest(a):
    a.on_node()
    state = api("get", "/nodes/" + a.node + "/lxc/150/status/current")
    return {"guest_status": state.get("status")}


def status(a):
    marker = a.owned()
    state = api("get", "/nodes/" + a.node + "/tasks/" + marker["task"] + "/status")
    return {k: state.get(k) for k in ["status", "exitstatus"]}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def recipient():
    """The offline recipient root installed, or None when there is none."""
    if not RECIPIENT_FILE.exists() and not RECIPIENT_FILE.is_symlink():
        return None
    info = RECIPIENT_FILE.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == RECIPIENT_OWNER and not info.st_mode & 0o022, "recipient file ownership")
    value = RECIPIENT_FILE.read_text().strip()
    need(RECIPIENT.fullmatch(value), "recipient")
    return value


def scan(archive):
    """Member paths of the tar, checked for the required shape."""
    names, found, wal = [], set(), set()
    with tarfile.open(archive, "r:") as tar:
        for member in tar:
            path = member_path(member.name)
            # A name like var/lib/ominull/../ominull-response-authority/x would
            # slip past the prefix test, so only canonical names are accepted.
            need(path == "" or (posixpath.normpath(path) == path and not path.startswith(("/", "../"))
                                and path != ".."), "member name is not canonical: " + member.name)
            names.append(member)
            if path in BULK_REQUIRED or path in SECRET_REQUIRED:
                need(member.isfile() and member.size > 0, "required path is not a file: " + path)
                found.add(path)
            elif path in OPTIONAL_WAL:
                need(member.isfile(), "WAL must be a regular file when present")
                wal.add(path)
    return names, found, wal


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]


def hashed(path):
    """The file's digest and identity, refused if it changed while hashed."""
    before = path.lstat()
    sha = digest(path)
    need(identity(before) == identity(path.lstat()), "archive changed while hashed")
    return sha, before


def publish(a, archive, sealed=None):
    """Record what artifact verified; fetch streams nothing else."""
    value = {"split": sealed is not None, "archive": identity(archive.lstat()),
             "secrets": identity(sealed.lstat()) if sealed is not None else None}
    with (a.directory / PUBLISHED).open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(value, file)


def artifact(a, forced):
    a.task_ok()
    need(not (a.directory / PUBLISHED).exists() and not (a.directory / PUBLISHED).is_symlink(), "artifact already published")
    archive = a.archive()
    info = archive.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size > 0, "archive file")
    to = recipient()
    if to is None:
        need(not forced, "no backup recipient installed; refusing to publish secrets in plaintext")
        sha, hashed_info = hashed(archive)
        need(identity(info) == identity(hashed_info), "archive changed while hashed")
        members, found, wal = scan(archive)
        need(found == BULK_REQUIRED | SECRET_REQUIRED, "Required production data missing from archive")
        need(identity(archive.lstat()) == identity(info), "archive changed while scanned")
        publish(a, archive)
        return {"path": str(archive), "size_bytes": info.st_size, "sha256": sha,
                "required_paths_verified": sorted(found), "wal_paths_verified": sorted(wal)}
    return split(a, archive, to)


def split(a, archive, to):
    members, found, wal = scan(archive)
    need(found == BULK_REQUIRED | SECRET_REQUIRED, "Required production data missing from archive")
    secret = [m for m in members if is_secret(m.name)]
    by_path = {member_path(m.name): m for m in members}
    for member in members:
        # A hard link carries its data under one name only; one crossing the
        # boundary would leave secret bytes in the bulk tar or lose them.
        if member.islnk():
            need(is_secret(member.name) == is_secret(member.linkname), "hard link crosses the secret boundary: " + member.name)
            need(member_path(member.linkname) in by_path, "dangling hard link")
    sealed = a.directory / SECRETS_NAME
    need(not sealed.exists() and not sealed.is_symlink(), "secrets archive already exists")
    # Plaintext secrets stream from the vzdump tar into age, never to disk.
    descriptor = os.open(sealed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        age = subprocess.Popen(["age", "--encrypt", "-r", to], stdin=subprocess.PIPE,
                               stdout=descriptor, stderr=subprocess.DEVNULL)
    except BaseException:
        os.close(descriptor)
        sealed.unlink()
        raise
    os.close(descriptor)
    stream = age.stdin
    assert stream is not None  # stdin=PIPE
    try:
        with tarfile.open(archive, "r:") as source, tarfile.open(fileobj=stream, mode="w|", format=tarfile.PAX_FORMAT) as out:
            wanted = {m.name for m in secret}
            for member in source:
                if member.name not in wanted:
                    continue
                copy = tarfile.TarInfo(member.name)
                for field in ("mode", "uid", "gid", "uname", "gname", "mtime", "linkname", "size", "devmajor", "devminor"):
                    setattr(copy, field, getattr(member, field))
                copy.type = tarfile.REGTYPE if member.issparse() else member.type
                # Keep xattrs and ACLs; tarfile rewrites name, size and link from the fields.
                copy.pax_headers = {k: v for k, v in member.pax_headers.items()
                                    if not k.startswith("GNU.sparse") and k not in {"path", "linkpath", "size"}}
                out.addfile(copy, source.extractfile(member) if member.isfile() else None)
        stream.close()
        need(age.wait(timeout=600) == 0, "age failed")
    except BaseException:
        age.kill()
        age.wait()
        sealed.unlink(missing_ok=True)
        raise
    names = a.directory / "secret-members.list"
    with names.open("xb") as file:
        file.write(b"".join(m.name.encode() + b"\0" for m in secret))
    try:
        # Below the caller's one-hour budget for this verb.
        subprocess.run(["tar", "--delete", "--file", str(archive), "--no-wildcards", "--no-recursion",
                        "--null", "--files-from", str(names)], check=True, capture_output=True, timeout=2400)
    finally:
        names.unlink()
    # The bulk tar must now hold no member under a secret prefix.
    before = archive.lstat()
    remaining, bulk_found, _ = scan(archive)
    need(not any(is_secret(m.name) for m in remaining), "secret member left in the bulk tar")
    need(bulk_found == BULK_REQUIRED, "Required production data missing from bulk archive")
    sha, after = hashed(archive)
    need(identity(before) == identity(after), "archive changed while scanned")
    publish(a, archive, sealed)
    sealed_paths = sorted((found | wal) - BULK_REQUIRED - {p for p in wal if not is_secret(p)})
    return {"path": str(archive), "size_bytes": after.st_size, "sha256": sha,
            "required_paths_verified": sorted(bulk_found),
            "wal_paths_verified": sorted(p for p in wal if not is_secret(p)),
            "secrets": {"path": str(sealed), "size_bytes": sealed.stat().st_size, "sha256": digest(sealed),
                        "recipient_id": "age:" + hashlib.sha256(to.encode()).hexdigest()[:16],
                        "members": len(secret), "paths_verified": sealed_paths}}


def fetch(a, which, out, forced):
    a.task_ok()
    record = a.directory / PUBLISHED
    need(record.is_file() and not record.is_symlink() and record.stat().st_uid == os.getuid(), "artifact not published")
    published = json.loads(record.read_text())
    if which == "archive":
        path, expected = a.archive(), published["archive"]
        # An unsplit tar still holds the keys: only the transitional root
        # alias may fetch it, and only while no recipient is installed.
        need(published["split"] or (not forced and recipient() is None), "secrets not sealed")
    else:
        need(which == "secrets", "fetch target")
        need(published["split"], "secrets not sealed")
        path, expected = a.directory / SECRETS_NAME, published["secrets"]
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as file:
        info = os.fstat(file.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), "fetch file")
        need(identity(info) == expected, "fetch file changed since artifact")
        shutil.copyfileobj(file, out, 1024 * 1024)


ALLOWED_CHILD = re.compile(r"vzdump-lxc-150-[0-9_\-]+\.(tar(?:\.dat|\.notes)?|log)|attempt\.json|secrets\.tar\.age|secret-members\.list|artifact\.json")


def cleanup(a):
    a.task_ok()
    # Refuse unexpected contents rather than recursively deleting a foreign tree.
    children = list(a.directory.iterdir())
    for child in children:
        need(child.is_file() and not child.is_symlink() and child.stat().st_uid == os.getuid(), "foreign member")
        need(ALLOWED_CHILD.fullmatch(child.name) and not child.name.endswith(".dat"), "foreign member")
    for child in children:
        child.unlink()
    a.directory.rmdir()
    return {"cleaned": True}


def discard(a):
    """A failed or killed attempt never produced a published generation."""
    a.on_node()
    directory = a.directory
    if directory.exists() or directory.is_symlink():
        need(directory.resolve() == directory and directory.is_dir(), "attempt directory")
        need(directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, "attempt owner")
        marker_path = directory / "attempt.json"
        marker = json.loads(marker_path.read_text()) if marker_path.is_file() and not marker_path.is_symlink() else {}
        need(marker.get("attempt", a.attempt) == a.attempt and marker.get("guest", GUEST) == GUEST, "attempt marker")
        if marker.get("task"):
            state = api("get", "/nodes/" + a.node + "/tasks/" + marker["task"] + "/status")
            need(state.get("status") == "stopped", "Attempt task is still running")
        else:
            need(not api("get", "/nodes/" + a.node + "/tasks", "--vmid", "150", "--source", "active"),
                 "A guest backup task is still active")
        children = list(directory.iterdir())
        for child in children:
            need(child.is_file() and not child.is_symlink() and child.stat().st_uid == os.getuid(), "foreign member")
            need(ALLOWED_CHILD.fullmatch(child.name), "foreign member")
        for child in children:
            child.unlink()
        directory.rmdir()
    return {"discarded": True}


VERBS = {"create": create, "guest": guest, "status": status, "cleanup": cleanup, "discard": discard}


def run(words, forced=False, out=None):
    need(len(words) in (4, 5), "usage: VERB ATTEMPT BACKUP_ID NODE [archive|secrets]")
    verb, rest = words[0], words[1:4]
    a = Attempt(*rest)
    if verb == "fetch":
        need(len(words) == 5, "fetch target")
        fetch(a, words[4], out or sys.stdout.buffer, forced)
        return None
    need(len(words) == 4, "usage")
    if verb == "artifact":
        return artifact(a, forced)
    need(verb in VERBS, "unknown verb")
    return VERBS[verb](a)


def main():
    original = os.environ.get("SSH_ORIGINAL_COMMAND")
    forced = original is not None
    words = original.split() if original is not None else sys.argv[1:]
    try:
        result = run(words, forced)
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print("refused: " + (str(exc) if isinstance(exc, Refused) else type(exc).__name__), file=sys.stderr)
        return 1
    if result is not None:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
