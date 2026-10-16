"""Fixed backup wire and isolated preparation tests; no remote production I/O."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import backup as bk
import observer as obs
import pve_backup_dispatch as pd

REQUEST = {"contract_version": 1, "operation": "prepare_backup", "project": "ominull",
           "source_id": bk.SOURCE, "backup_id": "bkp-fixture"}


class ProtocolTests(unittest.TestCase):
    def test_optional_catalogue_qualification_is_strict_and_compatible(self):
        qualification = {"backup_id": "bkp-old", "sha256": "a" * 64,
                         "snapshot_id": "restic-point", "repository_id": "repo-fixture"}
        for value in [None, qualification]:
            request = {**REQUEST, "qualified_previous": value}
            self.assertEqual(bk.parse_request(json.dumps(request)), request)
        for value in [{}, {**qualification, "sha256": "bad"},
                      {**qualification, "snapshot_id": "../foreign"}]:
            with self.subTest(value=value), self.assertRaises(obs.ObservationError):
                bk.parse_request(json.dumps({**REQUEST, "qualified_previous": value}))

    def test_fixed_wire_refuses_target_command_and_destination_overrides(self):
        self.assertEqual(bk.parse_request(json.dumps(REQUEST)), REQUEST)
        for extra in [{"host": "foreign"}, {"destination": "/tmp/foreign"}, {"command": "stop"},
                      {"contract_version": True}, {"project": "other"},
                      {"source_id": "other"}, {"backup_id": "../escape"}, {"operation": "reset"}]:
            with self.subTest(extra=extra), self.assertRaises(obs.ObservationError):
                bk.parse_request(json.dumps({**REQUEST, **extra}))
        with self.assertRaises(obs.ObservationError):
            bk.parse_request('{"contract_version":1,"contract_version":1}')

    def test_dispatcher_verbs_are_fixed_and_backup_never_stops_or_prunes(self):
        source = bk.DISPATCHER.read_text()
        compile(source, "pve-backup-dispatch", "exec")
        self.assertIn('"--mode", "snapshot"', source)
        self.assertIn('"--compress", "0", "--remove", "0"', source)
        self.assertIn('"--tmpdir", "/var/tmp"', source)
        self.assertNotIn('"--stop"', source)
        self.assertNotIn("rmtree", source)
        self.assertIn("timeout=3600, worker_result=True", source)
        result = subprocess.CompletedProcess([], 0, stdout='INFO: backup completed\n"UPID:pve-fixture:fixture"\n')
        with patch.object(subprocess, "run", return_value=result) as process:
            self.assertEqual(pd.api("create", "/nodes/pve-fixture/vzdump", timeout=3600, worker_result=True), "UPID:pve-fixture:fixture")
            self.assertEqual(process.call_args.kwargs["timeout"], 3600)
        for words in [["shell", "a" * 32, "bkp", "pve-fixture"], ["create", "a" * 31, "bkp", "pve-fixture"],
                      ["create", "a" * 32, "../x", "pve-fixture"], ["create", "a" * 32, "bkp", "pve fixture"],
                      ["fetch", "a" * 32, "bkp", "pve-fixture", "/etc/shadow"], ["guest"]]:
            with self.subTest(words=words), self.assertRaises(pd.Refused):
                pd.run(words)

    def test_forced_key_sends_only_the_verb_and_the_alias_sends_the_dispatcher(self):
        config = {"ssh_alias": "root-alias", "proxmox_node": "pve-fixture"}
        argv = bk.remote_argv(config, ["status", "a" * 32, "bkp-fixture"])
        self.assertEqual(argv[-2], "root-alias")
        self.assertTrue(argv[-1].startswith("python3 -c "))
        self.assertTrue(argv[-1].endswith(" status " + "a" * 32 + " bkp-fixture pve-fixture"))
        forced = bk.remote_argv({**config, "backup_ssh_alias": "ominull-backup"}, ["fetch", "a" * 32, "bkp-fixture", "secrets"])
        self.assertEqual(forced[-2:], ["ominull-backup", "fetch " + "a" * 32 + " bkp-fixture pve-fixture secrets"])
        for words in [["status", "a" * 32, "bkp fixture"], ["status", "a" * 32, "bkp;id"], ["status", "a" * 32, ""]]:
            with self.subTest(words=words), self.assertRaises(obs.ObservationError):
                bk.remote_argv(config, words)
        self.assertIn("SSH_ORIGINAL_COMMAND", bk.DISPATCHER.read_text())

    def test_remote_failure_withholds_stderr_and_host(self):
        failed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"private credential material")
        with patch.object(subprocess, "run", return_value=failed), self.assertRaises(obs.ObservationError) as caught:
            bk.remote({"ssh_alias": "private-alias", "proxmox_node": "pve-fixture"}, "fixed", "a" * 32, "bkp-fixture")
        self.assertEqual(str(caught.exception), "backup_remote_failed")

    def test_only_exact_mounted_t7_ntfs_is_accepted(self):
        mount = {"target": str(bk.BACKUP_MOUNT), "uuid": bk.BACKUP_UUID, "fstype": "ntfs3"}
        for change in [None, {"target": "/"}, {"uuid": "OTHER"}, {"uuid": None}, {"fstype": "ext4"}]:
            with self.subTest(change=change):
                row = mount if change is None else {**mount, **change}
                result = subprocess.CompletedProcess([], 0, stdout=json.dumps({"filesystems": [row]}).encode())
                with patch.object(subprocess, "run", return_value=result):
                    if change is None:
                        bk.require_backup_mount()
                    else:
                        with self.assertRaises(obs.ObservationError):
                            bk.require_backup_mount()
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, stdout=b"")), self.assertRaises(obs.ObservationError):
            bk.require_backup_mount()


REQUIRED = sorted(pd.BULK_REQUIRED | pd.SECRET_REQUIRED)


@contextlib.contextmanager
def dump_root():
    """A private stand-in for /var/lib/vz/dump with one owned attempt."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        with patch.object(pd, "ROOT", root), patch.object(pd, "RECIPIENT_FILE", root / "no-recipient"):
            yield root


def owned_attempt(root, attempt="a" * 32, task="UPID:pve-fixture:fixture"):
    directory = root / ("st-ominull-" + attempt)
    directory.mkdir(mode=0o700)
    (directory / "attempt.json").write_text(json.dumps({"attempt": attempt, "backup_id": "bkp-fixture",
                                                        "guest": 150, "task": task}))
    return directory


def write_dump(directory, extra=()):
    """A vzdump-shaped tar: directories, every required file, then extras."""
    archive = directory / "vzdump-lxc-150-2026_10_06-15_00_00.tar"
    with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as tar:
        for name in ["./", "./etc/", "./etc/ominull/", "./var/", "./var/lib/", "./var/lib/ominull/",
                     "./var/lib/ominull/evidence/", "./var/lib/ominull-response-authority/", "./opt/",
                     "./opt/ominull/", "./opt/ominull/bin/", "./opt/ominull/bin/certs/"]:
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(member)
        for name in REQUIRED:
            data = ("content of " + name).encode()
            member = tarfile.TarInfo("./" + name)
            member.size, member.mode = len(data), 0o600
            tar.addfile(member, io.BytesIO(data))
        for member, data in extra:
            tar.addfile(member, None if data is None else io.BytesIO(data))
    return archive


def finished(*args, **kwargs):
    if args[:2] == ("get", "/nodes/pve-fixture/tasks/UPID:pve-fixture:fixture/status"):
        return {"status": "stopped", "exitstatus": "OK"}
    raise AssertionError(args)


class RemoteCleanupTests(unittest.TestCase):
    def test_exact_owned_attempt_cleanup_and_foreign_contents_refusal(self):
        for foreign in [False, True]:
            with self.subTest(foreign=foreign), dump_root() as root:
                directory = owned_attempt(root)
                archive = directory / "vzdump-lxc-150-2026_10_06-15_00_00.tar"
                archive.write_bytes(b"verified fixture")
                (directory / "secrets.tar.age").write_bytes(b"sealed")
                if foreign:
                    (directory / "foreign.txt").write_text("preserve foreign data")
                with patch.object(pd, "api", side_effect=finished):
                    if foreign:
                        with self.assertRaises(pd.Refused):
                            pd.run(["cleanup", "a" * 32, "bkp-fixture", "pve-fixture"])
                    else:
                        self.assertEqual(pd.run(["cleanup", "a" * 32, "bkp-fixture", "pve-fixture"]), {"cleaned": True})
                self.assertEqual(directory.exists(), foreign)
                if foreign:
                    self.assertTrue(archive.exists())

    def test_failed_attempt_discard_waits_for_its_task_and_refuses_foreign_contents(self):
        for case in ["stopped", "running", "foreign", "absent"]:
            with self.subTest(case=case), dump_root() as root:
                attempt = "b" * 32
                directory = root / ("st-ominull-" + attempt)
                if case != "absent":
                    owned_attempt(root, attempt)
                    (directory / "vzdump-lxc-150-2026_10_06-15_00_00.tar.dat").write_bytes(b"partial")
                    if case == "foreign":
                        (directory / "foreign.txt").write_text("preserve")
                status = {"status": "running" if case == "running" else "stopped", "exitstatus": "ERROR"}
                with patch.object(pd, "command", return_value="pve-fixture\n"), patch.object(pd, "api", return_value=status):
                    if case in {"running", "foreign"}:
                        with self.assertRaises(pd.Refused):
                            pd.run(["discard", attempt, "discard", "pve-fixture"])
                    else:
                        self.assertEqual(pd.run(["discard", attempt, "discard", "pve-fixture"]), {"discarded": True})
                self.assertEqual(directory.exists(), case in {"running", "foreign"})


class RemoteArtifactTests(unittest.TestCase):
    def artifact(self, forced=False):
        with patch.object(pd, "api", side_effect=finished):
            return pd.run(["artifact", "a" * 32, "bkp-fixture", "pve-fixture"], forced=forced)

    def test_checkpointed_database_without_wal_and_present_wal_shape(self):
        for wal in [None, "regular", "symlink"]:
            with self.subTest(wal=wal), dump_root() as root:
                extra = []
                if wal:
                    member = tarfile.TarInfo("./var/lib/ominull/ominull.db-wal")
                    if wal == "symlink":
                        member.type, member.linkname = tarfile.SYMTYPE, "foreign"
                    extra.append((member, None if wal == "symlink" else b""))
                write_dump(owned_attempt(root), extra)
                if wal == "symlink":
                    with self.assertRaises(pd.Refused):
                        self.artifact()
                    continue
                response = self.artifact()
                self.assertEqual(response["required_paths_verified"], REQUIRED)
                self.assertEqual(response["wal_paths_verified"], [] if wal is None else ["var/lib/ominull/ominull.db-wal"])
                self.assertNotIn("secrets", response)

    def test_missing_required_path_is_refused(self):
        with dump_root() as root:
            directory = owned_attempt(root)
            archive = directory / "vzdump-lxc-150-2026_10_06-15_00_00.tar"
            with tarfile.open(archive, "w") as tar:
                member = tarfile.TarInfo("./var/lib/ominull/ominull.db")
                member.size = 2
                tar.addfile(member, io.BytesIO(b"db"))
            with self.assertRaises(pd.Refused):
                self.artifact()

    def test_forced_key_without_recipient_refuses_plaintext_secrets(self):
        with dump_root() as root:
            write_dump(owned_attempt(root))
            with self.assertRaises(pd.Refused):
                self.artifact(forced=True)
            self.assertFalse((root / ("st-ominull-" + "a" * 32) / "secrets.tar.age").exists())

    def test_recipient_must_be_root_owned_and_well_formed(self):
        with dump_root() as root:
            write_dump(owned_attempt(root))
            recipient = root / "recipient"
            recipient.write_text("not-a-recipient\n")
            recipient.chmod(0o644)
            with patch.object(pd, "RECIPIENT_FILE", recipient), patch.object(pd, "RECIPIENT_OWNER", os.getuid()):
                with self.assertRaises(pd.Refused):
                    self.artifact()
            with patch.object(pd, "RECIPIENT_FILE", recipient):
                with self.assertRaises(pd.Refused):  # owned by the test user, not root
                    self.artifact()

    def fetch(self, which="archive", forced=False):
        out = io.BytesIO()
        with patch.object(pd, "api", side_effect=finished):
            pd.run(["fetch", "a" * 32, "bkp-fixture", "pve-fixture", which], forced=forced, out=out)
        return out.getvalue()

    def test_fetch_before_artifact_is_refused(self):
        # The forced key could otherwise create a dump and read it whole,
        # keys included, by never calling artifact.
        for forced in [True, False]:
            with self.subTest(forced=forced), dump_root() as root:
                write_dump(owned_attempt(root))
                for which in ["archive", "secrets"]:
                    with self.assertRaises(pd.Refused):
                        self.fetch(which, forced)

    def test_unsplit_archive_is_fetched_only_by_the_alias_while_no_recipient_exists(self):
        with dump_root() as root:
            directory = owned_attempt(root)
            archive = write_dump(directory)
            self.artifact()
            self.assertEqual(oct((directory / "artifact.json").stat().st_mode & 0o777), "0o600")
            self.assertEqual(self.fetch(), archive.read_bytes())
            with self.assertRaises(pd.Refused):
                self.fetch(forced=True)
            with self.assertRaises(pd.Refused):
                self.fetch("secrets")
            recipient = root / "recipient"
            recipient.write_text("age1" + "q" * 58 + "\n")
            recipient.chmod(0o600)
            with patch.object(pd, "RECIPIENT_FILE", recipient), patch.object(pd, "RECIPIENT_OWNER", os.getuid()):
                with self.assertRaises(pd.Refused):
                    self.fetch()

    def test_fetch_refuses_a_file_changed_or_replaced_after_artifact(self):
        for change in ["appended", "replaced", "symlink"]:
            with self.subTest(change=change), dump_root() as root:
                directory = owned_attempt(root)
                archive = write_dump(directory)
                self.artifact()
                data = archive.read_bytes()
                if change == "appended":
                    with archive.open("ab") as file:
                        file.write(b"x")
                elif change == "replaced":
                    archive.unlink()
                    archive.write_bytes(data)
                else:
                    target = directory / "vzdump-lxc-150-2026_10_06-15_00_00.log"
                    archive.rename(target)
                    archive.symlink_to(target)
                with self.assertRaises((pd.Refused, OSError)):
                    self.fetch()

    def test_artifact_runs_once(self):
        with dump_root() as root:
            write_dump(owned_attempt(root))
            self.artifact()
            with self.assertRaises(pd.Refused):
                self.artifact()


@unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "age is not installed")
class SecretSplitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.identity = Path(self.temp.name) / "identity.txt"
        subprocess.run(["age-keygen", "-o", str(self.identity)], check=True, capture_output=True)
        self.recipient_text = subprocess.run(["age-keygen", "-y", str(self.identity)], check=True,
                                             capture_output=True, text=True).stdout.strip()

    @contextlib.contextmanager
    def recipient(self, root):
        path = root / "recipient"
        path.write_text(self.recipient_text + "\n")
        path.chmod(0o644)
        with patch.object(pd, "RECIPIENT_FILE", path), patch.object(pd, "RECIPIENT_OWNER", os.getuid()):
            yield

    def split(self, root, forced=True):
        with self.recipient(root), patch.object(pd, "api", side_effect=finished):
            return pd.run(["artifact", "a" * 32, "bkp-fixture", "pve-fixture"], forced=forced)

    def decrypt(self, path):
        plain = subprocess.run(["age", "--decrypt", "-i", str(self.identity), str(path)], check=True,
                               capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tar:
            members = {}
            for member in tar:
                data = tar.extractfile(member) if member.isfile() else None
                members[member.name.removeprefix("./")] = data.read() if data else None
            return members

    def test_secret_members_are_sealed_and_gone_from_the_bulk_tar(self):
        later_key = tarfile.TarInfo("./var/lib/ominull-response-authority/tenants/t-1.key")
        later_key.size = 6
        nested = tarfile.TarInfo("./var/lib/ominull-response-authority/tenants/")
        nested.type = tarfile.DIRTYPE
        new_cert_key = tarfile.TarInfo("./opt/ominull/bin/certs/client.key")
        new_cert_key.size = 4
        wal = tarfile.TarInfo("./var/lib/ominull-response-authority/authority.db-wal")
        wal.size = 3
        with dump_root() as root:
            directory = owned_attempt(root)
            archive = write_dump(directory, [(nested, None), (later_key, b"tenant"), (new_cert_key, b"cert"), (wal, b"wal")])
            response = self.split(root)
            with tarfile.open(archive) as tar:
                names = [m.name.removeprefix("./").rstrip("/") for m in tar.getmembers()]
            self.assertFalse([n for n in names if pd.is_secret(n)], "secret member left in the bulk tar")
            self.assertTrue(set(pd.BULK_REQUIRED) <= set(names))
            self.assertIn("etc/ominull", names)  # the directory itself stays; only its contents move
            self.assertEqual(response["required_paths_verified"], sorted(pd.BULK_REQUIRED))
            self.assertEqual(response["wal_paths_verified"], [])
            sealed = directory / "secrets.tar.age"
            self.assertEqual(response["secrets"]["path"], str(sealed))
            self.assertEqual(response["secrets"]["sha256"], hashlib.sha256(sealed.read_bytes()).hexdigest())
            self.assertEqual(response["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(oct(sealed.stat().st_mode & 0o777), "0o600")
            self.assertEqual(response["secrets"]["paths_verified"],
                             sorted(pd.SECRET_REQUIRED | {"var/lib/ominull-response-authority/authority.db-wal"}))
            members = self.decrypt(sealed)
            for name in pd.SECRET_REQUIRED:
                self.assertEqual(members[name], ("content of " + name).encode())
            self.assertEqual(members["var/lib/ominull-response-authority/tenants/t-1.key"], b"tenant")
            self.assertEqual(members["opt/ominull/bin/certs/client.key"], b"cert")
            self.assertNotIn("var/lib/ominull/ominull.db", members)
            self.assertNotIn(b"content of etc/ominull/admin.key", archive.read_bytes())
            self.assertFalse((directory / "secret-members.list").exists())
            # Cleanup accepts what the split leaves behind.
            with patch.object(pd, "api", side_effect=finished):
                self.assertEqual(pd.run(["cleanup", "a" * 32, "bkp-fixture", "pve-fixture"]), {"cleaned": True})

    def test_transitional_alias_also_splits_once_the_recipient_exists(self):
        with dump_root() as root:
            write_dump(owned_attempt(root))
            self.assertIn("secrets", self.split(root, forced=False))

    def test_hard_link_across_the_boundary_is_refused(self):
        for source, target in [("./var/lib/ominull/copy-of-secret", "./var/lib/ominull-response-authority/secret.key"),
                               ("./etc/ominull/db-link", "./var/lib/ominull/ominull.db")]:
            with self.subTest(source=source), dump_root() as root:
                link = tarfile.TarInfo(source)
                link.type, link.linkname = tarfile.LNKTYPE, target
                directory = owned_attempt(root)
                archive = write_dump(directory, [(link, None)])
                before = archive.read_bytes()
                with self.assertRaises(pd.Refused):
                    self.split(root)
                self.assertEqual(archive.read_bytes(), before)
                self.assertFalse((directory / "secrets.tar.age").exists())

    def test_dotted_names_cannot_hide_a_secret_from_the_prefix_test(self):
        for name in ["./var/lib/ominull/../ominull-response-authority/copy.key", "./var//lib/ominull-response-authority/x",
                     "./etc/./ominull/admin.key.bak", "../etc/ominull/escape"]:
            with self.subTest(name=name), dump_root() as root:
                member = tarfile.TarInfo(name)
                member.size = 6
                directory = owned_attempt(root)
                write_dump(directory, [(member, b"secret")])
                with self.assertRaises(pd.Refused):
                    self.split(root)
                self.assertFalse((directory / "secrets.tar.age").exists())

    def test_fetch_streams_only_the_named_files(self):
        for forced in [True, False]:
            with self.subTest(forced=forced), dump_root() as root:
                directory = owned_attempt(root)
                archive = write_dump(directory)
                self.split(root, forced)
                for which, path in [("archive", archive), ("secrets", directory / "secrets.tar.age")]:
                    out = io.BytesIO()
                    with self.recipient(root), patch.object(pd, "api", side_effect=finished):
                        pd.run(["fetch", "a" * 32, "bkp-fixture", "pve-fixture", which], forced=forced, out=out)
                    self.assertEqual(out.getvalue(), path.read_bytes())

    def test_forced_fetch_before_the_split_is_refused_with_a_recipient(self):
        with dump_root() as root:
            write_dump(owned_attempt(root))
            for which in ["archive", "secrets"]:
                with self.recipient(root), patch.object(pd, "api", side_effect=finished), self.assertRaises(pd.Refused):
                    pd.run(["fetch", "a" * 32, "bkp-fixture", "pve-fixture", which], forced=True, out=io.BytesIO())


class BackupConfigurationTests(unittest.TestCase):
    def test_backup_loader_does_not_depend_on_deployment_build_or_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "scripts/st_extension"
            directory.mkdir(parents=True)
            config = {"schema_version": 1, "target_id": "fixture-target", "ssh_alias": "fixture-alias",
                      "lxc_id": 150, "hub_base_url": "https://hub.example.invalid:9443",
                      "admin_key_file": str(root / "missing-admin.key"),
                      "hub_package": "dist/ominull-hub_1.8.43_amd64.deb",
                      "local_binary": "build/ominull-hub",
                      "local_authority_binary": "build/ominull-response-authority"}
            path = directory / "production.local.json"
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            loaded, digest = obs.load_config(root, require_deployment_inputs=False)
            self.assertEqual(loaded, config)
            path.write_text(json.dumps({**config, "proxmox_node": "pve-fixture"}))
            self.assertEqual(obs.load_config(root, require_deployment_inputs=False)[0]["proxmox_node"], "pve-fixture")
            path.write_text(json.dumps(config))
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(obs.ObservationError):
                obs.load_config(root)
            path.chmod(0o644)
            with self.assertRaises(obs.ObservationError):
                obs.load_config(root, require_deployment_inputs=False)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        # An explicitly assigned native directory lets the same tiny fixtures
        # verify ordinary rename publication on the owner's NTFS mount.
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("OMINULL_PUBLICATION_TEST_ROOT"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.destination = self.root / "external" / bk.SOURCE
        self.patch = patch.object(bk, "DESTINATION", self.destination)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.config = {"ssh_alias": "approved-fixture", "lxc_id": 150, "proxmox_node": "pve-fixture"}
        self.config_patch = patch.object(obs, "load_config", return_value=(self.config, "a" * 64))
        self.load_config_mock = self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.mount_patch = patch.object(bk, "require_backup_mount")
        self.mount_patch.start()
        self.addCleanup(self.mount_patch.stop)
        self.payload = b"consistent-uncompressed-archive-fixture"
        self.calls = []
        self.task = "UPID:pve-fixture:fixture"
        self.failure = None
        self.guest_status = "running"
        self.discarded = []
        self.sealed = None  # Set to bytes when the remote side splits secrets out.

    def remote(self, config, program, attempt, backup_id):
        self.calls.append(program)
        if self.failure == program:
            raise obs.ObservationError("fixture_failure")
        if program == bk.REMOTE_GUEST:
            return {"guest_status": self.guest_status}
        if program == bk.REMOTE_CREATE:
            return {"task": self.task, "used_bytes": len(self.payload)}
        if program == bk.REMOTE_STATUS:
            return {"status": "stopped", "exitstatus": "ERROR" if self.failure == "task" else "OK"}
        if program == bk.REMOTE_ARTIFACT:
            artifact: dict[str, object] = {"path": f"/var/lib/vz/dump/st-ominull-{attempt}/vzdump-lxc-150-2026_10_06-15_00_00.tar",
                        "size_bytes": len(self.payload), "sha256": hashlib.sha256(self.payload).hexdigest(),
                        "required_paths_verified": ["fixture-required-path"], "wal_paths_verified": []}
            if self.sealed is not None:
                artifact["secrets"] = {"path": f"/var/lib/vz/dump/st-ominull-{attempt}/secrets.tar.age",
                                       "size_bytes": len(self.sealed), "sha256": hashlib.sha256(self.sealed).hexdigest(),
                                       "recipient_id": "age:" + "c" * 16, "members": 9,
                                       "paths_verified": ["etc/ominull/admin.key"]}
            return artifact
        if program == bk.REMOTE_CLEANUP:
            self.assertTrue((self.destination / "current/lxc-150.tar").exists())
            return {"cleaned": True}
        if program == bk.REMOTE_DISCARD:
            self.discarded.append(attempt)
            return {"discarded": True}
        self.fail("unexpected remote program")

    def fetch(self, config, attempt, backup_id, which, expected, destination):
        if self.failure == "fetch":
            destination.write_bytes(b"incomplete")
            raise obs.ObservationError("fixture_fetch_failure")
        destination.write_bytes(self.payload if which == "archive" else self.sealed)
        destination.chmod(0o600)

    def prepare(self, request=REQUEST):
        with patch.object(bk, "remote", side_effect=self.remote), patch.object(bk, "fetch", side_effect=self.fetch):
            return bk.prepare(request, self.root)

    def qualified_request(self, prior):
        return {**REQUEST, "qualified_previous": {"backup_id": prior["backup_id"],
                "sha256": prior["sha256"], "snapshot_id": "restic-point", "repository_id": "repo-fixture"}}

    def test_qualified_predecessor_retirement_allows_repeated_fresh_capture(self):
        prior = self.prepare()
        for payload in [b"second generation", b"third generation"]:
            self.payload = payload
            result = self.prepare(self.qualified_request(prior))
            self.assertEqual(result["status"], "completed")
            self.assertEqual(Path(result["archive_path"]).read_bytes(), payload)
            self.assertFalse(list(self.destination.glob(".previous-*")))
            prior = result

    def test_mismatched_qualification_refused_before_remote_capture(self):
        prior = self.prepare()
        request = self.qualified_request(prior)
        request["qualified_previous"]["sha256"] = "a" * 64
        self.calls.clear()
        with self.assertRaises(obs.ObservationError):
            self.prepare(request)
        self.assertEqual(self.calls, [])
        self.assertEqual(bk._generation(self.destination / "current"), prior)

    def test_interrupted_qualified_retirement_resumes_only_exact_owned_files(self):
        prior = self.prepare()
        staging, response = self.staged_generation()
        original = Path.unlink
        def interrupt(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path.name == "lxc-150.tar":
                raise OSError("interrupted qualified retirement")
            return result
        with patch.object(Path, "unlink", interrupt), self.assertRaises(OSError):
            bk.publish(staging, response, self.qualified_request(prior)["qualified_previous"])
        self.assertEqual(bk._generation(self.destination / "current"), response)
        bk.retire_qualified_previous()
        self.assertFalse(list(self.destination.glob(".previous-*")))
        self.assertFalse((self.destination / ".retirement.json").exists())

    def test_success_manifest_binds_exact_verified_archive_then_cleans_only_attempt(self):
        result = self.prepare()
        self.load_config_mock.assert_called_once_with(self.root, require_deployment_inputs=False)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["target_id"], 150)
        self.assertEqual(result["backup_id"], REQUEST["backup_id"])
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result["size_bytes"], len(self.payload))
        self.assertEqual(json.loads(Path(result["manifest_path"]).read_text()), result)
        self.assertEqual(Path(result["archive_path"]).read_bytes(), self.payload)
        self.assertEqual(self.calls[-1], bk.REMOTE_CLEANUP)
        self.assertEqual(list(self.destination.glob(".attempt-*")), [])

    def test_atomic_replacement_preserves_complete_generations(self):
        prior = self.prepare()
        self.payload = b"second consistent generation"
        result = self.prepare()
        self.assertNotEqual(prior["sha256"], result["sha256"])
        self.assertEqual(json.loads(Path(result["manifest_path"]).read_text()), result)
        self.assertEqual(Path(result["archive_path"]).read_bytes(), self.payload)
        self.assertEqual(list(self.destination.glob(".attempt-*")), [])
        previous = list(self.destination.glob(".previous-*"))
        self.assertEqual(len(previous), 1)
        self.assertEqual(json.loads((previous[0] / "manifest.json").read_text()), prior)

    def test_uncaptured_generations_recover_without_accumulating(self):
        # The parent captured neither of two fresh generations (live 2026-10-16):
        # the next unqualified run offers current again instead of refusing forever.
        prior = self.prepare()
        self.payload = b"second consistent generation"
        second = self.prepare()
        previous = list(self.destination.glob(".previous-*"))
        self.calls.clear()
        offered = self.prepare({**REQUEST, "backup_id": "bkp-reoffer"})
        self.assertEqual(self.calls, [])
        self.assertEqual(offered["backup_id"], "bkp-reoffer")
        self.assertEqual(offered["sha256"], second["sha256"])
        self.assertEqual(offered["reused_from_backup_id"], second["backup_id"])
        self.assertFalse(offered["capture_fresh"])
        self.assertEqual(bk._generation(self.destination / "current"), offered)
        self.assertEqual(list(self.destination.glob(".previous-*")), previous)
        self.assertEqual(bk._generation(previous[0]), prior)
        # Once the parent captures current, the older uncaptured generation is
        # superseded and the next fresh capture proceeds normally.
        self.payload = b"third consistent generation"
        third = self.prepare(self.qualified_request(offered))
        self.assertEqual(third["status"], "completed")
        self.assertEqual(Path(third["archive_path"]).read_bytes(), self.payload)
        self.assertFalse(list(self.destination.glob(".previous-*")))
        self.assertFalse((self.destination / ".retirement.json").exists())
        markers = [json.loads(path.read_text()) for path in self.destination.glob("retirement-completed-*.json")]
        self.assertIn(prior["backup_id"], [marker["qualification"]["backup_id"] for marker in markers
                                           if marker.get("superseded_by") == "bkp-reoffer"])

    def test_superseded_retirement_refuses_a_newer_predecessor(self):
        prior = self.prepare()
        self.payload = b"second consistent generation"
        self.prepare()
        offered = self.prepare({**REQUEST, "backup_id": "bkp-reoffer"})
        previous = list(self.destination.glob(".previous-*"))[0]
        bk._save_json(previous / "manifest.json", {**prior, "completed_at": "2999-01-01T00:00:00+00:00"})
        self.calls.clear()
        with self.assertRaises(obs.ObservationError):
            self.prepare(self.qualified_request(offered))
        self.assertEqual(self.calls, [])
        self.assertTrue(previous.exists())

    def staged_generation(self, payload=b"replacement fixture"):
        staging = self.destination / (".attempt-" + "a" * 32)
        staging.mkdir(mode=0o700)
        (staging / "lxc-150.tar").write_bytes(payload)
        (staging / "lxc-150.tar").chmod(0o600)
        response = {**json.loads((self.destination / "current/manifest.json").read_text()),
                    "backup_id": "bkp-staged", "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload), "completed_at": "2099-01-01T00:00:00+00:00"}
        bk._save_json(staging / "manifest.json", response)
        return staging, response

    def test_interruption_after_each_rename_recovers_without_losing_last_good(self):
        prior = self.prepare()
        staging, response = self.staged_generation()
        current = self.destination / "current"
        original = Path.rename
        for boundary in ["current", staging.name]:
            with self.subTest(boundary=boundary):
                def interrupt(path, target):
                    result = original(path, target)
                    if path.name == boundary:
                        raise OSError("simulated interrupted publication")
                    return result
                with patch.object(Path, "rename", interrupt), self.assertRaises(OSError):
                    bk.publish(staging, response)
                recovered = bk.recover_publication()
                if boundary == "current":
                    self.assertIsNone(recovered)
                    self.assertEqual(bk._generation(current), prior)
                    self.assertTrue(staging.exists())
                else:
                    self.assertEqual(recovered, response)
                    self.assertEqual(bk._generation(current), response)
                    previous = self.destination / (".previous-" + "a" * 32)
                    self.assertEqual(bk._generation(previous), prior)
        self.assertFalse((self.destination / ".publication.json").exists())

    def test_verified_failed_generation_reused_without_remote_capture_or_false_freshness(self):
        prior = self.prepare()
        staging, staged = self.staged_generation()
        failure = {"backup_id": staged["backup_id"], "error": "backup_atomic_publication",
                   "publication_completed": False}
        bk._save_json(self.destination / ("failure-" + "a" * 32 + ".json"), failure)
        self.calls.clear()
        result = self.prepare()
        self.assertEqual(self.calls, [])
        self.assertEqual(result["backup_id"], REQUEST["backup_id"])
        self.assertEqual(result["reused_from_backup_id"], staged["backup_id"])
        self.assertEqual(result["completed_at"], staged["completed_at"])
        self.assertFalse(result["capture_fresh"])
        self.assertEqual(bk._generation(self.destination / "current"), result)
        previous = self.destination / (".previous-" + "a" * 32)
        self.assertEqual(bk._generation(previous), prior)
        self.assertFalse(staging.exists())

    def test_corrupt_failed_generation_is_refused_before_remote_capture(self):
        self.prepare()
        staging, staged = self.staged_generation()
        bk._save_json(self.destination / ("failure-" + "a" * 32 + ".json"),
                      {"backup_id": staged["backup_id"], "error": "backup_atomic_publication",
                       "publication_completed": False})
        (staging / "lxc-150.tar").write_bytes(b"x" * staged["size_bytes"])
        self.calls.clear()
        with self.assertRaises(obs.ObservationError):
            self.prepare()
        self.assertEqual(self.calls, [])

    def test_failure_retains_prior_publication_and_attempt_without_remote_cleanup(self):
        prior = self.prepare()
        self.calls.clear()
        for failure in [bk.REMOTE_CREATE, "task", bk.REMOTE_ARTIFACT, "fetch"]:
            with self.subTest(failure=failure):
                self.failure = failure
                self.calls.clear()
                result = self.prepare()
                self.assertEqual(result["status"], "failed")
                self.assertNotIn(bk.REMOTE_CLEANUP, self.calls)
                self.assertEqual(json.loads(Path(prior["manifest_path"]).read_text()), prior)
                self.assertTrue((self.destination / ("failure-" + result["attempt_id"] + ".json")).exists())
                self.assertTrue((self.destination / (".attempt-" + result["attempt_id"])).exists())

    def test_next_run_discards_unverified_failed_attempt_and_captures(self):
        prior = self.prepare()
        for failure in [bk.REMOTE_CREATE, "fetch"]:
            with self.subTest(failure=failure):
                self.failure = failure
                failed = self.prepare()
                self.assertEqual(failed["status"], "failed")
                self.failure = None
                self.payload = failure.encode() if isinstance(failure, str) else b"next"
                result = self.prepare(self.qualified_request(prior))
                self.assertEqual(result["status"], "completed")
                self.assertIn(failed["attempt_id"], self.discarded)
                self.assertEqual(list(self.destination.glob(".attempt-*")), [])
                prior = result

    def test_killed_attempt_without_failure_record_is_discarded(self):
        self.prepare()
        staging = self.destination / (".attempt-" + "c" * 32)
        staging.mkdir(mode=0o700)
        (staging / "lxc-150.tar").write_bytes(b"partial")
        self.guest_status = "stopped"
        result = self.prepare()
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.discarded, ["c" * 32])
        self.assertFalse(staging.exists())

    def test_refused_remote_discard_keeps_attempt_and_captures_nothing(self):
        self.prepare()
        staging = self.destination / (".attempt-" + "c" * 32)
        staging.mkdir(mode=0o700)
        self.failure = bk.REMOTE_DISCARD
        self.calls.clear()
        with self.assertRaises(obs.ObservationError):
            self.prepare()
        self.assertTrue(staging.exists())
        self.assertNotIn(bk.REMOTE_CREATE, self.calls)

    def test_verified_attempt_is_never_discarded(self):
        self.prepare()
        staging, _ = self.staged_generation()
        with self.assertRaises(obs.ObservationError):
            self.prepare()
        self.assertTrue((staging / "lxc-150.tar").exists())
        self.assertEqual(self.discarded, [])

    def test_evidence_markers_are_bounded(self):
        self.prepare()
        for index in range(bk.EVIDENCE_KEEP + 5):
            marker = self.destination / f"retirement-completed-{index:032x}.json"
            marker.write_text("{}")
            os.utime(marker, (index, index))
        self.guest_status = "stopped"
        self.prepare()
        remaining = sorted(path.name for path in self.destination.glob("retirement-completed-*.json"))
        self.assertEqual(len(remaining), bk.EVIDENCE_KEEP)
        self.assertNotIn(f"retirement-completed-{0:032x}.json", remaining)

    def test_stopped_guest_skips_without_failure_evidence_or_attempt(self):
        prior = self.prepare()
        self.calls.clear()
        self.guest_status = "stopped"
        result = self.prepare()
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "guest_stopped")
        self.assertEqual(result["backup_id"], REQUEST["backup_id"])
        self.assertEqual(self.calls, [bk.REMOTE_GUEST])
        self.assertEqual(list(self.destination.glob(".attempt-*")), [])
        self.assertEqual(list(self.destination.glob("failure-*.json")), [])
        self.assertEqual(bk._generation(self.destination / "current"), prior)

    def test_unknown_guest_state_refused_before_staging(self):
        self.guest_status = "paused"
        with self.assertRaises(obs.ObservationError):
            self.prepare()
        self.assertEqual(self.calls, [bk.REMOTE_GUEST])
        self.assertEqual(list(self.destination.glob(".attempt-*")), [])

    def test_wrong_protected_guest_refused_before_remote_io(self):
        self.config["lxc_id"] = 151
        with patch.object(bk, "remote", side_effect=AssertionError("remote must not run")), self.assertRaises(obs.ObservationError):
            bk.prepare(REQUEST, self.root)

    def test_missing_mount_refuses_before_mkdir_or_remote_job(self):
        with patch.object(bk, "require_backup_mount", side_effect=obs.ObservationError("backup_mount_unavailable")), self.assertRaises(obs.ObservationError):
            self.prepare()
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.calls, [])

    def test_capacity_refusal_preserves_attempt_and_never_fetches_or_cleans(self):
        with patch.object(bk.shutil, "disk_usage", return_value=type("Usage", (), {"free": 0})()):
            result = self.prepare()
        self.assertEqual(result["error"], "backup_local_capacity")
        self.assertNotIn(bk.REMOTE_CLEANUP, self.calls)
        self.assertTrue((self.destination / (".attempt-" + result["attempt_id"])).exists())

    def test_symlink_destination_refused_before_remote_io(self):
        self.destination.parent.mkdir()
        self.destination.symlink_to(self.root, target_is_directory=True)
        with patch.object(bk, "remote", side_effect=AssertionError("remote must not run")), self.assertRaises(obs.ObservationError):
            bk.prepare(REQUEST, self.root)

    def test_remote_cleanup_failure_is_truthful_and_preserves_publication(self):
        self.failure = bk.REMOTE_CLEANUP
        result = self.prepare()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["proxmox_task_id"], self.task)
        self.assertTrue((self.destination / "current/lxc-150.tar").exists())
        self.assertTrue((self.destination / ("failure-" + result["attempt_id"] + ".json")).exists())

    def test_unowned_existing_publication_is_not_replaced(self):
        current = self.destination / "current"
        current.mkdir(parents=True, mode=0o700)
        self.destination.chmod(0o700)
        (current / "foreign.txt").write_text("foreign data")
        with self.assertRaises(obs.ObservationError):
            self.prepare()
        self.assertEqual((current / "foreign.txt").read_text(), "foreign data")
        self.assertNotIn(bk.REMOTE_CLEANUP, self.calls)

    def test_fetch_verifies_received_bytes_and_digest(self):
        target = self.root / "incoming.tar"
        artifact = {"path": "/fixed/fixture.tar", "size_bytes": len(self.payload),
                    "sha256": hashlib.sha256(self.payload).hexdigest()}
        config = {**self.config, "backup_ssh_alias": "ominull-backup"}
        def process(argv, **kwargs):
            self.assertEqual(argv[-2:], ["ominull-backup", "fetch " + "a" * 32 + " bkp-fixture pve-fixture archive"])
            kwargs["stdout"].write(self.payload)
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(subprocess, "run", side_effect=process):
            bk.fetch(config, "a" * 32, "bkp-fixture", "archive", artifact, target)
        self.assertEqual(target.read_bytes(), self.payload)
        corrupt = self.root / "bad.tar"
        with patch.object(subprocess, "run", side_effect=process), self.assertRaises(obs.ObservationError):
            bk.fetch(config, "a" * 32, "bkp-fixture", "archive", {**artifact, "sha256": "0" * 64}, corrupt)
        self.assertTrue(corrupt.exists())

    def test_split_generation_publishes_both_digests_and_retires_both_files(self):
        self.sealed = b"age-encrypted-secret-members"
        first = self.prepare()
        self.assertEqual(first["status"], "completed", first)
        current = self.destination / "current"
        self.assertEqual(sorted(p.name for p in current.iterdir()), ["lxc-150-secrets.tar.age", "lxc-150.tar", "manifest.json"])
        self.assertEqual(first["secrets_archive_path"], str(current / "lxc-150-secrets.tar.age"))
        self.assertEqual(first["secrets_sha256"], hashlib.sha256(self.sealed).hexdigest())
        self.assertEqual(first["secrets_size_bytes"], len(self.sealed))
        self.assertEqual(json.loads((current / "manifest.json").read_text()), first)
        bk._generation(current, verify_hash=True)
        (current / "lxc-150-secrets.tar.age").write_bytes(b"tampered-secret-archive-xxxx")
        with self.assertRaises(obs.ObservationError):
            bk._generation(current, verify_hash=True)
        (current / "lxc-150-secrets.tar.age").write_bytes(self.sealed)
        second = self.prepare(self.qualified_request(first))
        self.assertEqual(second["status"], "completed", second)
        self.assertFalse(list(self.destination.glob(".previous-*")))

    def test_forced_key_refuses_an_unsplit_archive(self):
        self.config["backup_ssh_alias"] = "ominull-backup"
        response = self.prepare()
        self.assertEqual(response["status"], "failed")
        self.assertEqual(response["error"], "backup_secrets_not_sealed")
        self.assertFalse((self.destination / "current").exists())
        self.assertNotIn(bk.REMOTE_CLEANUP, self.calls)


if __name__ == "__main__":
    unittest.main()
