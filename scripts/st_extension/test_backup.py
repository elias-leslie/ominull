"""Fixed backup wire and isolated preparation tests; no remote production I/O."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import backup as bk
import observer as obs

REQUEST = {"contract_version": 1, "operation": "prepare_backup", "project": "ominull",
           "source_id": bk.SOURCE, "backup_id": "bkp-fixture"}


class ProtocolTests(unittest.TestCase):
    def test_fixed_wire_refuses_target_command_and_destination_overrides(self):
        self.assertEqual(bk.parse_request(json.dumps(REQUEST)), REQUEST)
        for extra in [{"host": "foreign"}, {"destination": "/tmp/foreign"}, {"command": "stop"},
                      {"contract_version": True}, {"project": "other"},
                      {"source_id": "other"}, {"backup_id": "../escape"}, {"operation": "reset"}]:
            with self.subTest(extra=extra), self.assertRaises(obs.ObservationError):
                bk.parse_request(json.dumps({**REQUEST, **extra}))
        with self.assertRaises(obs.ObservationError):
            bk.parse_request('{"contract_version":1,"contract_version":1}')

    def test_remote_programs_parse_and_fixed_backup_never_stops_or_prunes(self):
        for program in [bk.REMOTE_CREATE, bk.REMOTE_STATUS, bk.REMOTE_ARTIFACT, bk.REMOTE_CLEANUP]:
            compile(program, "fixed-remote-program", "exec")
        self.assertIn('"--mode", "snapshot"', bk.REMOTE_CREATE)
        self.assertIn('"--compress", "0", "--remove", "0"', bk.REMOTE_CREATE)
        self.assertNotIn('"--stop"', bk.REMOTE_CREATE)
        self.assertNotIn('rmtree', bk.REMOTE_CLEANUP)

    def test_remote_failure_withholds_stderr_and_host(self):
        failed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"private credential material")
        with patch.object(subprocess, "run", return_value=failed), self.assertRaises(obs.ObservationError) as caught:
            bk.remote({"ssh_alias": "private-alias"}, "fixed", "a" * 32, "bkp-fixture")
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


class RemoteCleanupTests(unittest.TestCase):
    def test_exact_owned_attempt_cleanup_and_foreign_contents_refusal(self):
        for foreign in [False, True]:
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                attempt = "a" * 32
                directory = root / ("st-ominull-" + attempt)
                directory.mkdir(mode=0o700)
                marker = {"attempt": attempt, "backup_id": "bkp-fixture", "guest": 150,
                          "task": "UPID:davion-gem:fixture"}
                (directory / "attempt.json").write_text(json.dumps(marker))
                archive = directory / "vzdump-lxc-150-2026_10_06-15_00_00.tar"
                archive.write_bytes(b"verified fixture")
                if foreign:
                    (directory / "foreign.txt").write_text("preserve foreign data")
                program = bk.REMOTE_CLEANUP.replace('pathlib.Path("/var/lib/vz/dump")', f"pathlib.Path({str(root)!r})")
                status = subprocess.CompletedProcess([], 0, stdout='{"status":"stopped","exitstatus":"OK"}')
                with patch.object(bk.sys, "argv", ["cleanup", attempt, "bkp-fixture"]), patch.object(subprocess, "run", return_value=status), contextlib.redirect_stdout(io.StringIO()):
                    if foreign:
                        with self.assertRaises(AssertionError):
                            exec(program, {})
                    else:
                        exec(program, {})
                self.assertEqual(directory.exists(), foreign)
                if foreign:
                    self.assertTrue(archive.exists())

    def test_checkpointed_database_without_wal_and_present_wal_shape(self):
        required = ["var/lib/ominull/ominull.db", "var/lib/ominull/evidence.key",
                    "var/lib/ominull/evidence/receipt.key", "var/lib/ominull-response-authority/authority.db",
                    "var/lib/ominull-response-authority/secret.key", "opt/ominull/bin/certs/ca.key",
                    "opt/ominull/bin/certs/ca.crt", "opt/ominull/bin/certs/server.key",
                    "opt/ominull/bin/certs/server.crt", "etc/ominull/hub.env",
                    "etc/ominull/response-authority.env", "etc/ominull/admin.key"]
        for wal in [None, "regular", "symlink"]:
            with self.subTest(wal=wal), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                attempt = "a" * 32
                directory = root / ("st-ominull-" + attempt)
                directory.mkdir(mode=0o700)
                (directory / "attempt.json").write_text(json.dumps({"attempt": attempt,
                    "backup_id": "bkp-fixture", "guest": 150, "task": "UPID:davion-gem:fixture"}))
                archive = directory / "vzdump-lxc-150-2026_10_06-15_00_00.tar"
                with tarfile.open(archive, "w") as tar:
                    for name in required:
                        member = tarfile.TarInfo("./" + name)
                        member.size = 7
                        tar.addfile(member, io.BytesIO(b"fixture"))
                    if wal:
                        member = tarfile.TarInfo("./var/lib/ominull/ominull.db-wal")
                        if wal == "symlink":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "foreign"
                        tar.addfile(member)
                program = bk.REMOTE_ARTIFACT.replace('pathlib.Path("/var/lib/vz/dump")', f"pathlib.Path({str(root)!r})")
                status = subprocess.CompletedProcess([], 0, stdout='{"status":"stopped","exitstatus":"OK"}')
                output = io.StringIO()
                with patch.object(bk.sys, "argv", ["artifact", attempt, "bkp-fixture"]), patch.object(subprocess, "run", return_value=status), contextlib.redirect_stdout(output):
                    if wal == "symlink":
                        with self.assertRaises(AssertionError):
                            exec(program, {})
                    else:
                        exec(program, {})
                if wal != "symlink":
                    response = json.loads(output.getvalue())
                    self.assertEqual(response["required_paths_verified"], sorted(required))
                    self.assertEqual(response["wal_paths_verified"], [] if wal is None else ["var/lib/ominull/ominull.db-wal"])


class BackupConfigurationTests(unittest.TestCase):
    def test_backup_loader_does_not_depend_on_deployment_build_or_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "scripts/st_extension"
            directory.mkdir(parents=True)
            config = {"schema_version": 1, "target_id": "fixture-target", "ssh_alias": "fixture-alias",
                      "lxc_id": 150, "hub_base_url": "http://hub.example.invalid:9999",
                      "admin_key_file": str(root / "missing-admin.key"),
                      "hub_package": "dist/ominull-hub_1.8.43_amd64.deb",
                      "local_binary": "build/ominull-hub",
                      "local_authority_binary": "build/ominull-response-authority"}
            path = directory / "production.local.json"
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            loaded, digest = obs.load_config(root, require_deployment_inputs=False)
            self.assertEqual(loaded, config)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(obs.ObservationError):
                obs.load_config(root)
            path.chmod(0o644)
            with self.assertRaises(obs.ObservationError):
                obs.load_config(root, require_deployment_inputs=False)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.destination = self.root / "external" / bk.SOURCE
        self.patch = patch.object(bk, "DESTINATION", self.destination)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.config = {"ssh_alias": "approved-fixture", "lxc_id": 150}
        self.config_patch = patch.object(obs, "load_config", return_value=(self.config, "a" * 64))
        self.load_config_mock = self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.mount_patch = patch.object(bk, "require_backup_mount")
        self.mount_patch.start()
        self.addCleanup(self.mount_patch.stop)
        self.payload = b"consistent-uncompressed-archive-fixture"
        self.calls = []
        self.task = "UPID:davion-gem:fixture"
        self.failure = None

    def remote(self, config, program, attempt, backup_id):
        self.calls.append(program)
        if self.failure == program:
            raise obs.ObservationError("fixture_failure")
        if program == bk.REMOTE_CREATE:
            return {"task": self.task, "used_bytes": len(self.payload)}
        if program == bk.REMOTE_STATUS:
            return {"status": "stopped", "exitstatus": "ERROR" if self.failure == "task" else "OK"}
        if program == bk.REMOTE_ARTIFACT:
            return {"path": f"/var/lib/vz/dump/st-ominull-{attempt}/vzdump-lxc-150-2026_10_06-15_00_00.tar",
                    "size_bytes": len(self.payload), "sha256": hashlib.sha256(self.payload).hexdigest(),
                    "required_paths_verified": ["fixture-required-path"], "wal_paths_verified": []}
        if program == bk.REMOTE_CLEANUP:
            self.assertTrue((self.destination / "current/lxc-150.tar").exists())
            return {"cleaned": True}
        self.fail("unexpected remote program")

    def fetch(self, config, artifact, destination):
        if self.failure == "fetch":
            destination.write_bytes(b"incomplete")
            raise obs.ObservationError("fixture_fetch_failure")
        destination.write_bytes(self.payload)
        destination.chmod(0o600)

    def prepare(self):
        with patch.object(bk, "remote", side_effect=self.remote), patch.object(bk, "fetch", side_effect=self.fetch):
            return bk.prepare(REQUEST, self.root)

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
        result = self.prepare()
        self.assertEqual(result["status"], "failed")
        self.assertEqual((current / "foreign.txt").read_text(), "foreign data")
        self.assertNotIn(bk.REMOTE_CLEANUP, self.calls)

    def test_fetch_verifies_received_bytes_and_digest(self):
        target = self.root / "incoming.tar"
        artifact = {"path": "/fixed/fixture.tar", "size_bytes": len(self.payload),
                    "sha256": hashlib.sha256(self.payload).hexdigest()}
        def process(argv, **kwargs):
            self.assertEqual(argv[-1], "cat -- /fixed/fixture.tar")
            kwargs["stdout"].write(self.payload)
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(subprocess, "run", side_effect=process):
            bk.fetch(self.config, artifact, target)
        self.assertEqual(target.read_bytes(), self.payload)
        corrupt = self.root / "bad.tar"
        with patch.object(subprocess, "run", side_effect=process), self.assertRaises(obs.ObservationError):
            bk.fetch(self.config, {**artifact, "sha256": "0" * 64}, corrupt)
        self.assertTrue(corrupt.exists())


if __name__ == "__main__":
    unittest.main()
