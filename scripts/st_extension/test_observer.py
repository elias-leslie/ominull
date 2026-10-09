"""Isolated protocol, provenance, and artifact-failure tests; no production I/O."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from typing import Any

import observer as obs


COMMIT = "a" * 40
REQUEST = {"contract_version": 1, "operation": "observe_deployment", "challenge": "1" * 32,
           "task_id": "task-fixture", "project": "ominull", "accepted_source_commit": COMMIT,
           "acceptance_id": "acceptance-fixture"}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts/st_extension").mkdir(parents=True)
        (self.root / "build").mkdir()
        (self.root / "dist").mkdir()
        self.key_file = self.root / "credential.key"
        self.key_file.write_text("fixture-only-credential\n")
        self.key_file.chmod(0o600)
        self.config: dict[str, Any] = {"schema_version": 1, "target_id": "fixture-target", "ssh_alias": "fixture-alias",
            "lxc_id": 100, "hub_base_url": "http://hub.example.invalid:9999",
            "admin_key_file": str(self.key_file), "hub_package": "dist/ominull-hub_1.8.43_amd64.deb",
            "local_binary": "build/ominull-hub", "local_authority_binary": "build/ominull-response-authority"}
        for path in (self.config["hub_package"], self.config["local_binary"],
                     self.config["local_authority_binary"]):
            (self.root / path).write_bytes(b"fixture")
        self.config_file = self.root / "scripts/st_extension/production.local.json"
        self.write_config()

    def write_config(self):
        self.config_file.write_text(json.dumps(self.config))
        self.config_file.chmod(0o600)


class ProtocolTests(unittest.TestCase):
    def test_exact_request_and_bindings(self):
        self.assertEqual(obs.parse_request(json.dumps(REQUEST)), REQUEST)
        for change in ({"contract_version": True}, {"project": "elsewhere"},
                       {"operation": "deploy"}, {"challenge": "../"},
                       {"accepted_source_commit": "main"}, {"task_id": "x\nsecret"},
                       {"expected_hash": "b" * 64}, {"host": "arbitrary"}):
            with self.subTest(change=change), self.assertRaises(obs.ObservationError):
                obs.parse_request(json.dumps({**REQUEST, **change}))
        self.assertEqual(obs.parse_request(json.dumps({**REQUEST, "accepted_source_commit": "b" * 64}))[
            "accepted_source_commit"], "b" * 64)

    def test_duplicate_json_and_size_are_rejected(self):
        with self.assertRaises(obs.ObservationError):
            obs.parse_json('{"project":"ominull","project":"other"}')
        with self.assertRaises(obs.ObservationError):
            obs.parse_request(" " * 16385)

    def test_buildinfo_requires_actual_clean_source(self):
        valid = (f"binary: go1.26.7\n\tbuild\tvcs=git\n\tbuild\tvcs.revision={COMMIT}\n"
                 "\tbuild\tvcs.modified=false\n").encode()
        self.assertEqual(obs.parse_buildinfo(valid), {"source_commit": COMMIT, "vcs_modified": False})
        for raw in (valid.replace(b"false", b"true"), valid.replace(COMMIT.encode(), b"main"),
                    valid + b"\tbuild\tvcs.modified=false\n", b"binary: go1.26.7\n"):
            with self.subTest(raw=raw), self.assertRaises(obs.ObservationError):
                obs.parse_buildinfo(raw)

    def test_service_state_requires_a_live_identity(self):
        valid = b"ActiveState=active\nSubState=running\nMainPID=123\nNRestarts=0\nExecMainStartTimestampMonotonic=456\n"
        self.assertEqual(obs.parse_service(valid)["pid"], 123)
        for raw in (valid.replace(b"MainPID=123", b"MainPID=0"),
                    valid.replace(b"active", b"failed"), valid + b"unexpected=secret\n",
                    valid.replace(b"NRestarts=0", b"NRestarts=invalid"),
                    valid + b"MainPID=123\n"):
            with self.assertRaises(obs.ObservationError):
                obs.parse_service(raw)

    def test_subprocess_errors_and_timeouts_do_not_echo_diagnostics(self):
        secret = "fixture-secret-in-diagnostics"
        with patch.object(obs.subprocess, "run", side_effect=subprocess.TimeoutExpired([secret], 60)):
            with self.assertRaisesRegex(obs.ObservationError, "command_unavailable_or_timeout"):
                obs.run(["fixture-command"])
        with patch.object(obs.subprocess, "run", return_value=subprocess.CompletedProcess(
                [secret], 1, stdout=secret.encode(), stderr=secret.encode())):
            with self.assertRaisesRegex(obs.ObservationError, "^command_failed$"):
                obs.run(["fixture-command"])

    def test_public_key_parser_reads_only_pinned_pem(self):
        header = ('#define PUBLIC \\\n"-----BEGIN PUBLIC KEY-----\\n" \\\n'
                  '"fixture-public-key\\n" \\\n"-----END PUBLIC KEY-----\\n"\n')
        with patch.object(obs, "git", return_value=header.encode()):
            self.assertEqual(obs.pinned_public_key(Path("/fixture"), COMMIT),
                b"-----BEGIN PUBLIC KEY-----\nfixture-public-key\n-----END PUBLIC KEY-----\n")


class ConfigurationTests(Fixture):
    def test_owner_only_fixed_configuration(self):
        config, digest = obs.load_config(self.root)
        self.assertEqual(config, self.config)
        self.assertEqual(digest, hashlib.sha256(self.config_file.read_bytes()).hexdigest())

    def test_missing_unsafe_or_expanded_configuration_fails_closed(self):
        mutations = ({"ssh_alias": "-oProxyCommand=secret"}, {"lxc_id": 0},
                     {"lxc_id": -1}, {"lxc_id": "100"}, {"lxc_id": True},
                     {"hub_base_url": "http://secret@hub/"},
                     {"hub_base_url": "http://hub/?key=secret"},
                     {"local_binary": "../../outside"}, {"hub_package": "dist/../outside.deb"},
                     {"expected_source_commit": COMMIT}, {"target_id": "secret\n"})
        original = copy.deepcopy(self.config)
        for mutation in mutations:
            self.config = {**original, **mutation}
            self.write_config()
            with self.subTest(mutation=mutation), self.assertRaises(obs.ObservationError):
                obs.load_config(self.root)
        self.config = original
        self.write_config()
        self.config_file.chmod(0o644)
        with self.assertRaises(obs.ObservationError):
            obs.load_config(self.root)
        self.config_file.unlink()
        with self.assertRaises(obs.ObservationError):
            obs.load_config(self.root)

    def test_symlink_and_header_injection_are_rejected(self):
        link = self.root / "link.key"
        link.symlink_to(self.key_file)
        self.config["admin_key_file"] = str(link)
        self.write_config()
        with self.assertRaises(obs.ObservationError):
            obs.load_config(self.root)
        self.config["admin_key_file"] = str(self.key_file)
        self.key_file.write_text("fixture\r\nX-Injected: secret")
        with self.assertRaises(obs.ObservationError):
            obs.credential(self.config)

    def test_approved_two_line_credential_uses_only_admin(self):
        self.key_file.write_text("fixture-admin\nfixture-tenant\n")
        self.assertEqual(obs.credential(self.config), "fixture-admin")
        self.key_file.write_text("fixture-admin\nfixture-tenant")
        self.assertEqual(obs.credential(self.config), "fixture-admin")
        for value in ("fixture-admin\n\n", "fixture-admin\ninvalid tenant\n",
                      "fixture-admin\nfixture-tenant\nextra\n", "fixture\rX-Injected: secret\n"):
            self.key_file.write_text(value)
            with self.subTest(value=value), self.assertRaises(obs.ObservationError):
                obs.credential(self.config)

    def test_failure_response_does_not_echo_private_values(self):
        self.config["hub_base_url"] = "http://secretcredential@host/"
        self.write_config()
        with patch.object(obs, "ssh", side_effect=AssertionError("must not contact target")):
            result = obs.observe(REQUEST, self.root, self.root)
        self.assertEqual([item["id"] for item in result["checks"]], list(obs.CHECK_IDS))
        self.assertTrue(all(item["state"] == "failed" for item in result["checks"]))
        self.assertNotIn("secretcredential", json.dumps(result))

    def test_actual_launcher_preserves_structured_failed_checks(self):
        code_root = Path(__file__).resolve().parents[2]
        self.config["hub_base_url"] = "http://secretcredential@host/"
        self.write_config()
        context = {"contract_version": 1, "project_id": "ominull", "project_root": str(self.root),
                   "cwd": str(code_root), "api_base": "http://server.example.invalid",
                   "agent_hub_url": "http://server.example.invalid",
                   "output": {"human": False, "compact": False, "progress_only": False}}
        env = {**os.environ, "ST_EXTENSION_CONTEXT": json.dumps(context)}
        process = subprocess.run([str(code_root / "scripts/st-ominull")], cwd=code_root,
            env=env, input=json.dumps(REQUEST), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["challenge"], REQUEST["challenge"])
        self.assertEqual([item["state"] for item in result["checks"]], ["failed"] * 3)
        self.assertNotIn("secretcredential", process.stdout + process.stderr)
        repeated = subprocess.run([str(code_root / "scripts/st-ominull"), "--request", json.dumps(REQUEST),
            "--request", json.dumps(REQUEST)], cwd=code_root, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
        self.assertEqual(repeated.returncode, 2)
        self.assertEqual(json.loads(repeated.stdout)["error"], "multiple_requests")


class SourceTests(Fixture):
    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.root), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()

    def prepare_git(self):
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "runtime.txt").write_text("runtime-v1")
        (self.root / "README.md").write_text("documentation")
        (self.root / "docs").mkdir()
        (self.root / "docs/note.md").write_text("note")
        (self.root / "scripts/st_extension/.gitignore").write_text("/production.local.json\n")
        for path in ("scripts/st_extension/observer.py", "scripts/st-ominull"):
            (self.root / path).write_text("fixture-code")
        (self.root / "scripts/st-ominull").chmod(0o755)
        (self.root / obs.POLICY_PATH).write_text(json.dumps(obs.POLICY))
        self.git("add", "runtime.txt", "README.md", "docs", "scripts")
        self.git("commit", "-qm", "fixture original")
        return self.git("rev-parse", "HEAD")

    def commit(self):
        self.git("add", "-u")
        self.git("commit", "-qm", "fixture revision")
        return self.git("rev-parse", "HEAD")

    def test_accepted_code_bytes_are_pinned(self):
        self.prepare_git()
        (self.root / "README.md").write_text("updated docs")
        (self.root / "scripts/st_extension/observer.py").write_text("reviewed observer")
        accepted = self.commit()
        obs.pin_code(self.root, self.root, accepted)
        (self.root / "scripts/st_extension/observer.py").write_text("not accepted")
        with self.assertRaisesRegex(obs.ObservationError, "observer_code_mismatch"):
            obs.pin_code(self.root, self.root, accepted)

    def test_changed_policy_or_launcher_mode_cannot_be_pinned(self):
        self.prepare_git()
        (self.root / obs.POLICY_PATH).write_text(json.dumps({**obs.POLICY, "prefixes": ["hub/"]}))
        changed = self.commit()
        with self.assertRaisesRegex(obs.ObservationError, "runtime_policy_mismatch"):
            obs.pin_code(self.root, self.root, changed)

    def test_accepted_launcher_mode_is_enforced(self):
        self.prepare_git()
        (self.root / "scripts/st-ominull").chmod(0o644)
        changed = self.commit()
        with self.assertRaisesRegex(obs.ObservationError, "observer_not_executable"):
            obs.pin_code(self.root, self.root, changed)


class PackageTests(Fixture):
    def prepare_package(self):
        directory = self.root / "package-root"
        (directory / "DEBIAN").mkdir(parents=True)
        (directory / "DEBIAN/control").write_text(
            "Package: ominull-hub\nVersion: 1.8.43\nArchitecture: amd64\n"
            "Maintainer: Fixture <fixture@example.invalid>\nDescription: isolated observer fixture\n")
        (directory / "opt/ominull/bin").mkdir(parents=True)
        for name in obs.BINARIES.values():
            (directory / "opt/ominull/bin" / name).write_bytes(b"isolated fixture binary")
            (self.root / "build" / name).write_bytes(b"isolated fixture binary")
        package = self.root / self.config["hub_package"]
        obs.run(["dpkg-deb", "--build", str(directory), str(package)])
        private = self.root / "signing.key"
        public = self.root / "public.pem"
        obs.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(private)])
        obs.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)])
        obs.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(package) + ".sig", str(package)])
        digest = obs.sha256_file(package)
        Path(str(package) + ".sha256").write_text(digest + "\n")
        (self.root / "dist/SHA256SUMS.txt").write_text(digest + "  " + package.name + "\n")
        return public.read_bytes()

    def test_signed_package_local_binaries_and_tamper_failures(self):
        public = self.prepare_package()
        real_run = obs.run

        # Fixture binaries are not Go executables; build info is mocked, so the
        # `go version -m` probe must be too while openssl and dpkg-deb stay real.
        def run_without_go_probe(argv, **kwargs):
            return b"" if argv[:3] == ["go", "version", "-m"] else real_run(argv, **kwargs)

        with patch.object(obs, "pinned_public_key", return_value=public), patch.object(
            obs, "parse_buildinfo", return_value={"source_commit": COMMIT, "vcs_modified": False}), patch.object(
            obs, "run", side_effect=run_without_go_probe):
            evidence = obs.package_evidence(self.root, self.config, COMMIT, self.root)
            self.assertTrue(evidence["package"]["signature_verified"])
            self.assertEqual(set(evidence["binaries"]), {"hub", "authority"})
            authority = self.root / self.config["local_authority_binary"]
            authority.write_bytes(b"tampered authority")
            with self.assertRaisesRegex(obs.ObservationError, "local_package_binary_mismatch"):
                obs.package_evidence(self.root, self.config, COMMIT, self.root)
            authority.write_bytes(b"isolated fixture binary")
            signature = Path(str(self.root / self.config["hub_package"]) + ".sig")
            signature.write_bytes(b"invalid signature")
            with self.assertRaisesRegex(obs.ObservationError, "command_failed"):
                obs.package_evidence(self.root, self.config, COMMIT, self.root)

    def test_digest_metadata_and_missing_artifact_failures(self):
        self.prepare_package()
        digest_file = Path(str(self.root / self.config["hub_package"]) + ".sha256")
        digest_file.write_text("0" * 64)
        with self.assertRaisesRegex(obs.ObservationError, "package_digest_mismatch"):
            obs.package_evidence(self.root, self.config, COMMIT, self.root)
        digest_file.unlink()
        with self.assertRaisesRegex(obs.ObservationError, "missing_file"):
            obs.package_evidence(self.root, self.config, COMMIT, self.root)


class RemoteAndRouteTests(Fixture):
    def test_fixed_ssh_command_cannot_select_host_container_or_mutate(self):
        with patch.object(obs, "run", return_value=b"data") as run:
            obs.ssh(self.config, "sha256sum -- /opt/ominull/bin/ominull-hub")
        argv = run.call_args.args[0]
        self.assertEqual(argv[-2], "fixture-alias")
        self.assertEqual(argv[-1], "pct exec 100 -- sha256sum -- /opt/ominull/bin/ominull-hub")
        self.assertIn("ConnectTimeout=5", argv)

    def test_http_routes_require_current_asset_and_anonymous_denial(self):
        script = b"fixture javascript"
        anonymous_status = 401
        def responses(config, path, key=None, **kwargs):
            content_type = "application/json"
            body = b"{}"
            status = 200
            if path == "/":
                content_type, body = "text/html", b'<script src="app.js?v=1.8.43"></script>'
            elif path.startswith("/app.js"):
                content_type, body = "text/javascript", script
            elif key is None:
                status = anonymous_status
            return {"path": path, "status": status, "content_type": content_type}, body
        with patch.object(obs, "http_read", side_effect=responses), patch.object(obs, "git", return_value=script):
            evidence = obs.routes_evidence(self.root, self.config, "1.8.43", COMMIT)
            self.assertEqual(evidence["routes"][-1]["status"], 401)
            self.assertNotIn("fixture-only-credential", json.dumps(evidence))
            with patch.object(obs, "git", return_value=b"changed source javascript"):
                with self.assertRaisesRegex(obs.ObservationError, "current_asset_mismatch"):
                    obs.routes_evidence(self.root, self.config, "1.8.43", COMMIT)
            anonymous_status = 200
            with self.assertRaisesRegex(obs.ObservationError, "anonymous_route_not_denied"):
                obs.routes_evidence(self.root, self.config, "1.8.43", COMMIT)

    def test_runtime_observation_retains_original_commit_and_detects_restart(self):
        original = "b" * 40
        evidence = {"package": {"version": "1.8.43"}, "binaries": {
            "hub": {"running_source_commit": original}}}
        initial = {"hub": {"pid": 123}, "authority": {"pid": 456}}
        with patch.object(obs, "pin_code", return_value={"policy_blob": COMMIT}), patch.object(
                obs, "package_evidence", return_value=evidence), patch.object(
                obs, "running_evidence", return_value=evidence), patch.object(
                obs, "health_evidence", return_value={"services": initial}), patch.object(
                obs, "routes_evidence", return_value={"routes": []}):
            with patch.object(obs, "services", return_value=initial):
                result = obs.observe(REQUEST, self.root, self.root)
            self.assertEqual(result["deployed_source_commit"], original)
            self.assertEqual(result["accepted_source_commit"], COMMIT)
            self.assertEqual([item["state"] for item in result["checks"]], ["success"] * 3)
            with patch.object(obs, "services", side_effect=[initial, {"hub": {"pid": 789}}]):
                changed = obs.observe(REQUEST, self.root, self.root)
            self.assertEqual(changed["checks"][-1]["state"], "failed")
            self.assertEqual(changed["checks"][-1]["evidence"]["error"], "process_changed_during_observation")


if __name__ == "__main__":
    unittest.main()
