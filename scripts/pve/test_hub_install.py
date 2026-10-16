"""The hub-install forced command against signed fixture packages and a fake pct; no Proxmox I/O."""
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
_loader = importlib.machinery.SourceFileLoader("ominull_hub_install", str(HERE / "ominull-hub-install"))
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
assert _spec is not None
hi = importlib.util.module_from_spec(_spec)
_loader.exec_module(hi)

# pct inside the fixture: state.json holds the installed version; dpkg -i reads the pushed package.
FAKE_PCT = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path
state_dir = Path(os.environ["FAKE_PCT_STATE"])
state = json.loads((state_dir / "state.json").read_text())
with (state_dir / "calls.log").open("a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[:2] == ["push", "150"]:
    Path(state_dir / "pushed.deb").write_bytes(Path(args[2]).read_bytes())
    sys.exit(0)
assert args[:3] == ["exec", "150", "--"], args
argv = args[3:]
if argv[0] == "dpkg-query":
    if state.get("installed") is None:
        sys.exit(1)
    print("install ok installed " + state["installed"], end="")
elif argv[:2] == ["dpkg", "-i"]:
    if state.get("dpkg_fails"):
        sys.exit(1)
    version = subprocess.run(["dpkg-deb", "--field", str(state_dir / "pushed.deb"), "Version"],
                             capture_output=True, text=True, check=True).stdout.strip()
    state["installed"] = version
    (state_dir / "state.json").write_text(json.dumps(state))
elif argv[0] == "ss":
    print("LISTEN 0 4096 *:9443 *:*")
elif argv[0] in {"rm", "systemctl"}:
    pass
else:
    sys.exit(2)
'''


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


class HubInstallTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.etc = self.dir / "etc"
        self.etc.mkdir(mode=0o755)
        self.work = self.dir / "work"
        self.work.mkdir(mode=0o700)
        self.state = self.dir / "pct"
        self.state.mkdir()
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        (bin_dir / "pct").write_text(FAKE_PCT)
        (bin_dir / "pct").chmod(0o755)
        self.set_state(installed="1.8.67")
        self.keys = {}
        for name in ("release", "next", "attacker"):
            key = self.dir / (name + ".key")
            key.write_bytes(openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout"))
            self.keys[name] = (key, openssl("ec", "-in", str(key), "-pubout"))
        self.pin = self.etc / "release-public.pem"
        self.pin.write_bytes(self.keys["release"][1])
        self.pin.chmod(0o644)
        for target, value in (("PIN", self.pin), ("WORK", self.work), ("OWNER", os.getuid()), ("READY_SECONDS", 2)):
            patcher = patch.object(hi, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        env = patch.dict(os.environ, {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                                      "FAKE_PCT_STATE": str(self.state)})
        env.start()
        self.addCleanup(env.stop)

    def set_state(self, **state):
        (self.state / "state.json").write_text(json.dumps(state))

    def installed(self):
        return json.loads((self.state / "state.json").read_text()).get("installed")

    def calls(self):
        log = self.state / "calls.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def deb(self, version, package="ominull-hub", pins=None):
        root = self.dir / ("root-" + package + version)
        (root / "DEBIAN").mkdir(parents=True)
        (root / "DEBIAN/control").write_text(
            "Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: fixture\nDescription: fixture\n" % (package, version))
        (root / "opt/ominull/bin").mkdir(parents=True)
        (root / "opt/ominull/bin/ominull-hub").write_bytes(b"fixture hub " + version.encode())
        if pins is not None:
            (root / "usr/share/ominull").mkdir(parents=True)
            (root / "usr/share/ominull/release-public.pem").write_bytes(self.keys[pins][1])
        out = self.dir / ("ominull-hub_%s_amd64.deb" % version)
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(out)], capture_output=True, check=True)
        return out

    def signed(self, deb, version, key="release", statement_version=None, name=None):
        name = name or deb.name
        sha = __import__("hashlib").sha256(deb.read_bytes()).hexdigest()
        statement = "OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n" % (name, statement_version or version, sha)
        key_file = self.keys[key][0]
        sig = openssl("dgst", "-sha256", "-sign", str(key_file), str(deb))
        release_sig = openssl("dgst", "-sha256", "-sign", str(key_file), data=statement.encode())
        return {name: deb.read_bytes(), name + ".sig": sig, name + ".release.sig": release_sig}

    def stream(self, files, extra=None):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in {**files, **(extra or {})}.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        buffer.seek(0)
        return buffer

    def install(self, version, files, **extra):
        return hi.run(["install", version], self.stream(files, **extra))

    def test_signed_newer_package_installs_and_waits_for_the_hub(self):
        deb = self.deb("1.8.68", pins="release")
        result = self.install("1.8.68", self.signed(deb, "1.8.68"))
        self.assertEqual(result["installed"], "1.8.68")
        self.assertEqual(result["previous"], "1.8.67")
        self.assertFalse(result["pin_rotated"])
        self.assertEqual(self.installed(), "1.8.68")
        calls = self.calls()
        self.assertIn(["push", "150", calls[1][2], hi.GUEST_DEB, "--perms", "0600"], calls)
        self.assertIn(["exec", "150", "--", "dpkg", "-i", hi.GUEST_DEB], calls)
        self.assertIn(["exec", "150", "--", "rm", "-f", "--", hi.GUEST_DEB], calls)
        self.assertEqual(list(self.work.glob("install-*")), [])
        self.assertEqual(hi.run(["version"], io.BytesIO())["installed"], "1.8.68")

    def test_rotation_release_signed_by_the_outgoing_key_moves_the_pin(self):
        deb = self.deb("1.8.68", pins="next")
        result = self.install("1.8.68", self.signed(deb, "1.8.68", key="release"))
        self.assertTrue(result["pin_rotated"])
        self.assertEqual(self.pin.read_bytes(), self.keys["next"][1])
        # The outgoing key no longer installs anything; the new one does.
        old = self.deb("1.8.69", pins="next")
        with self.assertRaisesRegex(hi.Refused, "signature"):
            self.install("1.8.69", self.signed(old, "1.8.69", key="release"))
        self.assertEqual(self.install("1.8.69", self.signed(old, "1.8.69", key="next"))["installed"], "1.8.69")

    def assert_refused(self, why, version, files, **extra):
        before = self.installed()
        with self.assertRaisesRegex(hi.Refused, why):
            self.install(version, files, **extra)
        self.assertEqual(self.installed(), before)
        self.assertNotIn("dpkg", json.dumps(self.calls()).replace("dpkg-query", ""))
        self.assertEqual(list(self.work.glob("install-*")), [])

    def test_unsigned_wrong_key_and_tampered_packages_are_refused(self):
        deb = self.deb("1.8.68")
        files = self.signed(deb, "1.8.68", key="attacker")
        self.assert_refused("signature", "1.8.68", files)
        files = self.signed(deb, "1.8.68")
        tampered = dict(files)
        tampered[deb.name] = files[deb.name] + b"\0"
        self.assert_refused("signature", "1.8.68", tampered)
        swapped = dict(files)
        swapped[deb.name + ".release.sig"] = files[deb.name + ".sig"]
        self.assert_refused("signature", "1.8.68", swapped)
        missing = {k: v for k, v in files.items() if not k.endswith(".release.sig")}
        self.assert_refused("missing", "1.8.68", missing)

    def test_replayed_older_or_mislabelled_packages_are_refused(self):
        # A genuinely signed older release replayed to remove a newer floor.
        old = self.deb("1.8.60")
        self.assert_refused("older than the installed hub", "1.8.60", self.signed(old, "1.8.60"))
        # A signed agent package, or a statement for another version.
        agent = self.deb("1.8.68", package="ominull-agent")
        self.assert_refused("package identity", "1.8.68", self.signed(agent, "1.8.68"))
        deb = self.deb("1.8.68")
        self.assert_refused("signature", "1.8.68", self.signed(deb, "1.8.68", statement_version="1.8.99"))
        self.assert_refused("unexpected member", "1.8.69", self.signed(deb, "1.8.68"))

    def test_stream_admits_only_the_three_regular_files(self):
        deb = self.deb("1.8.68")
        files = self.signed(deb, "1.8.68")
        self.assert_refused("unexpected member", "1.8.68", files, extra={"../../etc/shadow": b"x"})
        self.assert_refused("unexpected member", "1.8.68", files, extra={"postinst": b"x"})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            link = tarfile.TarInfo(deb.name)
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/shadow"
            archive.addfile(link)
        buffer.seek(0)
        with self.assertRaisesRegex(hi.Refused, "member type"):
            hi.run(["install", "1.8.68"], buffer)

    def test_words_versions_and_pin_ownership_fail_closed(self):
        for words in (["install"], ["install", "1.8.68", "x"], ["install", "1.8.68;id"], ["install", "../1.8.68"],
                      ["install", "01.8.68"], ["dpkg", "-i", "x"], ["id"], []):
            with self.subTest(words=words), self.assertRaises(hi.Refused):
                hi.run(words, io.BytesIO())
        self.pin.chmod(0o666)
        with self.assertRaisesRegex(hi.Refused, "ownership"):
            hi.run(["version"], io.BytesIO())
        self.pin.chmod(0o644)
        self.pin.write_bytes(self.keys["release"][1] + self.keys["next"][1])
        with self.assertRaisesRegex(hi.Refused, "one public key"):
            hi.run(["version"], io.BytesIO())

    def test_forced_command_reads_ssh_original_command(self):
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "install 1.8.68 && id"}), \
                patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO())), patch("builtins.print") as printed:
            self.assertEqual(hi.main(), 1)
        self.assertIn("refused", printed.call_args.args[0])
        self.assertEqual(self.calls(), [])

    def test_failed_dpkg_keeps_the_pin(self):
        self.set_state(installed="1.8.67", dpkg_fails=True)
        deb = self.deb("1.8.68", pins="next")
        with self.assertRaisesRegex(hi.Refused, "dpkg -i failed"):
            self.install("1.8.68", self.signed(deb, "1.8.68"))
        self.assertEqual(self.pin.read_bytes(), self.keys["release"][1])
        self.assertIn(["exec", "150", "--", "rm", "-f", "--", hi.GUEST_DEB], self.calls())


if __name__ == "__main__":
    unittest.main()
