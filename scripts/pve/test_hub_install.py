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
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
_loader = importlib.machinery.SourceFileLoader("ominull_hub_install", str(HERE / "ominull-hub-install"))
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
assert _spec is not None
hi = importlib.util.module_from_spec(_spec)
_loader.exec_module(hi)

# pct inside the fixture: state.json holds the installed version and its dpkg status; dpkg -i reads
# the pushed package. dpkg_fails names the status a failed dpkg -i leaves behind (once); dpkg_leaves
# the status a dpkg -i that exits 0 leaves.
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
    if "query_fails" in state:
        sys.exit(state["query_fails"])
    if state.get("installed") is None:
        print("dpkg-query: no packages found matching ominull-hub", file=sys.stderr)
        sys.exit(1)
    print(state.get("status", "install ok installed") + " " + state["installed"], end="")
elif argv[:2] == ["dpkg", "-i"]:
    version = subprocess.run(["dpkg-deb", "--field", str(state_dir / "pushed.deb"), "Version"],
                             capture_output=True, text=True, check=True).stdout.strip()
    failure = state.pop("dpkg_fails", None)
    if failure is True:
        sys.exit(1)
    state["installed"] = version
    state["status"] = failure or state.pop("dpkg_leaves", "install ok installed")
    (state_dir / "state.json").write_text(json.dumps(state))
    sys.exit(1 if failure else 0)
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


    def test_failed_postinst_leaves_a_floor_a_signed_fix_forward_can_clear(self):
        self.set_state(installed="1.8.67", dpkg_fails="install ok half-configured")
        broken = self.deb("1.8.68")
        with self.assertRaisesRegex(hi.Refused, "dpkg -i failed"):
            self.install("1.8.68", self.signed(broken, "1.8.68"))
        # The key still reports, so deploy-hub.sh --check and the release preflight pass.
        self.assertEqual(hi.run(["version"], io.BytesIO())["state"], "half-configured")
        self.assertEqual(hi.run(["version"], io.BytesIO())["installed"], "1.8.68")
        (self.state / "calls.log").unlink()
        old = self.deb("1.8.67")
        self.assert_refused("older than the installed hub 1.8.68", "1.8.67", self.signed(old, "1.8.67"))
        # A signed reinstall of the same version (a fix built as 1.8.69 would pass the same floor).
        self.assertEqual(self.install("1.8.68", self.signed(broken, "1.8.68"))["previous"], "1.8.68")
        self.assertEqual(hi.run(["version"], io.BytesIO())["state"], "installed")

    def test_reinstreq_package_takes_a_newer_fix_and_odd_states_fail_closed(self):
        self.set_state(installed="1.8.68", status="install reinstreq half-installed")
        deb = self.deb("1.8.69")
        self.assertEqual(self.install("1.8.69", self.signed(deb, "1.8.69"))["installed"], "1.8.69")
        self.set_state(installed="1.8.67", status="deinstall ok config-files")
        self.assertIsNone(hi.run(["version"], io.BytesIO())["installed"])
        for status in ("install ok weird", "install bad installed", "install ok installed 1.8.67 extra"):
            self.set_state(installed="1.8.67", status=status)
            with self.subTest(status=status), self.assertRaisesRegex(hi.Refused, "installed hub state"):
                hi.run(["version"], io.BytesIO())

    def test_a_failed_state_query_keeps_the_floor(self):
        # pct exec 255 (CT locked or down) or dpkg-query 2 (database error) is not "no hub":
        # an older signed package must not install through it.
        old = self.deb("1.8.60")
        files = self.signed(old, "1.8.60")
        for code in (255, 2, 1):
            self.set_state(installed="1.8.67", query_fails=code)
            with self.subTest(code=code):
                with self.assertRaisesRegex(hi.Refused, "installed hub state"):
                    hi.run(["version"], io.BytesIO())
                self.assert_refused("installed hub state", "1.8.60", files)
                self.assertFalse(any(call[0] == "push" for call in self.calls()))
        # dpkg-query's own "no packages found" answer is a CT without a hub: a first install proceeds.
        self.set_state(installed=None)
        self.assertEqual(hi.run(["version"], io.BytesIO())["state"], "not-installed")
        self.assertEqual(self.install("1.8.60", files)["previous"], None)

    def test_a_dpkg_that_leaves_the_package_unconfigured_is_not_an_install(self):
        self.set_state(installed="1.8.67", dpkg_leaves="install ok unpacked")
        deb = self.deb("1.8.68")
        with self.assertRaisesRegex(hi.Refused, "installed version"):
            self.install("1.8.68", self.signed(deb, "1.8.68"))

    def huge_header(self, kind):
        """A tar whose first header is a pax (x) or GNU long-name (L) record claiming 400 MiB."""
        info = tarfile.TarInfo("././@LongLink" if kind == tarfile.GNUTYPE_LONGNAME else "pax")
        info.type, info.size = kind, 400 * 1024 * 1024
        return info.tobuf(format=tarfile.GNU_FORMAT if kind == tarfile.GNUTYPE_LONGNAME else tarfile.USTAR_FORMAT)

    def test_oversized_pax_or_long_name_header_is_refused_before_it_is_buffered(self):
        for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            stream = Endless(self.huge_header(kind))
            with self.subTest(kind=kind), self.assertRaisesRegex(hi.Refused, "larger than allowed"):
                hi.run(["install", "1.8.68"], stream)
            self.assertLess(stream.sent, 2 * hi.HEADER_SLACK)
            self.assertEqual(list(self.work.glob("install-*")), [])
            self.assertEqual(self.calls(), [])

    def test_a_stalled_sender_is_dropped_and_frees_the_lock(self):
        deb = self.deb("1.8.68")
        files = self.signed(deb, "1.8.68")
        with patch.object(hi, "RECEIVE_SECONDS", 1):
            started = time.monotonic()
            with self.assertRaisesRegex(hi.Refused, "not received within 1 s"):
                hi.run(["install", "1.8.68"], Stalled(self.stream(files).getvalue()[:700]))
            self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(list(self.work.glob("install-*")), [])
        self.assertEqual(self.install("1.8.68", files)["installed"], "1.8.68")


class Endless:
    """prefix, then zeros forever; counts what the reader took."""

    def __init__(self, prefix):
        self.prefix, self.sent = prefix, 0

    def read(self, size=-1):
        assert size is not None and size >= 0, "unbounded read"
        start = self.sent
        self.sent += size
        head = self.prefix[start:start + size]
        return head + b"\0" * (size - len(head))


class Stalled:
    """prefix, then a sender that never sends again."""

    def __init__(self, prefix):
        self.prefix = prefix

    def read(self, size=-1):
        if self.prefix:
            head, self.prefix = self.prefix[:size], self.prefix[size:]
            return head
        time.sleep(60)
        return b""


if __name__ == "__main__":
    unittest.main()
