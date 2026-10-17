"""scripts/pve/install.sh end to end against a sandboxed stand-in for the Proxmox host; no Proxmox I/O.

The "PVE host" is a bubblewrap sandbox (user namespace, uid 0 inside) whose /usr/local/sbin, /etc, /var/lib and
/root are fixture directories. A stand-in ssh runs the owner alias's session in it, and for a key given with -i runs
only the command= of that key's authorized_keys line, as sshd does for a forced command.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FILES = ["scripts/pve/install.sh", "scripts/pve/ominull-hub-install", "scripts/st_extension/pve_backup_dispatch.py",
         "scripts/st_extension/pve_observe_dispatch.py", "agent/include/release_key.h"]

FAKE_SSH = r'''#!/usr/bin/env python3
import os, re, subprocess, sys
from pathlib import Path
pve = Path(os.environ["FAKE_PVE"])
args = sys.argv[1:]
if "-G" in args:
    print("hostname 192.0.2.39")
    sys.exit(0)
def sandbox(argv, env=None):
    real_etc = ["passwd", "group", "ssl", "alternatives", "ld.so.cache"]
    cmd = ["bwrap", "--unshare-user", "--uid", "0", "--gid", "0", "--bind", "/", "/", "--dev", "/dev",
           "--tmpfs", "/etc"]
    for name in real_etc:
        if os.path.exists("/etc/" + name):
            cmd += ["--ro-bind", "/etc/" + name, "/etc/" + name]
    for target, source in (("/etc/ominull-hub-install", "etc-hub"), ("/etc/ominull-backup", "etc-backup"),
                           ("/usr/local/sbin", "sbin"), ("/var/lib", "varlib"), ("/root", "root"), ("/usr/local/bin", "bin")):
        cmd += ["--bind", str(pve / source), target]
    cmd += ["--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/root"]
    for key, value in (env or {}).items():
        cmd += ["--setenv", key, value]
    return subprocess.run(cmd + argv).returncode
if "-i" in args:
    key = args[args.index("-i") + 1]
    target = next(i for i, a in enumerate(args) if a.startswith("root@"))
    original = " ".join(args[target + 1:])
    blob = subprocess.run(["ssh-keygen", "-y", "-f", key], capture_output=True, text=True, check=True).stdout.split()[1]
    for line in (pve / "root/.ssh/authorized_keys").read_text().splitlines():
        match = re.fullmatch(r'restrict,from="[0-9.]+",command="([^"]+)" ssh-ed25519 (\S+) \S+', line)
        if match and match.group(2) == blob:
            sys.exit(sandbox([match.group(1)], {"SSH_ORIGINAL_COMMAND": original}))
    sys.exit(255)
alias = args[0]
assert alias == "proxmox-gem" and args[1:3] == ["bash", "-s"], args
# Like sshd: the remote arguments arrive joined with spaces and the login shell re-splits them.
sys.exit(sandbox(["bash", "-c", " ".join(args[1:])]))
'''

FAKE_PVE_BIN = {
    "hostname": "#!/bin/sh\necho davion-gem\n",
    "pvesh": "#!/bin/sh\necho '{\"status\": \"running\"}'\n",
    "pct": "#!/bin/sh\n[ \"$1 $2 $3 $4\" = 'exec 150 -- dpkg-query' ] || exit 2\nprintf 'install ok installed 1.8.67'\n",
}


@unittest.skipUnless(shutil.which("bwrap") and shutil.which("ssh-keygen"), "needs bubblewrap and ssh-keygen")
class InstallTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.repo = self.dir / "repo"
        for name in FILES:
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, self.repo / name)
        git = ["git", "-C", str(self.repo), "-c", "user.name=fixture", "-c", "user.email=fixture@invalid"]
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "fixture"], check=True)
        self.pve = self.dir / "pve"
        for name in ("etc-hub", "etc-backup", "sbin", "varlib/vz/dump", "root/.ssh", "bin"):
            (self.pve / name).mkdir(parents=True)
        self.keys = self.pve / "root/.ssh/authorized_keys"
        self.keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerOwnerOwnerOwnerOwnerOwnerOwnerOwnerOwn owner\n")
        for name, body in FAKE_PVE_BIN.items():
            (self.pve / "bin" / name).write_text(body)
            (self.pve / "bin" / name).chmod(0o755)
        tools = self.dir / "tools"
        tools.mkdir()
        (tools / "ssh").write_text(FAKE_SSH)
        (tools / "ssh").chmod(0o755)
        self.env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"], "FAKE_PVE": str(self.pve),
                    "OMINULL_PVE_KEY_DIR": str(self.dir / "keys"), "HOME": str(self.dir)}
        (self.dir / ".ssh").mkdir()

    def install(self, *args):
        return subprocess.run(["bash", str(self.repo / "scripts/pve/install.sh"), *args], env=self.env,
                              capture_output=True, text=True, timeout=120)

    def test_installs_three_forced_keys_and_each_refuses_a_shell(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("backup key answers: guest", result.stdout)
        self.assertIn("observe key answers: package", result.stdout)
        self.assertIn("hub-install key answers: version", result.stdout)
        self.assertIn("every key refuses other commands", result.stdout)
        self.assertIn("no backup recipient yet", result.stdout)
        lines = self.keys.read_text().splitlines()
        self.assertEqual(lines[0].split()[-1], "owner")
        self.assertEqual([line.split()[-1] for line in lines[1:]], ["ominull-backup", "ominull-observe", "ominull-hub-install"])
        for line, command in zip(lines[1:], ("ominull-backup-dispatch", "ominull-observe-dispatch", "ominull-hub-install")):
            self.assertTrue(line.startswith('restrict,from="192.168.86.128",command="/usr/local/sbin/' + command + '" ssh-ed25519 '))
        for name in ("ominull-backup-dispatch", "ominull-observe-dispatch", "ominull-hub-install"):
            self.assertTrue(os.access(self.pve / "sbin" / name, os.X_OK))
        for role in ("backup", "observe", "hub-install"):
            key = self.dir / "keys" / (role + ".ed25519")
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.dir / "keys").stat().st_mode & 0o777, 0o700)

    def test_rerun_keeps_keys_and_pin_and_repin_only_on_request(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.keys.read_text()
        pin = self.pve / "etc-hub/release-public.pem"
        # Stands in for the pin a rotation release moved.
        private = subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout"],
                                 capture_output=True, check=True).stdout
        pin.write_bytes(subprocess.run(["openssl", "ec", "-pubout"], input=private, capture_output=True, check=True).stdout)
        moved = pin.read_text()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release pin kept", result.stdout)
        self.assertEqual(self.keys.read_text(), before)
        self.assertEqual(pin.read_text(), moved)
        result = self.install("--repin-release-key")
        self.assertIn("release pin written", result.stdout)
        self.assertNotEqual(pin.read_text(), moved)
        original = pin.read_bytes()
        # A rotation commit pins a new key; --release-key-ref keeps the outgoing one that signs the rotation release.
        header = self.repo / "agent/include/release_key.h"
        header.write_text(header.read_text().replace(original.decode().splitlines()[1], "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUczKMOE8yfDzAWxOC6WPJiSTz/Oo"))
        git = ["git", "-C", str(self.repo), "-c", "user.name=fixture", "-c", "user.email=fixture@invalid"]
        subprocess.run([*git, "commit", "-q", "-am", "rotation"], check=True)
        result = self.install("--repin-release-key", "--release-key-ref", "HEAD~1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(pin.read_bytes(), original)
        self.assertEqual(self.install("--release-key-ref", "no-such-ref").returncode, 128)

    def test_recipient_is_installed_and_bad_input_installs_nothing(self):
        recipient = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True).stdout
        public = next(line.split(": ")[1] for line in recipient.splitlines() if line.startswith("# public key: "))
        result = self.install("--recipient", public)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.pve / "etc-backup/recipient").read_text().strip(), public)
        for bad in ("age1short", public + ";id", "AGE1" + public[4:]):
            with self.subTest(bad=bad):
                self.assertEqual(self.install("--recipient", bad).returncode, 2)

    def test_uncommitted_dispatcher_is_refused(self):
        with (self.repo / "scripts/pve/ominull-hub-install").open("a") as file:
            file.write("# local edit\n")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("uncommitted changes", result.stderr)
        self.assertEqual(list((self.pve / "sbin").iterdir()), [])

    def test_a_key_file_with_options_never_reaches_authorized_keys(self):
        keys = self.dir / "keys"
        keys.mkdir(mode=0o700)
        (keys / "observe.ed25519").write_text("not a key\n")
        (keys / "observe.ed25519").chmod(0o600)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("ominull-", self.keys.read_text())


if __name__ == "__main__":
    unittest.main()
