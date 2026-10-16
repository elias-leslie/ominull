#!/usr/bin/python3 -I
"""Fixed read-only Proxmox-side verbs for the OmniNull deployment observer (CT 150).

Installed as root on the Proxmox host at /usr/local/sbin/ominull-observe-dispatch
(scripts/pve/install.sh) and reached only through a forced-command key, so the
observer can read these facts about the hub container and nothing else:

    restrict,from="...",command="/usr/local/sbin/ominull-observe-dispatch" ssh-ed25519 ...

The command line arrives in SSH_ORIGINAL_COMMAND as one of:

    service ROLE              systemctl show of the hub or response authority unit
    digest ROLE               sha256sum of /opt/ominull/bin/<binary>
    running-digest ROLE PID   sha256sum of /proc/PID/exe
    running-binary ROLE PID   the first 64 MiB + 1 bytes of /proc/PID/exe
    package                   dpkg-query status and version of ominull-hub

ROLE is hub or authority. PID must be the unit's current MainPID, so the key
cannot read another process's executable. Nothing here writes, restarts or
reads a file other than those. Until the key is installed the observer runs the
same commands (command_for) over its ordinary alias.
"""
import os
import re
import subprocess
import sys

GUEST = "150"
UNITS = {"hub": "ominull-hub", "authority": "ominull-response-authority"}
MAX_BINARY = 64 * 1024 * 1024
SERVICE_PROPERTIES = "ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestampMonotonic"
PID = re.compile(r"[1-9][0-9]{0,9}")


class Refused(Exception):
    """The words name no fixed read; nothing ran."""


def need(condition, why):
    if not condition:
        raise Refused(why)


def command_for(words):
    """The argv run inside the container for these words, plus the PID to confirm."""
    need(isinstance(words, list) and all(isinstance(word, str) for word in words), "usage")
    if words == ["package"]:
        return ["dpkg-query", "-W", "-f=${Status} ${Version}", "ominull-hub"], None
    need(len(words) in (2, 3) and words[1] in UNITS, "usage")
    verb, unit = words[0], UNITS[words[1]]
    if len(words) == 2:
        if verb == "service":
            return ["systemctl", "show", unit + ".service", "--property=" + SERVICE_PROPERTIES], None
        need(verb == "digest", "unknown verb")
        return ["sha256sum", "--", "/opt/ominull/bin/" + unit], None
    need(PID.fullmatch(words[2]) is not None, "pid")
    exe = "/proc/" + words[2] + "/exe"
    if verb == "running-digest":
        return ["sha256sum", "--", exe], (unit, words[2])
    need(verb == "running-binary", "unknown verb")
    return ["head", "-c", str(MAX_BINARY + 1), "--", exe], (unit, words[2])


def in_guest(argv, **kwargs):
    return subprocess.run(["pct", "exec", GUEST, "--", *argv], stdin=subprocess.DEVNULL, check=False, **kwargs)


def main_pid(unit):
    result = in_guest(["systemctl", "show", unit + ".service", "--property=MainPID"],
                      capture_output=True, text=True, timeout=30)
    need(result.returncode == 0, "unit state")
    match = re.fullmatch(r"MainPID=([0-9]+)\n?", result.stdout)
    if match is None:
        raise Refused("unit state")
    return match.group(1)


def run(words, out):
    argv, confirm = command_for(words)
    if confirm is not None:
        unit, pid = confirm
        need(main_pid(unit) == pid, "pid is not the unit's main process")
    out.flush()
    result = in_guest(argv, stdout=out, stderr=subprocess.DEVNULL, timeout=60)
    return result.returncode


def main():
    original = os.environ.get("SSH_ORIGINAL_COMMAND")
    words = original.split(" ") if original is not None else sys.argv[1:]
    try:
        return run(words, sys.stdout.buffer)
    except (Refused, OSError, subprocess.SubprocessError) as exc:
        print("refused: " + (str(exc) if isinstance(exc, Refused) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
