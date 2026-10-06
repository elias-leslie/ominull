"""Fixed-target, read-only production observation; no private ST imports.

Only the dispatcher-issued binding fields are accepted. Infrastructure and
credential locations come from the owner-only file at the registered root.
Subprocess output and HTTP bodies never enter errors or returned evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
from typing import TypedDict


POLICY_PATH = "scripts/st_extension/runtime-inputs.json"


class RuntimePolicy(TypedDict):
    rule_version: int
    prefixes: list[str]
    paths: list[str]


POLICY: RuntimePolicy = {"rule_version": 1, "prefixes": ["docs/", "dist/", "scripts/st_extension/"],
          "paths": ["README.md", "scripts/st-ominull"]}
REQUEST_KEYS = {"contract_version", "operation", "challenge", "task_id", "project",
                "accepted_source_commit", "acceptance_id"}
CONFIG_KEYS = {"schema_version", "target_id", "ssh_alias", "lxc_id", "hub_base_url",
               "admin_key_file", "hub_package", "local_binary", "local_authority_binary"}
CHECK_IDS = ("production_binary", "production_health", "production_routes")
BINARIES = {"hub": "ominull-hub", "authority": "ominull-response-authority"}
SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
MAX_OUTPUT = 2 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024
COMMAND_TIMEOUT = 60
HTTP_TIMEOUT = 10


class ObservationError(Exception):
    """Only fixed, credential-free codes are safe to return to the dispatcher."""


def require(condition, code):
    if not condition:
        raise ObservationError(code)


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ObservationError("invalid_json") from exc


def parse_request(raw):
    require(len(raw.encode()) <= 16384, "request_too_large")
    request = parse_json(raw)
    require(isinstance(request, dict) and set(request) == REQUEST_KEYS, "request_fields")
    require(type(request["contract_version"]) is int and request["contract_version"] == 1,
            "request_version")
    require(request["operation"] == "observe_deployment" and request["project"] == "ominull",
            "request_operation_or_project")
    require(isinstance(request["challenge"], str) and
            re.fullmatch(r"[0-9a-f]{32}", request["challenge"]), "request_challenge")
    require(isinstance(request["accepted_source_commit"], str) and
            SHA.fullmatch(request["accepted_source_commit"]), "request_commit")
    for field in ("task_id", "acceptance_id"):
        require(isinstance(request[field], str) and IDENTIFIER.fullmatch(request[field]),
                "request_binding")
    return request


def context_root(raw, code_root):
    context = parse_json(raw)
    require(isinstance(context, dict) and set(context) == {
        "contract_version", "project_id", "project_root", "cwd", "api_base",
        "agent_hub_url", "output"}, "context_fields")
    require(type(context["contract_version"]) is int and context["contract_version"] == 1
            and context["project_id"] == "ominull", "context_identity")
    require(context["output"] == {"human": False, "compact": False, "progress_only": False}
            and all(type(v) is bool for v in context["output"].values()),
            "context_output")
    require(isinstance(context["project_root"], str) and
            Path(context["project_root"]).is_absolute(), "context_root")
    root = Path(context["project_root"])
    require(root.is_dir() and root.resolve() == root, "context_root")
    require(isinstance(context["cwd"], str) and Path(context["cwd"]).resolve() == code_root
            and Path.cwd().resolve() == code_root, "context_code_root")
    return root


def regular_file(path, private=False):
    # Reject symlinked parent components as well as symlinked files.
    require(path.is_absolute() and path.resolve() == path, "unsafe_file_path")
    try:
        info = path.lstat()
    except OSError as exc:
        raise ObservationError("missing_file") from exc
    require(stat.S_ISREG(info.st_mode), "unsafe_file_type")
    if private:
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                "private_file_permissions")
    return path


def load_config(root, *, require_deployment_inputs=True):
    path = regular_file(root / "scripts/st_extension/production.local.json", private=True)
    with path.open("rb") as file:
        raw = file.read(16385)
    require(len(raw) <= 16384, "config_too_large")
    config = parse_json(raw)
    require(isinstance(config, dict) and set(config) == CONFIG_KEYS, "config_fields")
    require(type(config["schema_version"]) is int and config["schema_version"] == 1,
            "config_version")
    require(type(config["lxc_id"]) is int and config["lxc_id"] > 0, "config_target")
    require(isinstance(config["target_id"], str) and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", config["target_id"]),
            "config_target_id")
    require(isinstance(config["ssh_alias"], str) and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", config["ssh_alias"]),
            "config_ssh_alias")
    require(isinstance(config["hub_base_url"], str), "config_url")
    try:
        url = urlsplit(config["hub_base_url"])
        port = url.port
    except ValueError as exc:
        raise ObservationError("config_url") from exc
    require(url.scheme in {"http", "https"} and url.hostname and not url.username
            and not url.password and url.path in {"", "/"} and not url.query
            and not url.fragment and (port is None or 1 <= port <= 65535)
            and not any(ch.isspace() for ch in config["hub_base_url"]), "config_url")
    require(isinstance(config["admin_key_file"], str), "config_key_path")
    require(Path(config["admin_key_file"]).is_absolute(), "config_key_path")
    if require_deployment_inputs:
        regular_file(Path(config["admin_key_file"]), private=True)
    expected = {"local_binary": "build/ominull-hub",
                "local_authority_binary": "build/ominull-response-authority"}
    for field, value in expected.items():
        require(config[field] == value, "config_binary_path")
        if require_deployment_inputs:
            regular_file(root / value)
    require(isinstance(config["hub_package"], str) and re.fullmatch(
        r"dist/ominull-hub_[0-9]+\.[0-9]+\.[0-9]+_amd64\.deb", config["hub_package"]),
        "config_package_path")
    if require_deployment_inputs:
        regular_file(root / config["hub_package"])
    return config, hashlib.sha256(raw).hexdigest()


def run(argv, *, cwd=None, output_file=None):
    try:
        env = dict(os.environ, GOTOOLCHAIN="local", GOENV="off")
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=output_file if output_file else subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=COMMAND_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObservationError("command_unavailable_or_timeout") from exc
    require(result.returncode == 0, "command_failed")
    if output_file:
        return b""
    require(len(result.stdout) <= MAX_OUTPUT, "command_output_too_large")
    return result.stdout


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(root, *args):
    return run(["git", "--no-replace-objects", "-C", str(root), *args])


def pin_code(root, code_root, commit):
    require(git(root, "rev-parse", commit + "^{commit}").decode().strip() == commit,
            "accepted_commit_missing")
    entries = parse_tree(git(root, "ls-tree", "-r", "-z", commit, "scripts/st_extension",
                             "scripts/st-ominull"))
    require("scripts/st-ominull" in entries and POLICY_PATH in entries
            and "scripts/st_extension/observer.py" in entries, "observer_not_accepted")
    require("scripts/st_extension/production.local.json" not in entries, "private_config_tracked")
    require(entries["scripts/st-ominull"][0] == "100755", "observer_not_executable")
    for path, (mode, kind, blob) in entries.items():
        require(kind == "blob" and mode in {"100644", "100755"}, "observer_code_type")
        local = regular_file(code_root / path)
        require(local.read_bytes() == git(root, "cat-file", "blob", blob), "observer_code_mismatch")
        actual_mode = "100755" if local.stat().st_mode & 0o111 else "100644"
        require(actual_mode == mode, "observer_mode_mismatch")
    policy = parse_json((code_root / POLICY_PATH).read_bytes())
    require(policy == POLICY and type(policy["rule_version"]) is int, "runtime_policy_mismatch")
    return {"executable_blob": entries["scripts/st-ominull"][2],
            "policy_blob": entries[POLICY_PATH][2]}


def parse_tree(raw):
    entries = {}
    try:
        for item in raw.split(b"\0"):
            if not item:
                continue
            identity, path = item.split(b"\t", 1)
            mode, kind, blob = identity.decode("ascii").split(" ")
            name = path.decode("utf-8")
            require(name not in entries and SHA.fullmatch(blob), "git_tree_invalid")
            entries[name] = (mode, kind, blob)
    except (ValueError, UnicodeError) as exc:
        raise ObservationError("git_tree_invalid") from exc
    return entries


def parse_buildinfo(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_OUTPUT, "buildinfo_size")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ObservationError("buildinfo_encoding") from exc
    settings = {}
    for line in lines:
        match = re.fullmatch(r"\s*build\s+(vcs(?:\.revision|\.modified|\.time)?)=(.+)", line)
        if match:
            require(match[1] not in settings, "buildinfo_duplicate")
            settings[match[1]] = match[2]
    require(settings.get("vcs") == "git" and settings.get("vcs.modified") == "false",
            "build_source_not_clean")
    require(SHA.fullmatch(settings.get("vcs.revision", "")), "build_source_missing")
    return {"source_commit": settings["vcs.revision"], "vcs_modified": False}


def pinned_public_key(root, commit):
    header = git(root, "show", commit + ":agent/include/release_key.h").decode()
    start = header.find('"-----BEGIN PUBLIC KEY-----')
    end = header.find('"-----END PUBLIC KEY-----', start)
    require(start >= 0 and end > start, "release_key_missing")
    end = header.find('"', end + 1)
    fragments = re.findall(r'"(?:[^"\\]|\\.)*"', header[start:end + 1])
    try:
        public_key = "".join(json.loads(fragment) for fragment in fragments).encode()
    except ValueError as exc:
        raise ObservationError("release_key_invalid") from exc
    require(public_key.startswith(b"-----BEGIN PUBLIC KEY-----\n") and
            public_key.endswith(b"-----END PUBLIC KEY-----\n"), "release_key_invalid")
    return public_key


def package_evidence(root, config, accepted, directory):
    package = regular_file(root / config["hub_package"])
    digest = sha256_file(package)
    signature = regular_file(Path(str(package) + ".sig"))
    digest_file = regular_file(Path(str(package) + ".sha256"))
    require(digest_file.read_text().strip() == digest, "package_digest_mismatch")
    manifest = regular_file(root / "dist/SHA256SUMS.txt")
    matches = []
    for line in manifest.read_text().splitlines():
        parts = line.split()
        require(len(parts) == 2 and DIGEST.fullmatch(parts[0]), "release_manifest_invalid")
        if parts[1] == package.name:
            matches.append(parts[0])
    require(matches == [digest], "release_manifest_mismatch")
    public_key = pinned_public_key(root, accepted)
    key_file = directory / "release-public.pem"
    key_file.write_bytes(public_key)
    run(["openssl", "dgst", "-sha256", "-verify", str(key_file),
         "-signature", str(signature), str(package)])
    metadata = run(["dpkg-deb", "--field", str(package), "Package", "Version", "Architecture"])
    fields = dict(line.split(": ", 1) for line in metadata.decode().splitlines())
    version = fields.get("Version", "")
    require(fields.get("Package") == "ominull-hub" and fields.get("Architecture") == "amd64"
            and package.name == f"ominull-hub_{version}_amd64.deb", "package_identity_mismatch")
    tar_path = directory / "package.tar"
    with tar_path.open("wb") as output:
        run(["dpkg-deb", "--fsys-tarfile", str(package)], output_file=output)
    binary_evidence = {}
    with tarfile.open(tar_path) as archive:
        for role, name in BINARIES.items():
            members = [m for m in archive.getmembers()
                       if m.name.removeprefix("./") == "opt/ominull/bin/" + name]
            require(len(members) == 1 and members[0].isfile()
                    and 0 < members[0].size <= MAX_BINARY, "package_binary_missing_or_unsafe")
            source = archive.extractfile(members[0])
            if source is None:
                raise ObservationError("package_binary_missing_or_unsafe")
            member_path = directory / ("package-" + name)
            with source, member_path.open("wb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    output.write(chunk)
            local_field = "local_binary" if role == "hub" else "local_authority_binary"
            local_path = regular_file(root / config[local_field])
            member_digest = sha256_file(member_path)
            require(sha256_file(local_path) == member_digest, "local_package_binary_mismatch")
            info = parse_buildinfo(run(["go", "version", "-m", str(member_path)]))
            binary_evidence[role] = {"name": name, "local_path": config[local_field],
                "package_member": "opt/ominull/bin/" + name,
                "local_sha256": member_digest, "package_sha256": member_digest, **info}
    require(binary_evidence["hub"]["source_commit"] == binary_evidence["authority"]["source_commit"],
            "binary_source_disagreement")
    return {"package": {"identity": package.name, "version": version,
                "sha256": digest, "signature_sha256": sha256_file(signature),
                "digest_metadata_sha256": sha256_file(digest_file),
                "manifest_sha256": sha256_file(manifest),
                "pinned_public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "signature_verified": True}, "binaries": binary_evidence}


def ssh(config, command, output_file=None):
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o",
            "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "--", config["ssh_alias"],
            "pct exec " + str(config["lxc_id"]) + " -- " + command]
    return run(argv, output_file=output_file)


def parse_service(raw):
    try:
        fields = unique_object([line.split("=", 1) for line in raw.decode().splitlines()])
    except (ValueError, UnicodeError) as exc:
        raise ObservationError("service_state_invalid") from exc
    require(set(fields) == {"ActiveState", "SubState", "MainPID", "NRestarts",
                            "ExecMainStartTimestampMonotonic"}, "service_state_fields")
    require(fields["ActiveState"] == "active" and fields["SubState"] == "running",
            "service_not_running")
    for key in ("MainPID", "NRestarts", "ExecMainStartTimestampMonotonic"):
        require(re.fullmatch(r"[0-9]+", fields[key]), "service_state_invalid")
    require(int(fields["MainPID"]) > 1 and int(fields["ExecMainStartTimestampMonotonic"]) > 0,
            "service_pid_invalid")
    return {"active_state": fields["ActiveState"], "sub_state": fields["SubState"],
            "pid": int(fields["MainPID"]), "restarts": int(fields["NRestarts"]),
            "started_monotonic_us": int(fields["ExecMainStartTimestampMonotonic"])}


def services(config):
    return {role: parse_service(ssh(config, "systemctl show " + name + ".service "
            "--property=ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestampMonotonic"))
            for role, name in BINARIES.items()}


def remote_digest(config, path):
    raw = ssh(config, "sha256sum -- " + shlex.quote(path))
    try:
        parts = raw.decode().split()
        require(len(parts) == 2 and parts[1] == path, "remote_digest_invalid")
        digest = parts[0]
    except UnicodeError as exc:
        raise ObservationError("remote_digest_invalid") from exc
    require(DIGEST.fullmatch(digest), "remote_digest_invalid")
    return digest


def running_evidence(config, evidence, initial, directory):
    for role, name in BINARIES.items():
        installed = remote_digest(config, "/opt/ominull/bin/" + name)
        proc_path = f"/proc/{initial[role]['pid']}/exe"
        running = remote_digest(config, proc_path)
        require(installed == running == evidence["binaries"][role]["package_sha256"],
                "installed_running_package_mismatch")
        fetched = directory / ("running-" + name)
        with fetched.open("wb") as output:
            ssh(config, f"head -c {MAX_BINARY + 1} -- {proc_path}", output_file=output)
        require(0 < fetched.stat().st_size <= MAX_BINARY and sha256_file(fetched) == running,
                "running_binary_changed_or_oversized")
        info = parse_buildinfo(run(["go", "version", "-m", str(fetched)]))
        require(info["source_commit"] == evidence["binaries"][role]["source_commit"],
                "running_source_mismatch")
        evidence["binaries"][role].update({"installed_sha256": installed,
             "running_sha256": running, "running_source_commit": info["source_commit"],
             "running_vcs_modified": False})
    status = ssh(config, "dpkg-query -W -f='${Status} ${Version}' ominull-hub").decode().strip()
    require(status == "install ok installed " + evidence["package"]["version"],
            "installed_package_version_mismatch")
    return evidence


def credential(config):
    path = regular_file(Path(config["admin_key_file"]), private=True)
    raw = path.read_bytes()
    require(0 < len(raw) <= 4096, "credential_size")
    try:
        lines = raw.decode("ascii").split("\n")
    except UnicodeError as exc:
        raise ObservationError("credential_invalid") from exc
    if lines[-1] == "":
        lines.pop()
    # The approved operations source contains admin first, tenant second. Only
    # line one is sent. Validate both so assignments, blanks, extra lines and
    # header-control characters cannot masquerade as the credential source.
    require(len(lines) in {1, 2}, "credential_invalid")
    tokens = [line.removesuffix("\r") for line in lines]
    require(all(token and all(0x21 <= ord(char) <= 0x7e for char in token)
                for token in tokens), "credential_invalid")
    return tokens[0]


def http_read(config, path, key=None, max_body=MAX_OUTPUT):
    url = urlsplit(config["hub_base_url"])
    if url.scheme == "https":
        conn = http.client.HTTPSConnection(url.hostname, url.port, timeout=HTTP_TIMEOUT,
                                          context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=HTTP_TIMEOUT)
    headers = {"Accept-Encoding": "identity", "Cache-Control": "no-cache"}
    if key is not None:
        headers["X-API-Key"] = key
    try:
        started = time.monotonic()
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        body = response.read(max_body + 1)
        require(len(body) <= max_body, "http_body_too_large")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0]
        if content_type not in {"application/json", "text/html", "text/javascript",
                                "application/javascript", "text/plain"}:
            content_type = "unknown"
        result = {"path": path, "status": response.status,
                  "duration_ms": round((time.monotonic() - started) * 1000, 3),
                  "content_type": content_type}
        return result, body
    except (OSError, http.client.HTTPException) as exc:
        raise ObservationError("http_unavailable") from exc
    finally:
        conn.close()


def health_evidence(config, initial):
    status, body = http_read(config, "/api/v1/console/status")
    require(status["status"] == 200 and status["content_type"] == "application/json",
            "health_http_failed")
    require(isinstance(parse_json(body), dict), "health_json_invalid")
    return {"services": initial, "http": status}


def routes_evidence(root, config, version, deployed):
    key = credential(config)
    routes = []
    console, body = http_read(config, "/", key)
    require(console["status"] == 200 and console["content_type"] == "text/html",
            "console_http_failed")
    asset = "/app.js?v=" + version
    require(("app.js?v=" + version).encode() in body, "console_asset_version_mismatch")
    routes.append(console)
    del body
    for path in ("/api/v1/hierarchy", "/api/v1/diagnostics"):
        route, body = http_read(config, path, key, max_body=8 * 1024 * 1024)
        require(route["status"] == 200 and route["content_type"] == "application/json",
                "authenticated_route_failed")
        require(isinstance(parse_json(body), (dict, list)), "route_json_invalid")
        routes.append(route)
        del body
    script, body = http_read(config, asset, key)
    expected = git(root, "show", deployed + ":hub/pkg/server/web/app.js")
    require(script["status"] == 200 and script["content_type"] in
            {"text/javascript", "application/javascript"} and body == expected,
            "current_asset_mismatch")
    script["sha256"] = hashlib.sha256(body).hexdigest()
    script["source_commit"] = deployed
    routes.append(script)
    del body
    anonymous, body = http_read(config, "/api/v1/hierarchy")
    require(anonymous["status"] == 401, "anonymous_route_not_denied")
    routes.append(anonymous)
    del body, key
    return {"routes": routes, "methods": ["GET"], "response_bodies_retained": False}


def observe(request, root, code_root):
    result = {"schema_version": 1, **{field: request[field] for field in (
        "challenge", "project", "task_id", "acceptance_id", "accepted_source_commit")},
        "target_id": "unconfigured", "deployed_source_commit": None,
        "runtime_policy_path": POLICY_PATH, "runtime_exclusions": POLICY, "checks": []}
    evidence = {}
    try:
        config, config_digest = load_config(root)
        result["target_id"] = config["target_id"]
        code = pin_code(root, code_root, request["accepted_source_commit"])
        base = {"configuration_sha256": config_digest, "observer": code}
    except (ObservationError, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, ObservationError) else "local_read_failed"
        result["checks"] = [{"id": name, "state": "failed", "evidence": {"error": code}}
                            for name in CHECK_IDS]
        return result
    initial = None
    with tempfile.TemporaryDirectory(prefix="ominull-observe-") as temp:
        directory = Path(temp)
        for check_id in CHECK_IDS:
            check_started = time.monotonic()
            try:
                if check_id == "production_binary":
                    evidence = package_evidence(root, config, request["accepted_source_commit"], directory)
                    initial = services(config)
                    evidence = running_evidence(config, evidence, initial, directory)
                    result["deployed_source_commit"] = evidence["binaries"]["hub"]["running_source_commit"]
                    check_evidence = evidence
                elif check_id == "production_health":
                    if initial is None:
                        initial = services(config)
                    check_evidence = health_evidence(config, initial)
                else:
                    require(result["deployed_source_commit"] is not None, "binary_observation_required")
                    check_evidence = routes_evidence(root, config, evidence["package"]["version"],
                                                    result["deployed_source_commit"])
                    require(services(config) == initial, "process_changed_during_observation")
                result["checks"].append({"id": check_id, "state": "success",
                                         "evidence": {**base, **check_evidence,
                                          "duration_ms": round((time.monotonic() - check_started) * 1000, 3)}})
            except (ObservationError, OSError, ValueError, tarfile.TarError) as exc:
                code = str(exc) if isinstance(exc, ObservationError) else "observation_read_failed"
                result["checks"].append({"id": check_id, "state": "failed",
                                         "evidence": {**base, "error": code,
                                          "duration_ms": round((time.monotonic() - check_started) * 1000, 3)}})
    return result


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ObservationError("invalid_arguments")

    parser = Parser(description="Read-only fixed production observation")
    parser.add_argument("--request", action="append", help="One JSON request; otherwise read one from stdin")
    try:
        args = parser.parse_args(argv)
        require(args.request is None or len(args.request) == 1, "multiple_requests")
        raw = args.request[0] if args.request is not None else sys.stdin.read(16385)
        request = parse_request(raw)
        code_root = Path(__file__).resolve().parents[2]
        root = context_root(os.environ.get("ST_EXTENSION_CONTEXT", ""), code_root)
        result = observe(request, root, code_root)
    except (ObservationError, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, ObservationError) else "observer_input_failed"
        print(json.dumps({"schema_version": 1, "error": code}, separators=(",", ":")))
        return 2
    print(json.dumps(result, separators=(",", ":")))
    # A failed check is valid observation evidence. The issuer decides gate
    # acceptance from check states; transport success must preserve failures.
    return 0
