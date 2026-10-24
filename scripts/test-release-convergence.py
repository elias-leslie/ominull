"""Exercise release convergence against a synthetic local operator HTTP API."""

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import unittest


VERSION = "1.2.0"


def status(online=("required",), offline=("sleeping",), outdated=(), issues=(), staged=None):
    response = {
        "latest_version": VERSION,
        "endpoints": [
            {"endpoint_id": identifier, "driver_version": "1.1.0" if identifier in outdated else VERSION, "status": state}
            for state, identifiers in (("online", online), ("offline", offline))
            for identifier in identifiers
        ],
        "outdated": [{"endpoint_id": identifier} for identifier in outdated] or None,
        "provenance_issues": [{"endpoint_id": identifier} for identifier in issues] or None,
        "retired": None,
        "pending": [{"endpoint_id": identifier} for identifier in outdated] or None,
    }
    if staged is not None:
        # A hub that stages rollouts lists them; state "" means none yet.
        response["staged_rollouts"] = [
            {"id": "ro_other", "version": VERSION, "state": "halted", "detail": "an older rollout"},
        ] + ([{"id": "ro_1", "version": VERSION, "state": staged, "detail": "fixture " + staged}] if staged else [])
    return response


class ReleaseConvergence(unittest.TestCase):
    def release(self, responses, *, canary="", wait=True):
        requests = []
        snapshots = copy.deepcopy(responses)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self):
                requests.append(("GET", self.path))
                response = snapshots.pop(0) if len(snapshots) > 1 else snapshots[0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(("POST", body))
                self.send_response(200)
                self.end_headers()
                reply: dict[str, object] = {"desired_version": VERSION, "scheduled": [], "unsupported": []}
                if "canary" in body:
                    reply["rollout"] = {"id": "ro_1"}
                self.wfile.write(json.dumps(reply).encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        # shutdown() waits for the serve loop to poll; the default 0.5 s poll
        # made this fixture most of the gate's release-script time.
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        source = Path(__file__).with_name("release.sh").read_text()
        script = f"set -euo pipefail\nROOT_DIR={shlex.quote(str(Path(__file__).resolve().parent.parent))}\n"
        script += "VERSION=1.2.0\nOMINULL_ADMIN_KEY=synthetic-fixture\n"
        script += f"HUB_URL=http://127.0.0.1:{server.server_port}\nCANARY_IDS={shlex.quote(canary)}\nWAIT_FOR_AGENTS={int(wait)}\n"
        script += "sleep() { :; }\nseq() { printf '1\\n2\\n3\\n'; }\n"
        script += source[source.index("hdr() {"):]
        try:
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        return result, requests

    def test_agent_update_is_one_request_with_no_approval(self):
        result, requests = self.release([status(outdated=("required",)), status()])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn("approval", (result.stderr + result.stdout).lower())
        self.assertEqual([r for r in requests if r[0] == "POST"], [("POST", {"all": True, "version": VERSION})])

    def test_offline_pending_does_not_block_online_convergence(self):
        result, requests = self.release([
            status(outdated=("required", "sleeping")), status(outdated=("sleeping",)),
        ])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("online cohort converged", result.stdout)
        self.assertIn('"offline_pending_count":1', result.stdout)
        self.assertEqual(requests[0][0], "GET")
        self.assertEqual(requests[1], ("POST", {"all": True, "version": VERSION}))

    def test_cohort_cannot_shrink_when_required_endpoint_goes_offline(self):
        result, _ = self.release([status(outdated=("required",)), status(online=(), offline=("required", "sleeping"))])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("converged on", result.stdout)

    def test_missing_captured_endpoint_cannot_converge(self):
        result, _ = self.release([status(), status(online=("replacement",), offline=())])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("converged on", result.stdout)

    def test_bad_native_provenance_blocks(self):
        result, _ = self.release([status(), status(issues=("required",))])
        self.assertNotEqual(result.returncode, 0)

    def test_missing_or_malformed_fields_prevent_queue(self):
        malformed = []
        for key in ("outdated", "provenance_issues", "pending", "retired", "endpoints"):
            missing = status()
            del missing[key]
            malformed.append(missing)
        wrong = status()
        wrong["outdated"] = {}
        malformed.append(wrong)
        wrong = status()
        wrong["endpoints"][0]["status"] = "mystery"
        malformed.append(wrong)
        duplicate = status()
        duplicate["endpoints"].append(duplicate["endpoints"][0])
        malformed.append(duplicate)
        malformed.append(status(online=(), offline=()))
        for response in malformed:
            with self.subTest(response=response):
                result, requests = self.release([response])
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(method == "POST" for method, _ in requests))

    def test_no_online_cohort_cannot_claim_success(self):
        result, requests = self.release([status(online=())])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(method == "POST" for method, _ in requests))

    def test_offline_explicit_canary_is_mandatory(self):
        result, requests = self.release([status()], canary="sleeping")
        self.assertNotEqual(result.returncode, 0)
        posts = [body for method, body in requests if method == "POST"]
        self.assertEqual(posts, [{"endpoint_ids": ["sleeping"], "version": VERSION}])

    def test_canary_does_not_recapture_full_cohort(self):
        result, requests = self.release([
            status(online=("canary", "required")),
            status(online=("canary",), offline=("required", "sleeping")),
        ], canary="canary")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len([method for method, _ in requests if method == "POST"]), 2)
        self.assertNotIn("online cohort converged", result.stdout)

    def test_no_wait_queues_without_convergence_claim(self):
        result, requests = self.release([status(online=())], wait=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(requests), 2)
        self.assertNotIn("converged", result.stdout)

    def test_canary_no_wait_never_queues_full_fleet(self):
        result, requests = self.release([status()], canary="required", wait=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests[1][1], {"endpoint_ids": ["required"], "version": VERSION})
        self.assertEqual(len(requests), 2)

    def test_wrong_version_prevents_queue(self):
        response = status()
        response["latest_version"] = "1.1.0"
        result, requests = self.release([response])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(method == "POST" for method, _ in requests))


    def test_required_endpoint_retirement_is_not_convergence(self):
        retired = status(online=("replacement",), offline=())
        retired["retired"] = [{"endpoint_id": "required"}]
        result, _ = self.release([status(), retired])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("converged on", result.stdout)

    def test_later_malformed_status_cannot_converge(self):
        response = status()
        del response["provenance_issues"]
        result, requests = self.release([status(), response])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(requests[1][0], "POST")
        self.assertNotIn("converged on", result.stdout)

    def test_version_observation_cannot_be_hidden_by_empty_outdated_list(self):
        response = status()
        response["endpoints"][0]["driver_version"] = "1.1.0"
        result, _ = self.release([status(), response])
        self.assertNotEqual(result.returncode, 0)

    def test_offline_at_start_can_return_without_expanding_required_cohort(self):
        result, _ = self.release([
            status(outdated=("required", "sleeping")),
            status(online=("required", "sleeping"), offline=(), outdated=("sleeping",)),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"offline_pending_count":1', result.stdout)

    def test_offline_canary_can_return_and_complete_both_phases(self):
        result, requests = self.release([
            status(outdated=("sleeping",)), status(online=("required", "sleeping"), offline=()),
        ], canary="sleeping")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("canary endpoints converged", result.stdout)
        self.assertIn("online cohort converged", result.stdout)
        self.assertEqual(len([method for method, _ in requests if method == "POST"]), 2)

    def test_staged_rollout_is_one_request(self):
        result, requests = self.release([
            status(outdated=("required",), staged=""), status(staged="canary"), status(staged="released"),
        ], canary="required")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Hub released the fleet", result.stdout)
        self.assertEqual([r for r in requests if r[0] == "POST"],
                         [("POST", {"all": True, "version": VERSION, "canary": ["required"]})])

    def test_halted_staged_rollout_fails(self):
        result, requests = self.release([
            status(outdated=("required",), staged=""), status(staged="halted"),
        ], canary="required")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Rollout halted", result.stderr)
        self.assertEqual(len([r for r in requests if r[0] == "POST"]), 1)

    def test_staged_no_wait_queues_once(self):
        result, requests = self.release([status(staged="")], canary="required", wait=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Staged rollout ro_1 queued", result.stdout)
        self.assertEqual(len([r for r in requests if r[0] == "POST"]), 1)

    def test_absent_canary_prevents_any_queue(self):
        result, requests = self.release([status()], canary="absent")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(method == "POST" for method, _ in requests))

    def test_empty_canary_selection_prevents_full_queue(self):
        result, requests = self.release([status()], canary=" , ")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(method == "POST" for method, _ in requests))


class HubPreflight(unittest.TestCase):
    """release.sh asks the hub-install key before building; a failure names the interim deploy hook."""

    def preflight(self, override):
        source = Path(__file__).with_name("release.sh").read_text()
        start = source.index('if [ "${DO_HUB}" -eq 1 ]; then\n    [ -x "${DEPLOY_CMD}" ]')
        block = source[start:source.index('if [ -n "${VERSION}" ]; then', start)]
        with tempfile.TemporaryDirectory() as temp:
            hook, log = Path(temp) / "deploy-hub.sh", Path(temp) / "calls"
            hook.write_text('#!/bin/sh\necho "$@" >> "%s"\n[ "$1" != --check ]\n' % log)
            hook.chmod(0o755)
            script = "set -euo pipefail\nDO_HUB=1\nDEPLOY_CMD=%s\n" % shlex.quote(str(hook))
            if override:
                script += "OMINULL_DEPLOY_CMD=%s\n" % shlex.quote(str(hook))
            result = subprocess.run(["bash", "-c", script + block + "echo built"], capture_output=True, text=True,
                                    timeout=10)
            return result, log.read_text() if log.exists() else ""

    def test_a_key_that_does_not_answer_stops_before_the_build_and_names_the_interim_hook(self):
        result, calls = self.preflight(override=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, "--check\n")
        self.assertNotIn("built", result.stdout)
        self.assertIn("OMINULL_DEPLOY_CMD=scripts/deploy_remote.sh", result.stderr)

    def test_an_explicit_deploy_hook_skips_the_key_check(self):
        result, calls = self.preflight(override=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, "")
        self.assertIn("built", result.stdout)


if __name__ == "__main__":
    unittest.main()
