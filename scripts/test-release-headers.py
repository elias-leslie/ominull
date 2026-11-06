"""Verify release requests pass credentials through a fresh descriptor per call."""
from pathlib import Path
import re
import json
import shlex
import subprocess
import unittest
from typing import Any

class ReleaseHeaders(unittest.TestCase):
    def test_fresh_descriptor_for_each_request(self):
        source = Path(__file__).with_name('release.sh').read_text()
        api = re.search(r'^api\(\) \{.*?^\}', source, re.M | re.S)
        assert api is not None
        hdr = re.search(r'^hdr\(\) \{.*?^\}', source, re.M | re.S)
        helper = Path(__file__).with_name('hub-request.sh').read_text()
        config = re.search(r'^hub_curl_config\(\) \{.*?^\}', helper, re.M | re.S)
        assert config is not None
        script = '''set -eu
OMINULL_ADMIN_KEY=test-release-credential
HUB_URL=http://example.test
HEADER_FILE=/unused-test-file
curl() {
 case " $* " in *" -K /dev/fd/3 "*) ;; *) echo 'missing descriptor config' >&2; return 80;; esac
 IFS= read -r config <&3
 [ "$config" = 'header = "X-API-Key: test-release-credential"' ]
 printf 'ok\\n'
}
'''
        script += config.group() + '\n' + ((hdr.group() + '\n') if hdr else '')
        script += api.group() + '\napi GET /test\napi POST /test "{}"\napi GET /test\n'
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['ok', 'ok', 'ok'])

    def test_config_names_the_calling_agent(self):
        # The hub records an admin-key call under X-Ominull-Agent (else "admin"):
        # $OMINULL_AGENT, else the agent session; a name the hub refuses is left out.
        helper = Path(__file__).with_name('hub-request.sh')
        base = {'PATH': '/usr/bin:/bin'}
        for env, want in [({'OMINULL_AGENT': 'summitflow offsite backup'}, 'summitflow offsite backup'),
                          ({'CLAUDE_CODE_SESSION_ID': 'f5c210d6-e196', 'AICO_WIDGET_ID': 'b33f5536'}, 'cc:f5c210 (Aico b33f5536)'),
                          ({'CODEX_THREAD_ID': '019a2b3c-4d5e'}, 'codex:019a2b'),
                          ({'OMINULL_AGENT': 'say "hi"'}, None), ({'OMINULL_AGENT': 'x' * 65}, None), ({'OMINULL_AGENT': ' x'}, None), ({}, None)]:
            with self.subTest(env=env):
                out = subprocess.run(['bash', '-c', f'. {shlex.quote(str(helper))}; hub_curl_config k https://h'],
                                     env={**base, **env}, text=True, capture_output=True, check=True).stdout.splitlines()
                self.assertEqual(out[0], 'header = "X-API-Key: k"')
                agent = [line for line in out if 'X-Ominull-Agent' in line]
                self.assertEqual(agent, [f'header = "X-Ominull-Agent: {want}"'] if want else [])

    def test_admin_key_scripts_refuse_plain_http(self):
        # The trust-bundle signer sends the admin key: never
        # as plain HTTP on the LAN, and always with the hub CA over HTTPS.
        here = Path(__file__).parent
        for name in ['sign-trust-bundle.sh']:
            with self.subTest(name=name):
                source = here.joinpath(name).read_text()
                self.assertNotIn('X-API-Key', source)
                self.assertIn('hub_curl_config', source)
                self.assertNotIn('http://', source)
                env = {'PATH': '/usr/bin:/bin', 'OMINULL_HUB_URL': 'http://192.0.2.1:9999', 'OMINULL_ADMIN_KEY': 'k',
                       'OMINULL_ADMIN_KEY_FILE': '/dev/null', 'OMINULL_TRUST_STATEMENT_CMD': 'exit 90'}
                result = subprocess.run(['bash', str(here / name), 'default'],
                                        env=env, text=True, capture_output=True, stdin=subprocess.DEVNULL)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('Refusing to send the hub key to http://192.0.2.1:9999', result.stderr)

    def test_convergence_requires_observed_requested_endpoints(self):
        source = Path(__file__).with_name('release.sh').read_text()
        wait_match = re.search(r'^wait_for\(\) \{.*?^\}', source, re.M | re.S)
        assert wait_match is not None
        wait = wait_match.group()
        validate_match = re.search(r'^validate_status\(\) \{.*?^\}', source, re.M | re.S)
        assert validate_match is not None
        validate = validate_match.group()
        target_match = re.search(r'^target_json\(\) \{.*?^\}', source, re.M | re.S)
        assert target_match is not None
        target = target_match.group()
        responses: list[dict[str, Any]] = [
            {"latest_version": "1.2.0", "outdated": [], "endpoints": []},
            {"latest_version": "1.2.0", "outdated": [], "endpoints": [{"endpoint_id": "other"}]},
            {"latest_version": "1.1.0", "outdated": [], "endpoints": [{"endpoint_id": "canary"}]},
        ]
        for response in responses:
            for key in ("provenance_issues", "retired", "pending"):
                response[key] = None
            for endpoint in response["endpoints"]:
                endpoint.update(driver_version="1.2.0", status="online")
            script = "VERSION=1.2.0\nCOHORT_IDS_JSON='[\"canary\"]'\napi() { printf '%s' " + shlex.quote(json.dumps(response)) + "; }\nsleep() { :; }\n"
            script += target + "\n" + validate + "\n" + wait + "\nwait_for canary\n"
            result = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn('converged on', result.stdout)

if __name__ == '__main__':
    unittest.main()
