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
        script += (hdr.group() + '\n') if hdr else ''
        script += api.group() + '\napi GET /test\napi POST /test "{}"\napi GET /test\n'
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['ok', 'ok', 'ok'])

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
