"""Verify release requests pass credentials through a fresh descriptor per call."""
from pathlib import Path
import re
import subprocess
import unittest

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

if __name__ == '__main__':
    unittest.main()
