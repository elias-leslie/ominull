"""Exercise the standalone poller predicate, without gateway state or credentials."""
import pathlib
import re
import subprocess
import unittest

class AddressFilter(unittest.TestCase):
    def test_scope(self):
        script = pathlib.Path(__file__).with_name('ominull-router-poll.sh').read_text()
        match = re.search(r'^is_local_destination\(\) \{.*?^\}', script, re.M | re.S)
        assert match is not None, 'poller needs a testable destination predicate'
        for address, local in [
            ('fd12::2', True), ('FC00::9', True), ('fe80::3', True),
            ('FEBF::3', True), ('ff02::1', True), ('::1', True),
            ('100.64.0.2', True), ('100.127.0.2', True), ('239.2.3.4', True),
            ('10.0.4.2', True), ('172.31.0.2', True),
            ('2001:db8::2', False), ('fca::2', False), ('100.128.0.2', False),
            ('8.8.8.8', False),
        ]:
            with self.subTest(address=address):
                result = subprocess.run(['sh', '-c', match.group() + '\nis_local_destination "$1"', 'test', address])
                self.assertEqual(result.returncode == 0, local)

if __name__ == '__main__':
    unittest.main()
