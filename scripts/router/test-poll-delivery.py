"""Run the router poller under busybox with stub hub, ubus and uci commands.

Covers what decides whether DNS is lost: the log offset moves only after the
hub answers 200, a half-written line waits for the next poll, delivered logs
are truncated, and an outage backlog is bounded. Needs busybox on PATH.
"""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
POLLER = HERE / 'ominull-router-poll.sh'
BUSYBOX = shutil.which('busybox')
APPLETS = ['sh', 'awk', 'sed', 'tail', 'head', 'wc', 'ls', 'date', 'grep', 'cat', 'mv', 'rm',
           'rmdir', 'mktemp', 'tr', 'printf', 'read', 'expr', 'cut', 'sort', 'touch', 'od']

CURL = r'''#!/bin/sh
# Records the request, then answers with the code in $STUB/code.
out='' body='' args=''
while [ $# -gt 0 ]; do
	case "$1" in
		-o) out=$2; shift ;;
		--data-binary) body=${2#@}; shift ;;
		-K) cat "$2" > "$STUB/key" 2>/dev/null; shift ;;
		-w|-H|--max-time) shift ;;
		*) args="$args $1" ;;
	esac
	shift
done
n=$(cat "$STUB/calls" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$STUB/calls"
cp "$body" "$STUB/body.$n"
echo "$args" > "$STUB/args.$n"
echo '{"dns_accepted":0}' > "$out"
cat "$STUB/code"
'''
JSONFILTER = '''#!/usr/bin/env python3
import json, sys
try:
    doc = json.load(open(sys.argv[sys.argv.index('-i') + 1]))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(doc, dict) and 'clients' in doc else 1)
'''


@unittest.skipUnless(BUSYBOX, 'busybox is required to emulate the gateway shell')
class PollDelivery(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.stub = self.dir / 'stub'
        self.bin = self.dir / 'bin'
        self.stub.mkdir()
        self.bin.mkdir()
        assert BUSYBOX is not None
        for applet in APPLETS:
            (self.bin / applet).symlink_to(BUSYBOX)
        self.write_exec('curl', CURL)
        self.write_exec('jsonfilter', JSONFILTER)
        self.write_exec('logger', '#!/bin/sh\necho "$@" >> "$STUB/log"\n')
        self.write_exec('uci', '#!/bin/sh\ncase "$*" in *ipaddr*) echo 10.0.0.1 ;; *netmask*) echo 255.255.255.0 ;; *) exit 1 ;; esac\n')
        self.write_exec('ubus', '#!/bin/sh\ncat "$STUB/ubus" 2>/dev/null || exit 1\n')
        self.log = self.dir / 'dnsmasq.log'
        self.log.write_text('')
        (self.dir / 'leases').write_text('')
        (self.dir / 'conntrack').write_text('')
        self.code('200')
        self.conf = self.dir / 'router.conf'
        self.configure()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def write_exec(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def configure(self, **extra):
        values = {
            'HUB_URL': 'https://hub.invalid:9443', 'TLS_CA': '/x/ca.crt', 'TLS_CERT': '/x/router.crt',
            'TLS_KEY': '/x/router.key', 'ROUTER_ID': 'gw', 'DNS_LOG': '1', 'DNS_LOG_FILE': str(self.log),
            'DNS_STATE': str(self.dir / 'offset'), 'LEASEFILE': str(self.dir / 'leases'),
            'CONNTRACK': str(self.dir / 'conntrack'), 'DHCP_CACHE': str(self.dir / 'dhcp'),
            'WORK_BASE': str(self.dir), 'LOGGER': str(self.bin / 'logger'), 'DNS_TRUNCATE_AT': '1000000',
        }
        values.update(extra)
        self.conf.write_text(''.join(f'{k}="{v}"\n' for k, v in values.items()))

    def code(self, value):
        (self.stub / 'code').write_text(value)

    def run_poller(self):
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'STUB': str(self.stub), 'TZ': 'UTC',
               'OMINULL_ROUTER_CONF': str(self.conf)}
        return subprocess.run([str(self.bin / 'sh'), str(POLLER)], env=env, capture_output=True, text=True)

    def last_body(self):
        n = (self.stub / 'calls').read_text().strip()
        return json.loads((self.stub / f'body.{n}').read_text())

    def append(self, text):
        with self.log.open('a') as f:
            f.write(text)

    def query(self, n, name='example.com', client='10.0.0.36'):
        return f'Oct 12 19:55:{n:02d} dnsmasq[1]: {n} {client}/53 query[A] {name} from {client}\n'

    def test_failed_post_keeps_queries_for_the_next_poll(self):
        self.append(self.query(1) + self.query(2))
        self.code('503')
        self.assertNotEqual(self.run_poller().returncode, 0)
        self.assertEqual(len(self.last_body()['dns']), 2)
        self.code('200')
        self.append(self.query(3))
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertEqual([d['domain'] for d in self.last_body()['dns']], ['example.com'] * 3)
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertEqual(self.last_body()['dns'], [], 'delivered queries were sent twice')

    def test_partial_line_waits_and_times_and_replies_parse(self):
        self.append(self.query(4, client='127.0.0.1')
                    + 'Oct 12 19:55:04 dnsmasq[1]: 4 10.0.0.36/53 reply example.com is 192.0.2.9\n'
                    + 'Oct 12 19:55:04 dnsmasq[1]: 4 10.0.0.36/53 reply example.com is NXDOMAIN\n'
                    + 'Oct 12 19:55:05 dnsmasq[1]: 5 10.0.0.36/53 query[AAAA] half.exa')
        self.assertEqual(self.run_poller().returncode, 0)
        body = self.last_body()
        self.assertEqual(body['dns'], [{'client_ip': '10.0.0.1', 'domain': 'example.com', 'qtype': 'A',
                                        'at': body['dns'][0]['at']}])
        self.assertTrue(body['dns'][0]['at'].endswith('-10-12T19:55:04+00:00'), body['dns'][0]['at'])
        self.assertEqual(body['resolutions'], [{'domain': 'example.com', 'ip': '192.0.2.9'}])
        self.append('mple.com from 10.0.0.36\n')
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertEqual([(d['domain'], d['qtype']) for d in self.last_body()['dns']], [('half.example.com', 'AAAA')])

    def test_delivered_log_is_truncated_and_backlog_is_capped(self):
        self.configure(DNS_TRUNCATE_AT='10')
        self.append(self.query(6))
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertEqual(self.log.stat().st_size, 0, 'a fully delivered log was not emptied')
        self.append(self.query(7))
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertEqual(len(self.last_body()['dns']), 1, 'the first line after truncation was skipped')

        self.configure(DNS_FILE_CAP='100')
        self.code('503')
        self.append(self.query(8) + self.query(9))
        self.run_poller()
        self.assertEqual(self.log.stat().st_size, 0)
        self.assertIn('dropped', (self.stub / 'log').read_text())

    def test_router_certificate_replaces_the_key_and_clients_are_forwarded(self):
        (self.stub / 'ubus').write_text('{"clients":{"aa:bb:cc:dd:ee:01":{"mac":"aa:bb:cc:dd:ee:01","total_rx":5,"total_tx":6}}}')
        self.assertEqual(self.run_poller().returncode, 0)
        args = (self.stub / 'args.1').read_text()
        self.assertIn('--cert /x/router.crt', args)
        self.assertIn('--cacert /x/ca.crt', args)
        self.assertNotIn('X-API-Key', (self.stub / 'key').read_text())
        self.assertEqual(self.last_body()['gl_clients']['clients']['aa:bb:cc:dd:ee:01']['total_rx'], 5)

        (self.stub / 'ubus').write_text('{"clients": {broken')
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertIsNone(self.last_body()['gl_clients'])

    def test_legacy_key_without_certificate(self):
        self.configure(TLS_CERT='', TLS_KEY='', TLS_CA='', HUB_URL='http://hub.invalid:9999', HUB_KEY='k')
        self.assertEqual(self.run_poller().returncode, 0)
        self.assertIn('X-API-Key: k', (self.stub / 'key').read_text())
        self.assertNotIn('--cert', (self.stub / 'args.1').read_text())


if __name__ == '__main__':
    unittest.main()
