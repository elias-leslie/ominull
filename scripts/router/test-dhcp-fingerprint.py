#!/usr/bin/env python3
"""Exercise the sourced OpenWrt hook and poller JSON without network access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent
hook = root / 'ominull-dhcp-hook.sh'
poller = (root / 'ominull-router-poll.sh').read_text()
escape = poller[poller.index('json_escape() {'):poller.index('# ---- leases')]
mac = 'da:bb:cc:dd:ee:01'
with tempfile.TemporaryDirectory() as cache:
    env = dict(os.environ, OMINULL_DHCP_CACHE=cache, DHCP_CACHE=cache)

    def capture(action='add', address=mac, ip='10.0.0.9', **metadata):
        # Sourcing must return to the standard wrapper, including invalid input.
        result = subprocess.run(['sh', '-c', 'hook=$1; shift; . "$hook"; printf wrapper-alive',
                                 'test', str(hook), action, address, ip],
                                env=dict(env, **metadata), check=True, capture_output=True, text=True)
        assert result.stdout == 'wrapper-alive', result

    def fingerprint(address=mac):
        out = subprocess.check_output(['sh', '-c', escape + '\nprintf "{\\"mac\\":\\"fixture\\""; fingerprint_json "$1"; printf "}"',
                                       'test', address], env=env, text=True)
        return json.loads(out)

    vendor = 'android-"quoted"\\class\nsecond\tline'
    capture(DNSMASQ_VENDOR_CLASS=vendor, DNSMASQ_REQUESTED_OPTIONS='1,3,6,15,26,28,51,58,59')
    observed = fingerprint()['dhcp']
    assert observed['vendor_class'] == vendor.replace('\n', '').replace('\t', '')
    assert observed['requested_options'] == '1,3,6,15,26,28,51,58,59'
    capture('old')
    assert fingerprint()['dhcp'] == observed, 'startup replay erased or refreshed metadata'
    capture(address='../../escape', DNSMASQ_VENDOR_CLASS='bad')
    capture(address='00:01:00:01:aa:bb:cc:dd', ip='fe80::1', DNSMASQ_VENDOR_CLASS='v6')
    assert len(list(Path(cache).iterdir())) == 1
    capture(DNSMASQ_VENDOR_CLASS='X' * 256, DNSMASQ_REQUESTED_OPTIONS='1,$(touch bad)')
    assert fingerprint()['dhcp'] == observed, 'invalid metadata replaced valid evidence'
    capture('del')
    assert 'dhcp' not in fingerprint()
    assert not list(Path(cache).iterdir())
print('DHCP hook/poller: capture, JSON escaping, replay, bounds, IPv4 scope, deletion, wrapper continuity passed')
