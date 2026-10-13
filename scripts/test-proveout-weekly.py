"""Prove-out measurement: window, signature grouping, first-match labels and the share judged real."""
import importlib.util
import pathlib
import unittest
from datetime import UTC, datetime

spec = importlib.util.spec_from_file_location('proveout', pathlib.Path(__file__).with_name('proveout-weekly.py'))
assert spec is not None and spec.loader is not None
proveout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proveout)

START, END = datetime(2026, 10, 6, tzinfo=UTC), datetime(2026, 10, 13, tzinfo=UTC)


def alert(ts, typ='NOVEL_PROCESS_EGRESS', proc='/usr/bin/curl', host='ws', sev='MEDIUM'):
    return {'timestamp': ts, 'anomaly_type': typ, 'process_path': proc, 'hostname': host, 'severity': sev}


class Measure(unittest.TestCase):
    def test_window_labels_and_share(self):
        alerts = [
            alert('2026-10-06T00:00:00.123456789Z'),
            alert('2026-10-07T10:00:00Z'),
            alert('2026-10-12T23:59:59.999999999Z', typ='ENDPOINT_SILENT', proc='', host='srv', sev='HIGH'),
            alert('2026-10-08T01:00:00Z', proc='C:\\Tools\\odd.exe', host='laptop'),
            alert('2026-10-13T00:00:00Z'),  # end is exclusive
            alert('2026-10-05T23:59:59Z'),
        ]
        rules = [
            {'type': 'ENDPOINT_SILENT', 'label': 'real'},
            {'type': 'NOVEL_*', 'process': 'curl', 'label': 'noise'},
            {'type': '*', 'label': 'expected', 'host': 'nowhere'},
        ]
        m = proveout.measure(alerts, rules, START, END)
        self.assertEqual(m['total'], 4)
        self.assertEqual(m['by_label'], {'noise': 2, 'real': 1, 'untriaged': 1})
        self.assertEqual(m['share_real'], round(1 / 3, 4))
        self.assertEqual([(s['process'], s['label']) for s in m['signatures']][0], ('curl', 'noise'))
        self.assertIn(('odd.exe', 'untriaged'), [(s['process'], s['label']) for s in m['signatures']])
        self.assertEqual(m['days_with_data'], 4)
        self.assertIn('share judged real 33.3%', proveout.summary_line(m))

    def test_unknown_label_is_refused(self):
        with self.assertRaises(SystemExit):
            proveout.measure([alert('2026-10-07T00:00:00Z')], [{'label': 'fine'}], START, END)


if __name__ == '__main__':
    unittest.main()
