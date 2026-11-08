"""The fleet coverage row: Aico's machines against the hub's enrolled agents."""
import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("fleet_coverage", Path(__file__).with_name("fleet_coverage.py"))
assert spec and spec.loader
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)

NOW = dt.datetime(2026, 11, 6, 14, 0, tzinfo=dt.UTC)
STATUS = {"rows": [
    {"id": "workstation/machine", "kind": "machine", "machine": "workstation"},
    {"id": "fleet/workstation/aico", "kind": "machine", "machine": "aico"},
    {"id": "fleet/workstation/neri-hunters", "kind": "machine", "machine": "neri-hunters"},
    {"id": "portfolio-ai/machine", "kind": "machine", "machine": "apps"},
    {"id": "ominull.machine", "kind": "machine", "machine": "ominull-hub"},
    {"id": "jobinator-4000/machine", "kind": "machine", "machine": "jobinator", "state": "ok", "shown": "off"},
    {"id": "fleet/workstation/agent-work", "kind": "machine", "machine": "agent-work", "state": "off", "shown": "off"},
    {"id": "fleet/x/apps", "kind": "machine", "machine": "apps", "shown": "ok"},
    {"id": "backups-native", "kind": "job", "machine": "workstation"},
    {"id": "jobs/x", "kind": "job", "machine": "other-host"},
]}


class FleetCoverage(unittest.TestCase):
    def test_fleet_is_machine_rows_only_less_the_hub(self):
        self.assertEqual(fc.fleet_machines(STATUS),
                         {"workstation", "aico", "neri-hunters", "apps", "jobinator", "agent-work"})

    def test_off_is_every_row_of_the_machine_shown_off(self):
        self.assertEqual(fc.off_machines(STATUS), {"jobinator", "agent-work"})

    def test_off_machines_are_not_counted_but_named(self):
        r = fc.row("m", NOW, fc.fleet_machines(STATUS), {"workstation", "aico", "neri-hunters", "agent-work"},
                   off=fc.off_machines(STATUS))
        self.assertEqual(r["meaning"], "1 of 5 fleet machines has no OmniNull agent: apps; "
                                       "not counted while off: jobinator")
        r = fc.row("m", NOW, {"aico", "jobinator"}, {"aico"}, off={"jobinator"})
        self.assertEqual((r["state"], r["meaning"]),
                         ("ok", "All 1 fleet machines have an OmniNull agent; not counted while off: jobinator"))

    def test_hosts_are_short_lower_case(self):
        builds = {"endpoints": [{"hostname": "WORKSTATION.lan"}, {"hostname": "aico"}, {"hostname": ""}, "x"]}
        self.assertEqual(fc.protected_hosts(builds), {"workstation", "aico"})
        with self.assertRaises(ValueError):
            fc.protected_hosts({"error": "no"})

    def test_names_the_uncovered_machines(self):
        r = fc.row("workstation", NOW, {"workstation", "aico", "neri-hunters", "apps"},
                   {"workstation", "aico", "pve-host"})
        self.assertEqual(r["state"], "warn")
        self.assertEqual(r["meaning"], "2 of 4 fleet machines have no OmniNull agent: apps, neri-hunters")
        self.assertEqual(r["id"], "ominull.fleet.coverage")
        self.assertEqual(r["next_run"], "2026-11-06T14:30:00Z")

    def test_all_covered_is_ok(self):
        r = fc.row("workstation", NOW, {"aico"}, {"aico", "pve-host"})
        self.assertEqual((r["state"], r["meaning"]), ("ok", "All 1 fleet machines have an OmniNull agent"))

    def test_unknown_is_never_covered(self):
        self.assertEqual(fc.row("m", NOW, {"aico"}, None, "the OmniNull hub was not read (x)")["state"], "warn")
        self.assertIn("lists no machines", fc.row("m", NOW, set(), {"aico"})["meaning"])

    def test_row_fits_the_status_contract(self):
        many = {f"machine-{i:03d}" for i in range(80)}
        r = fc.row("workstation", NOW, many, set())
        self.assertLessEqual(len(r["meaning"]), 300)
        self.assertLessEqual(len(r["what"]), 120)
        self.assertEqual(set(r), {"id", "what", "kind", "machine", "project", "state", "meaning", "last_run", "next_run"})

    def test_hub_source_reads_the_site_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "site.json"
            p.write_text(json.dumps({"config": {"ingest": {"sources": [
                {"name": "other", "url": "https://x:1/a", "ca_file": "/x"},
                {"name": "ominull", "url": "https://192.0.2.58:9443/api/v1/whatever", "ca_file": "/etc/ca.crt"}]}}}))
            self.assertEqual(fc.hub_source(str(p)), ("https://192.0.2.58:9443", "/etc/ca.crt"))
            p.write_text(json.dumps({"ingest": {"sources": [{"name": "ominull", "url": "http://x:1/", "ca_file": "/x"}]}}))
            with self.assertRaises(ValueError):
                fc.hub_source(str(p))


if __name__ == "__main__":
    unittest.main()
