#!/usr/bin/env python3
"""A hub that is off or restarting is not a failed run; a hub that answers wrongly still is."""
import contextlib
import email.message
import importlib.util
import io
import ssl
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("sync_agent_sessions", Path(__file__).parent / "sync-agent-sessions.py")
assert spec and spec.loader
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def run_with(post):
    out = io.StringIO()
    with mock.patch.object(sync, "sessions", return_value=[{"window": "w"}]), mock.patch.object(sync, "post", post), contextlib.redirect_stdout(out):
        sync.main()
    return out.getvalue()


class HubAnswers(unittest.TestCase):
    def test_saved(self):
        self.assertIn("ok: 1 of 1", run_with(mock.Mock(return_value={"saved": 1})))

    def test_no_connection_skips(self):
        for reason in (ConnectionRefusedError(111, "refused"), OSError(113, "no route")):
            self.assertIn("skipped", run_with(mock.Mock(side_effect=urllib.error.URLError(reason))))
        self.assertIn("skipped", run_with(mock.Mock(side_effect=TimeoutError())))

    def test_real_failures_stay_failures(self):
        for error in (
            urllib.error.HTTPError("u", 401, "no", email.message.Message(), None),
            urllib.error.URLError(ssl.SSLCertVerificationError("bad cert")),
        ):
            with self.assertRaises(urllib.error.URLError):
                run_with(mock.Mock(side_effect=error))


if __name__ == "__main__":
    unittest.main()
