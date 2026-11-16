"""CLI safety: import purity, consent gate, dry-run isolation, resume entry."""


import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import tests
from cuktech_pc import cli, cloud, journal as J
from cuktech_pc.cli import INCONCLUSIVE, REJECTED
from tests.fakepeer import FakeBleClient


class ImportPurity(unittest.TestCase):
    def test_import_has_no_side_effects(self):
        # importing the CLI module must not create files, also not in
        # HOME (the defaults point into ~/.cuktech_pc). A child process
        # imports a new copy. The shared module of this run stays as it is.
        with TemporaryDirectory() as cwd, TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home, PYTHONPATH=str(tests.PROJECT_DIR))
            done = subprocess.run(
                [sys.executable, "-c", "import cuktech_pc.cli"],
                cwd=cwd, env=env, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(list(Path(cwd).iterdir()), [])
            self.assertEqual(list(Path(home).iterdir()), [])

    def test_no_password_argument(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["setup", "--password", "x"])

    def test_no_implicit_bind_subcommand(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])  # a command is required


class ConsentGate(unittest.TestCase):
    def _consent(self, answer) -> bool:
        with mock.patch("builtins.input", answer):
            return cli.request_consent(
                address="AA:BB:CC:DD:EE:FF", model="njcuk.fitting.ad1204",
                user_id="424242",
            )

    def test_yes_accepted(self):
        for typed in ("y", "Y", "yes", " YES "):
            with self.subTest(typed):
                self.assertTrue(self._consent(lambda prompt="", t=typed: t))

    def test_mismatch_and_empty_refused(self):
        # Enter, no, and a typed MAC are all No (default is No)
        for typed in ("", "no", "n", "AA:BB:CC:DD:EE:FF"):
            with self.subTest(typed):
                self.assertFalse(self._consent(lambda prompt="", t=typed: t))
        with self.subTest("end of input"):
            self.assertFalse(self._consent(mock.Mock(side_effect=EOFError)))


class DryRunIsOffline(unittest.TestCase):
    def test_dry_run_touches_no_network_ble_or_account(self):
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            # any attempt to construct an account or scan must explode
            with mock.patch.object(
                cloud, "MiAccount", side_effect=AssertionError("network!")
            ), mock.patch.object(
                cli, "scan_for_ad1204u", side_effect=AssertionError("ble!")
            ):
                rc = cli.main(
                    ["setup", "--dry-run", "--journal", str(journal_path)]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(journal_path.exists())

    def test_dry_run_refuses_proxy_env(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ, {"HTTPS_PROXY": "http://x"}, clear=False
            ):
                rc = cli.main(
                    ["setup", "--dry-run", "--journal", str(Path(tmp) / "j.json")]
                )
            self.assertEqual(rc, 1)


class ResumeEntryPoints(unittest.TestCase):
    def _state(self, **over):
        base = dict(
            mac="AA:BB:CC:DD:EE:FF", model="njcuk.fitting.ad1204",
            token_hex="ab" * 12, bind_key_hex="cd" * 16, a_key_hex="ef" * 16,
        )
        base.update(over)
        return J.JournalState(**base)

    def test_verify_first_path_skips_cloud_when_token_works(self):
        # with any existing journal token, setup MUST attempt offline
        # login first; success short-circuits before any cloud login
        with TemporaryDirectory() as tmp:
            journal = J.BindJournal(Path(tmp) / "journal.json")
            state = self._state()
            journal.record_derived(
                state, token_hex=state.token_hex,
                bind_key_hex=state.bind_key_hex, a_key_hex=state.a_key_hex,
                factory_did="1234567890123456789",
            )
            journal.record_did_allocated(state, "9876543210123456789")
            journal.record_cloud_signed(
                state, utc=1760000000, cloud_sign_b64="cw==", cloud_cert_b64="Zg=="
            )
            # the charger accepts the journal token: the real offline login
            peer = FakeBleClient(token=bytes.fromhex(state.token_hex))
            with mock.patch(
                "cuktech_pc.blebind.connect", return_value=peer
            ), mock.patch.object(
                cloud, "MiAccount", side_effect=AssertionError("no cloud allowed")
            ):
                rc = cli.main(
                    ["setup", "--journal", str(Path(tmp) / "journal.json")]
                )
            self.assertEqual(rc, 0)
            # the real verify marked the journal bound and verified
            loaded = journal.load()
            self.assertEqual(loaded.stage, "bound")
            self.assertTrue(loaded.bound_verified)

    def test_inconclusive_never_restarts_and_preserves_journal(self):
        # an unreachable device is INCONCLUSIVE — no restart prompt,
        # no cloud construction, journal untouched
        with TemporaryDirectory() as tmp:
            journal = J.BindJournal(Path(tmp) / "journal.json")
            state = self._state()
            journal.record_derived(
                state, token_hex=state.token_hex,
                bind_key_hex=state.bind_key_hex, a_key_hex=state.a_key_hex,
                factory_did="1234567890123456789",
            )
            journal.record_did_allocated(state, "9876543210123456789")
            # cloud material arrived: the device MAY have been told to commit
            journal.record_cloud_signed(state, utc=1, cloud_sign_b64="AA==",
                                        cloud_cert_b64="AA==")
            with mock.patch.object(
                cli, "verify_token_login", return_value=INCONCLUSIVE
            ), mock.patch.object(
                cloud, "MiAccount", side_effect=AssertionError("no cloud allowed")
            ), mock.patch(
                "builtins.input", side_effect=AssertionError("no prompt allowed")
            ):
                rc = cli.main(
                    ["setup", "--journal", str(Path(tmp) / "journal.json")]
                )
            self.assertEqual(rc, 1)
            loaded = journal.load()
            self.assertEqual(loaded.stage, "cloud-signed")
            self.assertEqual(loaded.token_hex, "ab" * 12)

    def test_rejected_declined_consent_keeps_journal(self):
        with TemporaryDirectory() as tmp:
            journal = J.BindJournal(Path(tmp) / "journal.json")
            state = self._state()
            journal.record_derived(
                state, token_hex=state.token_hex,
                bind_key_hex=state.bind_key_hex, a_key_hex=state.a_key_hex,
                factory_did="1234567890123456789",
            )
            journal.record_did_allocated(state, "9876543210123456789")
            inputs = iter(["wrong-typed-value"])  # user declines
            with mock.patch.object(
                cli, "verify_token_login", return_value=REJECTED
            ), mock.patch.object(
                cloud, "MiAccount", side_effect=AssertionError("no cloud allowed")
            ), mock.patch(
                "builtins.input", lambda prompt="": next(inputs)
            ):
                rc = cli.main(
                    ["setup", "--journal", str(Path(tmp) / "journal.json")]
                )
            self.assertEqual(rc, 1)
            # journal untouched: still did-allocated, secrets preserved
            loaded = journal.load()
            self.assertEqual(loaded.stage, "did-allocated")
            self.assertEqual(loaded.token_hex, "ab" * 12)
            self.assertEqual(
                [p.name for p in Path(tmp).iterdir()], ["journal.json"])  # no archive


class ExportAndStatus(unittest.TestCase):
    def test_export_token_requires_verified_bound(self):
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            out = Path(tmp) / "token.json"
            state = J.JournalState(
                mac="AA:BB:CC:DD:EE:FF", model="m", token_hex="ab" * 12,
            )
            J.BindJournal(journal_path).save(state)
            rc = cli.main(
                ["export-token", "--journal", str(journal_path), "--output", str(out)]
            )
            self.assertEqual(rc, 1)  # not bound -> refuse
            self.assertFalse(out.exists())

    def test_export_token_writes_0600_ha_format(self):
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            out = Path(tmp) / "token.json"
            journal = J.BindJournal(journal_path)
            state = J.JournalState(
                mac="AA:BB:CC:DD:EE:FF", model="m", token_hex="ab" * 12,
                stage="bound", bound_verified=True,
            )
            journal.save(state)
            rc = cli.main(
                ["export-token", "--journal", str(journal_path), "--output", str(out)]
            )
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data, {"address": "AA:BB:CC:DD:EE:FF", "token_hex": "ab" * 12})
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
