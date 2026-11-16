"""Staged journal: atomic 0600 persistence, monotonic stages, resume matrix."""


import os
import tempfile
import unittest
from pathlib import Path

from cuktech_pc import journal as J


def make_state(**over):
    base = dict(mac="AA:BB:CC:DD:EE:FF", model="njcuk.fitting.ad1204")
    base.update(over)
    return J.JournalState(**base)


class PersistenceMechanics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "journal.json"
        self.journal = J.BindJournal(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_load_missing_returns_none(self):
        self.assertIsNone(self.journal.load())

    def test_corrupt_journal_refuses_rather_than_clobbers(self):
        self.path.write_text("{not json")
        os.chmod(self.path, 0o600)  # pass the mode check: reach the JSON parse
        with self.assertRaises(J.JournalError) as ctx:
            self.journal.load()
        self.assertIn("unreadable", str(ctx.exception))
        self.assertIn("not json", self.path.read_text())  # untouched

    def test_stage_monotonicity_enforced(self):
        state = make_state()
        self.journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="d" * 19,
        )
        self.journal.record_did_allocated(state, "9876543210123456789")
        with self.assertRaises(J.JournalError):  # "derived" is a step back
            self.journal.record_derived(
                state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
                a_key_hex="ef" * 16, factory_did="d" * 19,
            )

    def test_full_ladder(self):
        state = make_state()
        self.journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="d" * 19,
        )
        self.journal.record_did_allocated(state, "9876543210123456789")
        self.journal.record_cloud_signed(
            state, utc=1760000000, cloud_sign_b64="cw==", cloud_cert_b64="Zg=="
        )
        self.journal.record_device_committed(state)
        self.journal.record_bound_verified(state)
        loaded = self.journal.load()
        self.assertEqual(loaded.stage, "bound")
        self.assertTrue(loaded.bound_verified)
        self.assertEqual(loaded.device_committed, "yes")
        self.assertEqual(loaded.cloud_bind, "standard_bind")

    def test_failure_records_never_lose_secrets_or_stage(self):
        state = make_state()
        self.journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="d" * 19,
        )
        self.journal.record_failure(state, "cloud-bind", "boom")
        loaded = self.journal.load()
        self.assertEqual(loaded.stage, "derived")
        self.assertEqual(loaded.token_hex, "ab" * 12)
        self.assertEqual(len(loaded.attempts), 1)

    def test_unknown_outcome_marks_device_committed_unknown(self):
        state = make_state()
        self.journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="d" * 19,
        )
        self.journal.record_device_confirm_pending(state)
        self.journal.record_unknown_outcome(state, "timeout")
        loaded = self.journal.load()
        self.assertEqual(loaded.device_committed, "unknown")
        self.assertTrue(loaded.attempts[-1]["note"].startswith("unknown outcome: timeout"))
        self.assertEqual(loaded.cloud_bind, "no")  # cloud never reached


class ResumeMatrix(unittest.TestCase):
    """A re-run must never blindly restart the ECDH/cloud sequence."""

    def test_no_journal_is_fresh(self):
        self.assertEqual(J.resume_action(None)[0], "fresh")

    def test_bound_verified_is_verify_only(self):
        state = make_state(stage="bound", token_hex="ab" * 12, bound_verified=True)
        self.assertEqual(J.resume_action(state)[0], "verify-only")

    def test_any_token_requires_verify_first(self):
        for stage in ("derived", "did-allocated", "cloud-signed", "device-committed", "bound"):
            for cloud_bind in ("no", "applydid", "standard_bind"):
                state = make_state(
                    stage=stage, token_hex="ab" * 12, cloud_bind=cloud_bind
                )
                action, reason = J.resume_action(state)
                self.assertEqual(
                    action, "verify-first", f"{stage}/{cloud_bind}: {reason}"
                )

    def test_reason_distinguishes_fresh_safe_from_explicit_consent(self):
        safe = make_state(stage="derived", token_hex="ab" * 12, cloud_bind="no")
        unsafe = make_state(
            stage="did-allocated", token_hex="ab" * 12, cloud_bind="applydid"
        )
        self.assertIn("not automatic", J.resume_action(unsafe)[1])  # explicit-consent hint
        self.assertIn("safe", J.resume_action(safe)[1])

    def test_no_token_is_fresh(self):
        state = make_state(stage="derived", token_hex="")
        self.assertEqual(J.resume_action(state)[0], "fresh")

    def test_recovery_text_is_manual_and_names_server_did(self):
        state = make_state(stage="cloud-signed", token_hex="ab" * 12,
                           cloud_bind="standard_bind", server_did="9876543210123456789")
        text = J.recovery_instructions(state)
        self.assertIn("manual", text.lower())
        self.assertIn("factory-reset", text)
        self.assertIn("did=9876543210123456789", text)


if __name__ == "__main__":
    unittest.main()
