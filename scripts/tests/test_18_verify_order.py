"""Offline verification runs the real login in Mi Home's order (live
2026-10-12: subscribe-both-first login timed out on a bound charger)."""


import asyncio
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cuktech_pc import blebind, cli
from cuktech_pc.journal import BindJournal, JournalState
from tests.fakepeer import FakeBleClient

TOKEN = bytes(range(12))
UPNP = blebind.UPNP_UUID


class _OrderedPeer(FakeBleClient):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.events: list[str] = []

    async def start_notify(self, uuid, handler, **kw):
        self.events.append(f"sub:{uuid[4:8]}")
        await super().start_notify(uuid, handler, **kw)

    async def write_gatt_char(self, uuid, data, response=False):
        if bytes(data) == b"\xa4":
            self.events.append("greet")
        await super().write_gatt_char(uuid, data, response)


class VerifyOrder(unittest.TestCase):
    def _verify(self, peer):
        with TemporaryDirectory() as tmp:
            journal = BindJournal(Path(tmp) / "journal.json")
            state = JournalState(mac="AA:BB:CC:DD:EE:FF", model="m",
                                 token_hex=TOKEN.hex())
            journal.record_derived(state, token_hex=TOKEN.hex(),
                                   bind_key_hex="cd" * 16,
                                   a_key_hex="ef" * 16,
                                   factory_did="1234567890123456789")

            async def fake_connect(*a, **k):
                return peer

            with mock.patch.object(blebind, "connect", fake_connect):
                return asyncio.run(cli.verify_token_login(
                    state.mac, TOKEN, journal, state))

    def test_bound_token_verifies_with_upnp_after_greeting(self):
        peer = _OrderedPeer(token=TOKEN)
        self.assertEqual(self._verify(peer), cli.VERIFIED)
        self.assertEqual(peer.events[:3], ["sub:0019", "greet", "sub:0010"])

    def test_e0_is_not_registered(self):
        peer = _OrderedPeer(token=TOKEN, login_error=bytes.fromhex("e0000000"))
        self.assertEqual(self._verify(peer), cli.NOT_REGISTERED)

    def test_wrong_token_is_rejected(self):
        peer = _OrderedPeer(token=b"\x99" * 12)  # charger holds another token
        self.assertEqual(self._verify(peer), cli.REJECTED)
