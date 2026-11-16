"""The v2 register state machine against a scripted fake BLE charger.

Covers: the wire order of the register, the 18-byte parcel frames, the
0x12 and auth-error outcomes, the greeting echo and log redaction.
"""


import asyncio
import base64
import logging
import unittest

from cuktech_pc import crypto
from cuktech_pc.blebind import AVDTP_UUID, UPNP_UUID, V2RegisterClient
from tests.fakepeer import DEVINFO, FakeBleClient

SIGN = bytes(range(64))
CERT = bytes.fromhex("30 82 01 77") + bytes(range(96))


def run(coro):
    return asyncio.run(coro)


async def _exchange(reg: V2RegisterClient):
    """Drive the client up to (and including) the ECDH exchange."""
    devinfo = await reg.get_devinfo()
    await reg.send_caps_echo(devinfo)
    priv, pub = crypto.generate_keypair()
    await reg.send_pubkey(crypto.public_key_to_bytes(pub))
    peer = await reg.recv_peer_pubkey()
    shared = crypto.ecdh_shared(priv, crypto.bytes_to_public_key(peer))
    return devinfo, crypto.derive_register(shared)


def make_client(peer: FakeBleClient) -> V2RegisterClient:
    return V2RegisterClient(peer, timeout=1.0)


class HappyPath(unittest.TestCase):
    def test_full_v2_order(self):
        peer = FakeBleClient(outcome="ok")

        async def scenario():
            reg = make_client(peer)
            async with reg:
                devinfo, secrets = await _exchange(reg)
                blob = crypto.build_bind_blob(
                    crypto.normalize_did("12345678901234567"),
                    SIGN, 1760000000, secrets.a_key,
                )
                await reg.write_bind_result(True)
                await reg.send_bind_blob(blob)
                await reg.send_cloud_cert(CERT)
                outcome = await reg.wait_final(timeout=1.0)
                return devinfo, secrets, blob, outcome

        devinfo, secrets, blob, outcome = run(scenario())
        self.assertEqual(outcome, "ok")
        self.assertEqual(devinfo.factory_did_text, "1234567890123456789")
        # the device received exactly our blob and cert
        self.assertEqual(peer._got_blob, blob)
        self.assertEqual(peer._got_cert, CERT)
        # order: 0x13, then the code-0 announcement, then the code-7
        # announcement. Match the exact 6-byte announcement frames.
        seq = peer.writes
        idx_13 = seq.index((UPNP_UUID, bytes.fromhex("13 00 00 00")))
        ann0 = seq.index((AVDTP_UUID, bytes.fromhex("00 00 00 00 06 00")))  # 92 B / 18
        ann7 = seq.index((AVDTP_UUID, bytes.fromhex("00 00 00 07 06 00")))  # 100 B / 18
        self.assertLess(idx_13, ann0)
        self.assertLess(ann0, ann7)

    def test_greeting_challenges_echoed(self):
        peer = FakeBleClient(token=bytes(range(12)))

        async def scenario():
            reg = make_client(peer)
            async with reg:
                await reg.greet()
                # the fake sends 00 00 04 01 and 00 00 04 02
                echoes = [
                    p for (u, p) in peer.writes
                    if u == AVDTP_UUID and p[:3] == b"\x00\x00\x05"
                ]
                self.assertEqual(
                    echoes,
                    [bytes.fromhex("00 00 05 01"), bytes.fromhex("00 00 05 02")],
                )

        run(scenario())


    def test_caps_echo_returns_the_device_caps_bytes_in_order(self):
        # caps_in_out 0x10 (no input caps in the low nibble) and caps2 0x20
        peer = FakeBleClient(devinfo=b"\x02\x00\x10\x20" + bytes(1) + b"1234567890123456789")

        async def scenario():
            async with make_client(peer) as reg:
                await reg.send_caps_echo(await reg.get_devinfo())

        run(scenario())
        self.assertEqual(peer.writes[-1], (UPNP_UUID, bytes.fromhex("15 10 20")))


class ParcelChunking(unittest.TestCase):
    def test_non_last_frames_are_2_plus_18_bytes(self):
        peer = FakeBleClient()

        async def scenario():
            reg = make_client(peer)
            async with reg:
                _, secrets = await _exchange(reg)
                blob = crypto.build_bind_blob(
                    crypto.normalize_did("1" * 19), SIGN, 5, secrets.a_key
                )
                await reg.write_bind_result(True)
                await reg.send_bind_blob(blob)
                await reg.send_cloud_cert(CERT)
                await reg.wait_final(timeout=1.0)

        run(scenario())
        # fw 0x41eeb4 drops a non-last frame that is not 2 + 18 bytes.
        # Frame = 2-byte LE index + chunk. 92 B = 5 x 18 + 2; 100 B = 5 x 18 + 10.
        for code, last_len in ((0x00, 2 + 2), (0x07, 2 + 10)):
            frames = peer.parcel_frames[code]
            self.assertEqual(
                [len(f) for f in frames], [20, 20, 20, 20, 20, last_len]
            )
            self.assertEqual(
                [f[:2] for f in frames],
                [bytes([i, 0]) for i in range(1, 7)],
            )


class DeviceOutcomes(unittest.TestCase):
    def _run_bind(self, outcome: str):
        peer = FakeBleClient(outcome=outcome)

        async def scenario():
            reg = make_client(peer)
            async with reg:
                _, secrets = await _exchange(reg)
                blob = crypto.build_bind_blob(
                    crypto.normalize_did("1" * 19), SIGN, 5, secrets.a_key
                )
                await reg.write_bind_result(True)
                await reg.send_bind_blob(blob)
                await reg.send_cloud_cert(CERT)
                return await reg.wait_final(timeout=0.3)

        return run(scenario()), peer

    def test_device_reject_0x12(self):
        outcome, peer = self._run_bind("reject")
        self.assertEqual(outcome, "fail")

    def test_auth_error_e1(self):
        outcome, _ = self._run_bind("e1")
        self.assertEqual(outcome, "auth-error")


class LogRedaction(unittest.TestCase):
    def test_no_secrets_in_debug_logs(self):
        peer = FakeBleClient(outcome="ok")
        records: list[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = Capture()
        logger = logging.getLogger("cuktech_pc")
        old_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        secrets_holder: dict[str, bytes] = {}

        async def scenario():
            reg = make_client(peer)
            async with reg:
                _, secrets = await _exchange(reg)
                secrets_holder["token"] = secrets.token
                secrets_holder["bind_key"] = secrets.bind_key
                secrets_holder["a_key"] = secrets.a_key
                blob = crypto.build_bind_blob(
                    crypto.normalize_did("1" * 19), SIGN, 5, secrets.a_key
                )
                await reg.write_bind_result(True)
                await reg.send_bind_blob(blob)
                await reg.send_cloud_cert(CERT)
                await reg.wait_final(timeout=1.0)

        try:
            run(scenario())
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)

        joined = "\n".join(records)
        for name, value in secrets_holder.items():
            self.assertNotIn(value.hex(), joined, f"{name} hex leaked to logs")
            self.assertNotIn(base64.b64encode(value).decode(), joined)
        self.assertNotIn(SIGN.hex(), joined)  # cloud_sign never logged
        self.assertNotIn(base64.b64encode(CERT).decode(), joined)
        self.assertNotIn(DEVINFO.hex(), joined)  # device info kept out too


if __name__ == "__main__":
    unittest.main()
