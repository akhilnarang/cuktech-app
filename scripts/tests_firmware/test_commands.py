import unittest

from cuktech_pc.firmware_commands import describe


class CommandTests(unittest.TestCase):
    def test_protocol_mask_uses_big_endian_and_ack_is_not_readback(self):
        result = describe(bytes.fromhex('fedcba01f1000108 03030f0f'))
        self.assertEqual(result['mask'], 0x03030f0f)
        self.assertTrue(all(enabled for port in result['enabled'].values() for enabled in port.values()))
        self.assertEqual(result['unknown_bits_hex'], '0x00000000')
        self.assertFalse(result['reply_verifies_setting'])
        reverse = describe(bytes.fromhex('fedcba01f1000108 0f0f0303'))
        self.assertFalse(reverse['enabled']['C1']['miPPS'])
        self.assertEqual(reverse['unknown_bits_hex'], '0x0c0c0000')

    def test_single_bits_preserve_protocol_and_port_namespaces(self):
        for bit, port, protocol in ((0,'C1','PD'),(1,'C1','PPS'),(3,'C1','miPPS'),
                                    (11,'C2','miPPS'),(17,'C3','SCP'),(24,'A','UFCS')):
            frame = bytes.fromhex('fedcba01f1000108') + (1 << bit).to_bytes(4, 'big')
            result = describe(frame)
            active = [(p,n) for p, modes in result['enabled'].items() for n,on in modes.items() if on]
            self.assertEqual(active, [(port,protocol)])

    def test_port_inputs_are_booleans_not_a_u32_mask(self):
        result = describe(bytes.fromhex('fedcba01f1000107 000102ff'))
        self.assertEqual(result['ports'], {'C1':False,'C2':True,'C3':True,'A':True})
        self.assertEqual(result['input_bytes'], [0,1,2,255])
        self.assertFalse(result['reply_verifies_setting'])

    def test_setting_validators_and_artwork_query_are_distinct(self):
        self.assertFalse(describe(bytes.fromhex('fedcba01f1000104 00'))['mutation'])
        self.assertTrue(describe(bytes.fromhex('fedcba01f1000104 04'))['accepted_by_validator'])
        self.assertEqual(describe(bytes.fromhex('fedcba01f1000105 05'))['seconds'], 60)
        self.assertEqual(describe(bytes.fromhex('fedcba01f1000105 04'))['seconds'], 0)
        self.assertFalse(describe(bytes.fromhex('fedcba01f1000109 ff'))['mutation'])
        self.assertTrue(describe(bytes.fromhex('fedcba01f1000109 01'))['mutation'])

    def test_only_exact_known_requests_are_admitted(self):
        for text in ('fedcba01f1000102', 'fedcba01f1000200'):
            self.assertFalse(describe(bytes.fromhex(text))['mutation'])
        for text in ('fedcba01f10001','fedcba01f1000102ef','fedcba01f1000108000000',
                     'fedcba01f100010800000000ef','fedcba01f100010a','fedcba01f100040a10',
                     'fedcba01f2000102','00dcba01f1000102'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                describe(bytes.fromhex(text))


if __name__ == '__main__':
    unittest.main()
