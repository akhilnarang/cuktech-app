import unittest
from cuktech_pc.firmware_blob_inventory import body_ranges, union_size


class BlobInventoryTests(unittest.TestCase):
    def test_union_accounts_for_shared_bodies_and_adjacency(self):
        self.assertEqual(union_size([(4,12),(8,16),(0,5),(16,20)]),20)
        self.assertEqual(union_size([(0,0),(4,8),(10,11)]),5)
        self.assertEqual(union_size([]),0)
        with self.assertRaises(ValueError):
            union_size([(2,1)])

    def test_inclusive_export_ranges_exclude_external_addresses(self):
        self.assertEqual(body_ranges('[[00403000, 0040300f] [00201344, 002013af] [00403020, 0040302f]]',0x403000,64),[(0,16),(32,48)])
        self.assertEqual(body_ranges('[[00403000, 00404000]]',0x403000,64),[])


if __name__ == '__main__':
    unittest.main()
