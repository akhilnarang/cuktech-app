"""Malformed-container and reconstructed-memory checks; no network or hardware."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from cuktech_pc.firmware_unpack import expand_startup_lz, parse_package, parse_region, compressed_streams, unpack, decode_alpha_runs, font_assets, grayscale_png, source_map
from tests_firmware.fixtures import image as signed_fixture, raw_image, signed_package


class StartupDecoderTests(unittest.TestCase):
    def test_literals_and_overlapping_back_reference(self):
        decoded, used=expand_startup_lz(b'\x40\x04ABC\x03padding',9)
        self.assertEqual(decoded,b'ABCABCABC')
        self.assertEqual(used,6)

    def test_extended_match_count_and_zero_literal_run(self):
        decoded,used=expand_startup_lz(b'\x02\x00X\x01\x08\x01',11)
        self.assertEqual(decoded,b'X'*11)
        self.assertEqual(used,6)

    def test_long_distance_high_byte(self):
        literal=bytes(range(254))
        encoded=b'\x00\xff\x00'+literal+b'\x03\x00XY'+b'\x1d\x00\x01'
        decoded,_=expand_startup_lz(encoded,259)
        self.assertEqual(decoded,literal+b'XY'+literal[:3])

    def test_bad_distance_and_truncation_rejected(self):
        for encoded,expected in [(b'\x11\x00',3),(b'\x11\x01',3),(b'\x02\x00',1),(b'\x00\x00\x00',1)]:
            with self.subTest(encoded=encoded),self.assertRaises(ValueError):
                expand_startup_lz(encoded,expected)

    def test_declared_output_is_enforced(self):
        with self.assertRaises(ValueError):
            expand_startup_lz(b'\x40\x04ABC\x03',8)


class UnpackTests(unittest.TestCase):
    def test_signed_components_recombine_byte_for_byte(self):
        image=signed_fixture()
        parsed=parse_package(image)
        self.assertTrue(parsed['signed'])
        components=parsed['components'][:3]
        rebuilt=image[:parsed['firmware_size']]+b''.join(image[c['offset']:c['offset']+c['size']] for c in components)
        self.assertEqual(rebuilt,image)
        self.assertEqual(parsed['product_id'],0x660e)

    def test_malformed_signing_bounds_and_tlv_rejected(self):
        tlv_overrun=bytearray(signed_fixture());tlv_overrun[1053]=255  # Length byte of the first TLV.
        rows=[(signed_fixture(cert_size=65535),'boundaries'),(signed_fixture()[:1040],'truncated Xiaomi signing header'),
              (bytes(tlv_overrun),'outside signing tag'),(b'X'*1024,'R2SF'),(signed_fixture(tag_size=31),'boundaries')]
        for malformed,message in rows:
            with self.subTest(message=message),self.assertRaisesRegex(ValueError,message):parse_package(malformed)
        # TLV region with one stray byte after the last TLV
        stray=signed_fixture(tlv=b'\x01\x05\x02\x01\x02\x49\x00'+b'\x04\x14njcuk.fitting.ad1204'+b'\x07')
        with self.assertRaisesRegex(ValueError,'truncated TLV header'):parse_package(stray)

    def test_verify_rejects_forged_packages_and_writes_nothing(self):
        rows=[('image','developer/image signature verification failed'),
              ('developer','developer/image signature verification failed'),
              ('one-certificate','expected two packaged certificates')]
        for forge,message in rows:
            with self.subTest(forge=forge),tempfile.TemporaryDirectory() as temp:
                source=Path(temp)/'package.bin';source.write_bytes(signed_package(forge))
                with self.assertRaisesRegex(ValueError,message):unpack(source,Path(temp)/'out',verify=True)
                self.assertFalse((Path(temp)/'out').exists())
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'package.bin';source.write_bytes(signed_package())
            result=unpack(source,Path(temp)/'out',verify=True)
            self.assertTrue(result['signature_verification']['image_and_tag'])

    def test_raw_roundtrip_and_manifest_digests(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'image.bin';source.write_bytes(raw_image())
            output=Path(temp)/'out'
            result=unpack(source,output,['0:16:header'])
            self.assertFalse(result['signed'])
            self.assertEqual((output/'firmware.bin').read_bytes(),source.read_bytes())
            self.assertEqual((output/'region-header.bin').read_bytes(),source.read_bytes()[:16])
            manifest=json.loads((output/'manifest.json').read_text())
            for item in manifest['outputs']:
                content=(output/item['name']).read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(),item['sha256'])

    def test_existing_output_cannot_overwrite_files(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'image.bin';source.write_bytes(raw_image())
            with self.assertRaises(ValueError):unpack(source,Path(temp))

    def test_region_traversal_and_out_of_range_rejected(self):
        for region in ['0:4:../escape','1020:8:past','-1:8:negative','0:0:empty']:
            with self.subTest(region=region),self.assertRaises(ValueError):parse_region(region,1024)

    def test_complete_compressed_stream_and_false_headers(self):
        content=b'firmware resource '*20
        encoded=zlib.compress(content)
        found=list(compressed_streams(b'bad\x78\x9cgarbage'+encoded+b'tail'))
        self.assertEqual(len(found),1)
        self.assertEqual(found[0][1],content)
        self.assertEqual(found[0][0]['size'],len(encoded))

    def test_truncated_compressed_stream_is_not_extracted(self):
        self.assertEqual(list(compressed_streams(zlib.compress(b'a'*100)[:-2])),[])

    def test_font_descriptor_and_alpha_run_boundaries(self):
        payload=bytearray(raw_image())
        struct.pack_into('<III',payload,128,2,1,0x403000+160)
        struct.pack_into('<III',payload,160,65,3,0x403000+176)
        payload[176:180]=b'\x00\x02\xff\x04'
        fonts=font_assets(bytes(payload),0x403000)
        self.assertEqual(len(fonts),1)
        self.assertEqual(fonts[0]['glyphs'][0]['source_size'],4)
        pixels,used=decode_alpha_runs(payload[176:],6)
        self.assertEqual((pixels,used),(b'\0\0\xff\xff\xff\xff',4))
        payload[179]=5
        self.assertEqual(font_assets(bytes(payload),0x403000),[])

    def test_png_pixels_and_chunk_crc_roundtrip(self):
        encoded=grayscale_png(b'\0\xff\x80\x40',2,2)
        self.assertEqual(encoded[:8],b'\x89PNG\r\n\x1a\n')
        cursor=8;compressed=b''
        while cursor<len(encoded):
            size=struct.unpack_from('>I',encoded,cursor)[0]
            kind=encoded[cursor+4:cursor+8];data=encoded[cursor+8:cursor+8+size]
            stored=struct.unpack_from('>I',encoded,cursor+8+size)[0]
            self.assertEqual(zlib.crc32(kind+data)&0xffffffff,stored)
            if kind==b'IDAT':compressed+=data
            cursor+=12+size
        self.assertEqual(zlib.decompress(compressed),b'\0\0\xff\0\x80\x40')

    def test_source_map_uses_union_not_sum_and_preserves_unknown_bytes(self):
        data = bytes(range(32))
        layout = source_map(data, 0x403000, [
            {"offset": 4, "size": 8, "kind": "one"},
            {"offset": 8, "size": 8, "kind": "shared"},
            {"offset": 16, "size": 4, "kind": "adjacent"},
        ])
        self.assertEqual(layout['classified_source_bytes'], 16)
        self.assertEqual(layout['unclassified_source_bytes'], 16)
        self.assertEqual([(r['offset'], r['size']) for r in layout['unclassified_ranges']], [(0, 4), (20, 12)])
        self.assertEqual(source_map(data, 0, [])['unclassified_source_bytes'], 32)
        for offset, size in [(-1, 1), (0, 0), (31, 2)]:
            with self.assertRaises(ValueError):
                source_map(data, 0, [{"offset": offset, "size": size, "kind": "bad"}])

    def test_unified_extraction_assets_and_unclassified_chunks_roundtrip(self):
        data = bytearray(raw_image())
        struct.pack_into('<III', data, 128, 2, 1, 0x403000 + 160)
        struct.pack_into('<III', data, 160, 65, 3, 0x403000 + 176)
        data[176:180] = b'\x00\x02\xff\x04'
        struct.pack_into('<HHHHI', data, 192, 2, 1, 16, 1, 0x403000 + 208)
        data[208:212] = bytes.fromhex('0201 00f8')
        with tempfile.TemporaryDirectory() as temp:
            source, out = Path(temp) / 'image.bin', Path(temp) / 'out'
            source.write_bytes(data)
            # Admit a small synthetic descriptor fixture to exercise the common
            # exporter. Production admission remains pinned to the real hash.
            with patch('cuktech_pc.firmware_unpack.KNOWN_AD1204_0073_SHA256', hashlib.sha256(data).hexdigest()):
                result = unpack(source, out, assets=True, split_unclassified=True)
            self.assertEqual(result['asset_summary']['glyphs'], 1)
            self.assertEqual(result['asset_summary']['color_bitmaps'], 1)
            layout = json.loads((out / 'source-map.json').read_text(encoding='utf-8'))
            reconstructed, covered = bytearray(len(data)), bytearray(len(data))
            for row in result['outputs']:
                content = (out / row['name']).read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(), row['sha256'])
                # Only exact raw slices participate, not derived pixel/JSON
                # outputs that share the same provenance start offset.
                start = row['source_offset']
                if row['name'] == 'firmware.bin' or start is None or content != data[start:start + len(content)]:
                    continue
                reconstructed[start:start + len(content)] = content
                covered[start:start + len(content)] = b'\x01' * len(content)
            self.assertEqual(reconstructed, data)
            self.assertTrue(all(covered))
            self.assertEqual(layout['classified_source_bytes'] + layout['unclassified_source_bytes'], len(data))
            for row in layout['unclassified_ranges']:
                self.assertEqual((out / row['file']).read_bytes(), data[row['offset']:row['offset'] + row['size']])
            self.assertIn('assets/color/index.html', (out / 'index.html').read_text(encoding='utf-8'))

    def test_unrecognized_image_keeps_color_profile_unclaimed(self):
        with tempfile.TemporaryDirectory() as temp:
            source, out = Path(temp) / 'image.bin', Path(temp) / 'out'
            source.write_bytes(raw_image())
            result = unpack(source, out, assets=True)
            self.assertEqual(result['asset_summary']['color_bitmaps'], 0)
            self.assertIn('unsupported', result['asset_summary']['color_profile'])
            self.assertFalse((out / 'unclassified').exists())


if __name__=='__main__':unittest.main()
