"""Tests for hardlink.db path resolution, global attach fallback, and CDN helpers."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util import Padding

from decode_image import (
    HardlinkIndex,
    build_cdn_download_urls,
    dat_file_priority,
    decrypt_cdn_payload,
    extract_image_cdn_info,
    find_dat_files,
    rank_dat_paths,
    select_best_dat_path,
)


class DatPriorityTests(unittest.TestCase):
    def test_plain_dat_beats_thumbnail(self):
        self.assertLess(
            dat_file_priority("abc123.dat", "abc123"),
            dat_file_priority("abc123_t.dat", "abc123"),
        )

    def test_hd_beats_thumbnail(self):
        self.assertLess(
            dat_file_priority("abc123_h.dat", "abc123"),
            dat_file_priority("abc123_t.dat", "abc123"),
        )

    def test_rank_prefers_larger_same_tier(self):
        paths = [
            "/tmp/abc123_t.dat",
            "/tmp/abc123.dat",
            "/tmp/abc123_h.dat",
        ]
        sizes = {
            paths[0]: 1000,
            paths[1]: 5000,
            paths[2]: 8000,
        }
        with patch("decode_image.os.path.getsize", side_effect=lambda p: sizes[p]):
            ranked = rank_dat_paths(paths, "abc123")
        self.assertEqual(os.path.basename(ranked[0]), "abc123.dat")
        self.assertEqual(os.path.basename(ranked[1]), "abc123_h.dat")

    def test_select_best_returns_none_for_empty(self):
        self.assertIsNone(select_best_dat_path([], "abc"))


def _make_hardlink_db(path, rows):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE dir2id (rowid INTEGER PRIMARY KEY, username TEXT)")
    conn.execute(
        "CREATE TABLE image_hardlink_info_v4 ("
        "md5_hash INTEGER, md5 TEXT, type INTEGER, file_name TEXT, "
        "file_size INTEGER, modify_time INTEGER, dir1 INTEGER, dir2 INTEGER)"
    )
    conn.execute("INSERT INTO dir2id (rowid, username) VALUES (1, 'chathash1')")
    conn.execute("INSERT INTO dir2id (rowid, username) VALUES (2, '2026-06')")
    for md5_hash, md5, typ, fname, fsize, mtime, d1, d2 in rows:
        conn.execute(
            "INSERT INTO image_hardlink_info_v4 VALUES (?,?,?,?,?,?,?,?)",
            (md5_hash, md5, typ, fname, fsize, mtime, d1, d2),
        )
    conn.commit()
    conn.close()


class HardlinkIndexTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.attach = os.path.join(self.base, "msg", "attach", "chathash1", "2026-06", "Img")
        os.makedirs(self.attach, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_lookup_builds_existing_paths(self):
        md5 = "deadbeef" * 2
        dat_path = os.path.join(self.attach, f"{md5}_h.dat")
        with open(dat_path, "wb") as f:
            f.write(b"\x00" * 128)

        db_path = os.path.join(self._tmp.name, "hardlink.db")
        _make_hardlink_db(db_path, [
            (1, "hlmd5", 2, f"{md5}_h.dat", 128, 1, 1, 2),
        ])
        idx = HardlinkIndex(db_path, self.base)
        found = idx.lookup_dat_paths(md5)
        self.assertEqual(found, [dat_path])

    def test_lookup_ignores_missing_files(self):
        md5 = "cafebabe" * 2
        db_path = os.path.join(self._tmp.name, "hardlink.db")
        _make_hardlink_db(db_path, [
            (1, "hlmd5", 2, f"{md5}.dat", 64, 1, 1, 2),
        ])
        idx = HardlinkIndex(db_path, self.base)
        self.assertEqual(idx.lookup_dat_paths(md5), [])


class FindDatFilesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.attach_root = os.path.join(self.base, "msg", "attach")

    def tearDown(self):
        self._tmp.cleanup()

    def _touch(self, chat_hash, month, fname):
        d = os.path.join(self.attach_root, chat_hash, month, "Img")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, fname)
        with open(path, "wb") as f:
            f.write(b"\x00" * 64)
        return path

    def test_global_fallback_when_username_hash_missing(self):
        md5 = "a" * 32
        expected = self._touch("otherhash", "2026-05", f"{md5}.dat")
        found = find_dat_files(
            md5,
            wechat_base_dir=self.base,
            username="wxid_not_matching",
        )
        self.assertIn(expected, found)

    def test_hardlink_takes_priority_over_glob(self):
        md5 = "b" * 32
        hardlink_path = self._touch("hlhash", "2026-06", f"{md5}_h.dat")
        self._touch("globhash", "2026-06", f"{md5}_t.dat")

        db_path = os.path.join(self._tmp.name, "hardlink.db")
        _make_hardlink_db(db_path, [
            (1, "x", 2, f"{md5}_h.dat", 999, 1, 1, 2),
        ])
        # fix dir mapping: rowid 1 -> hlhash
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM dir2id")
        conn.execute("INSERT INTO dir2id (rowid, username) VALUES (1, 'hlhash')")
        conn.execute("INSERT INTO dir2id (rowid, username) VALUES (2, '2026-06')")
        conn.commit()
        conn.close()

        # recreate file at corrected path
        hardlink_path = self._touch("hlhash", "2026-06", f"{md5}_h.dat")
        found = find_dat_files(
            md5,
            wechat_base_dir=self.base,
            hardlink_db=db_path,
        )
        self.assertEqual(found[0], hardlink_path)


class CdnHelperTests(unittest.TestCase):
    def test_extract_image_cdn_info_from_xml(self):
        xml = (
            '<msg><img aeskey="ab" cdnbigimgurl="BIGTOKEN" '
            'cdnmidimgurl="MIDTOKEN" cdnthumburl="THUMB" length="12345" '
            'md5="c" * 32 /></msg>'
        )
        xml = xml.replace('"c" * 32', '"' + ("c" * 32) + '"')
        info = extract_image_cdn_info(xml)
        self.assertEqual(info["aes_key"], "ab")
        self.assertEqual(info["big_url"], "BIGTOKEN")
        self.assertEqual(info["mid_url"], "MIDTOKEN")
        self.assertEqual(info["length"], 12345)

    def test_build_cdn_download_urls_for_http_and_token(self):
        http_urls = build_cdn_download_urls("https://cdn.example/img")
        self.assertEqual(http_urls, ["https://cdn.example/img"])
        token_urls = build_cdn_download_urls("3057020100abcd")
        self.assertTrue(any("3057020100abcd" in u for u in token_urls))

    def test_decrypt_cdn_payload_roundtrip(self):
        key_hex = "0123456789abcdef0123456789abcdef"
        key = bytes.fromhex(key_hex)
        plain = b"\xff\xd8\xff" + b"JPGDATA"
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        enc = cipher.encrypt(Padding.pad(plain, AES.block_size))
        out = decrypt_cdn_payload(enc, key_hex)
        self.assertEqual(out, plain)


if __name__ == "__main__":
    unittest.main()