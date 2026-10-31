# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT
"""Reuse one managed OpenSSL installation without copying its libraries."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from native_provider import source_layout


class ProviderLayoutTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def prefix(self, windows=False):
        prefix = self.root / 'installed provider'
        (prefix / 'lib').mkdir(parents=True)
        (prefix / 'include').mkdir()
        (prefix / 'LICENSE.txt').write_text('test license')
        (prefix / 'bin').mkdir()
        extension = '.lib' if windows else '.a'
        for name in ('libssl', 'libcrypto'):
            (prefix / 'lib' / (name + extension)).write_bytes(b'unchanged provider')
        (prefix / 'bin' / ('openssl.exe' if windows else 'openssl')).write_bytes(b'fixture CLI')
        return prefix

    def test_prefix_view_borrows_original_library_bytes(self):
        prefix = self.prefix()
        view = source_layout(prefix, self.root / 'view', False)
        for name in ('libssl.a', 'libcrypto.a'):
            self.assertTrue((view / name).is_symlink())
            self.assertEqual((view / name).resolve(), prefix / 'lib' / name)
        self.assertEqual((view / 'include').resolve(), prefix / 'include')
        self.assertEqual((view / 'apps/openssl').resolve(), prefix / 'bin/openssl')

    def test_windows_archive_names_share_the_same_prefix(self):
        prefix = self.prefix(True)
        view = source_layout(prefix, self.root / 'view', True)
        self.assertEqual((view / 'libssl.lib').resolve(), prefix / 'lib/libssl.lib')
        self.assertEqual((view / 'apps/openssl.exe').resolve(), prefix / 'bin/openssl.exe')

    def test_incomplete_prefix_cannot_create_a_partial_view(self):
        prefix = self.prefix()
        (prefix / 'lib/libcrypto.a').unlink()
        with self.assertRaises(ValueError):
            source_layout(prefix, self.root / 'view', False)
        self.assertFalse((self.root / 'view').exists())

    def test_source_layout_needs_no_view_or_copy(self):
        source = self.root / 'source'
        source.mkdir()
        for name in ('libssl.a', 'libcrypto.a'):
            (source / name).write_bytes(b'existing source-layout provider')
        self.assertEqual(source_layout(source, self.root / 'unused', False), source)
        self.assertFalse((self.root / 'unused').exists())


if __name__ == '__main__':
    unittest.main()
