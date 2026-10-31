# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Source-distribution boundary checks independent of SDK/provider builds."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import copy

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/release_source.py'
SPEC=importlib.util.spec_from_file_location('tls_release_source',SCRIPT)
RELEASE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(RELEASE)

class SourceDistributionTests(unittest.TestCase):
    def test_receipt_requires_moved_consumer_and_public_sdk_compiler(self):
        row={'portable_git_dependencies':'passed','relocated_consumer':'passed','sanitized':True,'acceptance':{
            'status':'passed','compiler_origin':'public-sdk','sdk_version':'1.0.2',
            'compiler_sha256':'a'*64,'sdk_compiler_sha256':'a'*64,
            'tests':{'passed':39,'failed':0},'isolated_replays':39,'native_cases':[{}]*73,
            'source_fallback_disabled':True,'production_fixture_imports':[],
            'native_production_fixture_symbols':[]}}
        RELEASE.validate_acceptance(row,'linux-x86_64','1.0.2')
        for field,value in [('portable_git_dependencies','failed'),('relocated_consumer','failed'),('sanitized',False)]:
            changed=copy.deepcopy(row);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                RELEASE.validate_acceptance(changed,'linux-x86_64','1.0.2')
        for field,value in [('status','failed'),('compiler_sha256','b'*64),('native_production_fixture_symbols',['nyra_tls_test_malloc'])]:
            changed=copy.deepcopy(row);changed['acceptance'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                RELEASE.validate_acceptance(changed,'linux-x86_64','1.0.2')

    def source(self,root):
        source=root/'source';source.mkdir()
        subprocess.run(['git','init',source],check=True,capture_output=True)
        (source/'package.yaml').write_text('name: tls\nversion: 0.2.0\ndependencies:\n  net_core:\n    git: https://github.com/nylang/netcore.git\n    rev: '+('e'*40)+'\n')
        (source/'entry.ny').write_text('/** @brief Public test input. */\n')
        (source/'secret-untracked').write_text('must not ship')
        subprocess.run(['git','-C',source,'add','package.yaml','entry.ny'],check=True,capture_output=True)
        return source
    def test_only_tracked_sources_and_portable_dependency_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=self.source(root);target=root/'tls'
            RELEASE.prepare_tree(source,target,'tls')
            manifest=(target/'package.yaml').read_text()
            self.assertTrue(manifest.startswith('name: tls\n'))
            self.assertIn('git: https://github.com/nylang/netcore.git',manifest)
            self.assertNotIn('path:',manifest)
            self.assertEqual(manifest,(source/'package.yaml').read_text())
            self.assertNotIn('stdlib:',manifest)
            self.assertFalse((target/'secret-untracked').exists())
            self.assertFalse((target/'.git').exists())
            self.assertEqual((target/'entry.ny').read_bytes(),(source/'entry.ny').read_bytes())
            self.assertEqual(set(RELEASE.tested_sources(source)),{'package.yaml','entry.ny'})
    def test_net_core_identity_survives_file_iteration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=self.source(root);target=root/'net_core'
            RELEASE.prepare_tree(source,target,'net_core')
            manifest=(target/'package.yaml').read_text()
            self.assertEqual(manifest,(source/'package.yaml').read_text())
    def test_tracked_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=self.source(root)
            try:(source/'link').symlink_to('entry.ny')
            except OSError:self.skipTest('symbolic links unavailable')
            subprocess.run(['git','-C',source,'add','link'],check=True,capture_output=True)
            with self.assertRaises(ValueError):RELEASE.prepare_tree(source,root/'tls','tls')

if __name__=='__main__':unittest.main()
