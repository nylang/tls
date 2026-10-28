#!/usr/bin/env python3
"""Assemble an auditable source distribution with a locked sibling net_core dependency."""
from __future__ import annotations
import argparse, hashlib, io, json, os, subprocess, tarfile
from pathlib import Path
PACKAGE=Path(__file__).resolve().parents[1]

def digest(path:Path)->str:
    value=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):value.update(block)
    return value.hexdigest()
def revision(path:Path)->str:return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
def tested_sources(source:Path)->dict:
    names=subprocess.check_output(['git','-C',str(source),'ls-files','-z']).decode().split('\0')
    return {name:digest(source/name) for name in filter(None,names)
            if Path(name).suffix in ('.ny','.ni','.c','.h','.py','.yaml')}

def validate_acceptance(row:dict,host:str,version:str):
    accept=row['acceptance']
    if row.get('relocated_consumer')!='passed' or row.get('sanitized') is not (not host.startswith('windows-')):
        raise ValueError('TLS relocated consumer or sanitizer acceptance incomplete')
    if accept.get('status')!='passed' or accept['compiler_origin']!='public-sdk' or accept['sdk_version']!=version or accept['compiler_sha256']!=accept['sdk_compiler_sha256'] or accept['tests']['passed']!=39 or accept['tests']['failed'] or accept['isolated_replays']!=39 or len(accept['native_cases'])!=73 or not accept['source_fallback_disabled'] or accept['production_fixture_imports'] or accept.get('native_production_fixture_symbols')!=[]:
        raise ValueError('TLS advertised acceptance incomplete')

def prepare_tree(source:Path,target:Path,name:str):
    import shutil
    target.mkdir(parents=True)
    names=subprocess.check_output(['git','-C',str(source),'ls-files','-z']).decode().split('\0')
    for member_name in filter(None,names):
        relative=Path(member_name)
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('unsafe source member')
        original=source/relative
        if original.is_symlink() or not original.is_file():raise ValueError('source archive requires ordinary tracked files: '+member_name)
        destination=target/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(original,destination)
    # Published manifests retain exact Git origins/revisions; no sibling path rewrite.
    manifest=(target/'package.yaml').read_text()
    if '\n    path:' in manifest:raise ValueError('release manifest contains a local dependency')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--net-core',type=Path,required=True);p.add_argument('--receipts',type=Path,required=True);p.add_argument('--out-dir',type=Path,required=True);a=p.parse_args()
    out=a.out_dir.resolve();net=a.net_core.resolve();version='0.2.0'
    if out.exists():p.error('new external output directory required')
    if out==PACKAGE or PACKAGE in out.parents:p.error('output must be outside package')
    lock=json.loads((PACKAGE/'release.lock.json').read_text());sdk=lock['sdk'];expected=set(sdk['hosts'])
    if revision(net)!=lock['net_core']['commit']:raise ValueError('net_core differs from release lock')
    receipts={};tls_sources=tested_sources(PACKAGE);net_sources=tested_sources(net)
    for path in a.receipts.rglob('ci-report.json'):
        row=json.loads(path.read_text());host=row['host'];accept=row['acceptance']
        if host in receipts or host not in expected or row['status']!='passed' or row['sdk_manifest_sha256']!=sdk['hosts'][host]['manifest_sha256'] or row['sdk_archive_sha256']!=sdk['hosts'][host]['archive_sha256'] or row['source_commit']!=revision(PACKAGE) or row['net_core_commit']!=lock['net_core']['commit']:raise ValueError('CI receipt identity mismatch')
        validate_acceptance(row,host,sdk['version'])
        if accept['source_sha256']!=tls_sources or accept['net_core_source_sha256']!=net_sources:
            raise ValueError('source inventory differs from exact tested input')
        if accept['openssl_pin_sha256']!=digest(PACKAGE/'openssl.lock.json'):
            raise ValueError('tested OpenSSL pin differs from release input')
        receipts[host]=row
    if set(receipts)!=expected:raise ValueError('missing host acceptance')
    out.mkdir(parents=True);root=out/('tls-'+version+'-source');root.mkdir();prepare_tree(PACKAGE,root/'tls','tls');prepare_tree(net,root/'net_core','net_core')
    record={'format':'nyra-tls-source-release-v1','version':version,'source_commit':revision(PACKAGE),'net_core_commit':revision(net),'sdk':sdk,'openssl':json.loads((PACKAGE/'openssl.lock.json').read_text()),'scope':'Source-only distribution; build the pinned OpenSSL and native adapters locally. Four desktop hosts accepted against the exact public SDK. Explicit CA trust required; no mobile/server/mTLS/system-trust claim.','manifest_rewrite':'None. Original package.yaml files retain immutable public Git dependencies. Git acquisition requires the corrected Nyra 1.0.4 toolchain; protocol qualification uses SDK 1.0.2 test snapshots.','hosts':{h:{'compiler_sha256':r['acceptance']['compiler_sha256'],'tests':39,'isolated_replays':39,'native_cases':73,'sanitized':r['sanitized'],'relocated_consumer':'passed'} for h,r in receipts.items()}}
    evidence=root/'evidence';evidence.mkdir()
    for host,row in receipts.items():(evidence/(host+'.json')).write_text(json.dumps(row,indent=2)+'\n')
    (root/'release.json').write_text(json.dumps(record,indent=2)+'\n');(out/'release.json').write_text(json.dumps(record,indent=2)+'\n')
    archive=out/(root.name+'.tar.gz')
    # All packages are public MIT sources. Reject symlinks and omit VCS/cache state.
    with tarfile.open(archive,'w:gz',format=tarfile.PAX_FORMAT) as bundle:
        for path in sorted(root.rglob('*')):
            if path.is_symlink():raise ValueError('source archive may not contain symbolic links')
            if not path.is_file():continue
            data=path.read_bytes();info=tarfile.TarInfo(root.name+'/'+path.relative_to(root).as_posix());info.size=len(data);info.mode=0o644;info.mtime=0;info.uid=info.gid=0;bundle.addfile(info,io.BytesIO(data))
    (out/'SHA256SUMS').write_text(''.join(digest(path)+'  '+path.name+'\n' for path in (archive,out/'release.json')))
    print(archive)
    return 0
if __name__=='__main__':raise SystemExit(main())
