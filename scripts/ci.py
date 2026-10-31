#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Run standalone public-SDK TLS acceptance and a moved source consumer before release."""
from __future__ import annotations
import argparse, hashlib, json, os, platform, re, shutil, subprocess, sys, tarfile, urllib.request, zipfile
from pathlib import Path,PurePosixPath
from release_source import prepare_tree,digest,revision
from sdk_layout import sdk_package
from native_provider import source_layout
PACKAGE=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out-dir',type=Path,required=True);p.add_argument('--sdk',type=Path,help='Reuse a local SDK, still checked against release.lock hashes');p.add_argument('--openssl-root',type=Path,help='Reuse the matching managed static OpenSSL provider');a=p.parse_args();out=a.out_dir.resolve()
    if out.exists():p.error('new external output required')
    if out==PACKAGE or PACKAGE in out.parents:p.error('output must be outside package')
    out.mkdir(parents=True);win=os.name=='nt';suffix='.exe' if win else '';host={'Darwin':'darwin','Linux':'linux','Windows':'windows'}[platform.system()]+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x86_64')
    lock=json.loads((PACKAGE/'release.lock.json').read_text());sdk_lock=lock['sdk'];pins=sdk_lock['hosts'].get(host);version=sdk_lock['version'];name='nyra-sdk-'+version+'-'+host
    if pins is None:raise ValueError('qualified SDK '+version+' pins are pending for '+host)
    if any(not isinstance(pins[key],str) or not re.fullmatch(r'[0-9a-f]{64}',pins[key]) for key in ('archive_sha256','manifest_sha256')):raise ValueError('SDK release hashes are not frozen; do not tag TLS yet')
    report={'format':'nyra-tls-ci-v1','status':'running','host':host,'source_commit':revision(PACKAGE),'net_core_commit':lock['net_core']['commit'],'sanitized':not win,'commands':[]}
    def save():(out/'ci-report.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,cmd,env=None):
        report['commands'].append({'name':name,'command':list(map(str,cmd))});save();print('BEGIN '+name,flush=True)
        with (out/(name+'.log')).open('w') as log:subprocess.run(list(map(str,cmd)),env=env,stdout=log,stderr=subprocess.STDOUT,timeout=3600,check=True)
        print('END '+name,flush=True)
    try:
        run('provider-layout-unit',[sys.executable,PACKAGE/'tests/tools/test_native_provider.py'])
        run('sdk-layout-unit',[sys.executable,PACKAGE/'tests/tools/test_sdk_layout.py'])
        run('packager-unit',[sys.executable,PACKAGE/'tests/tools/test_release_source.py'])
        if a.sdk:
            sdk=a.sdk.expanduser().resolve()
        else:
            archive=out/(name+('.zip' if win else '.tar.gz'));url='https://github.com/nylang/sdk/releases/download/v'+version+'/'+archive.name
            with urllib.request.urlopen(url,timeout=180) as response,archive.open('wb') as target:shutil.copyfileobj(response,target,1024*1024)
            if digest(archive)!=pins['archive_sha256']:raise ValueError('SDK archive hash mismatch')
            extracted=out/'sdk';extracted.mkdir()
            if win:
                with zipfile.ZipFile(archive) as bundle:
                    for member in bundle.infolist():
                        parts=PurePosixPath(member.filename).parts
                        if not parts or parts[0]!=name or '..' in parts or '\\' in member.filename or ':' in member.filename or (member.external_attr>>16)&0o170000==0o120000:raise ValueError('unsafe SDK archive member')
                    bundle.extractall(extracted)
            else:
                with tarfile.open(archive,'r:gz') as bundle:
                    for member in bundle.getmembers():
                        parts=PurePosixPath(member.name).parts
                        if not parts or parts[0]!=name or '..' in parts or '\\' in member.name:raise ValueError('unsafe SDK archive member')
                    bundle.extractall(extracted,filter='data')
            sdk=extracted/name
        metadata=json.loads((sdk/'manifest.json').read_text());tool=(sdk/metadata['tools']['nyrac']['path']).resolve()
        if sdk.resolve() not in tool.parents or digest(sdk/'manifest.json')!=pins['manifest_sha256'] or metadata['version']!=version or metadata['host']!=host or digest(tool)!=metadata['tools']['nyrac']['sha256']:raise ValueError('SDK compiler/manifest identity mismatch')
        report.update(sdk_archive_sha256=pins['archive_sha256'],sdk_archive_verified=not bool(a.sdk),sdk_manifest_sha256=digest(sdk/'manifest.json'))
        net=out/'net_core';run('net-init',['git','init',net]);run('net-line-endings',['git','-C',net,'config','core.autocrlf','false']);run('net-remote',['git','-C',net,'remote','add','origin',lock['net_core']['url']]);run('net-fetch',['git','-C',net,'fetch','--depth','1','origin',lock['net_core']['commit']]);run('net-checkout',['git','-C',net,'checkout','--detach','FETCH_HEAD'])
        if revision(net)!=lock['net_core']['commit']:raise ValueError('net_core lock mismatch')
        perl='C:/Strawberry/perl/bin/perl.exe' if win else 'perl'
        provider_env=os.environ.copy()
        if platform.system()=='Darwin':provider_env['MACOSX_DEPLOYMENT_TARGET']='14.0'
        if a.openssl_root:
            ssl=source_layout(a.openssl_root.expanduser(),out/'openssl-provider',win)
        else:
            run('openssl',[sys.executable,PACKAGE/'scripts/build_openssl.py','--out-dir',out/'openssl','--perl',perl,'--build-cli','--jobs','4'],provider_env)
            ssl=out/'openssl'/('openssl-'+json.loads((PACKAGE/'openssl.lock.json').read_text())['version'])
        cc=shutil.which('clang') or 'clang'
        run('accept',[sys.executable,PACKAGE/'scripts/accept.py','--sdk',sdk,'--net-core',net,'--openssl-root',ssl,'--native-cc',cc,'--out-dir',out/'acceptance',*(['--no-sanitize'] if win else [])])
        accepted=json.loads((out/'acceptance/acceptance.json').read_text());report['acceptance']=accepted
        # Use ordinary production archives, not the acceptance suite's interposed transport.
        kit=sdk/'hosts'/host/'llvm/bin';env=os.environ|{'CC':str(kit/('clang'+suffix)),'AR':str(kit/('llvm-ar'+suffix)),'PATH':str(kit)+os.pathsep+os.environ.get('PATH',''),'NYRA_SDK_ROOT':str(sdk),'NYRA_KERNEL_ROOT':str(out/'source-fallback-disabled')}
        if not win and platform.system()=='Darwin':env|={'SDKROOT':subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip(),'MACOSX_DEPLOYMENT_TARGET':'14.0'}
        run('tls-native',[sys.executable,PACKAGE/'scripts/build_native.py','--openssl-root',ssl,'--out-dir',out/'tls-native','--cc',kit/('clang'+suffix),'--ar',kit/('llvm-ar'+suffix)],env)
        stage=out/'portable';stage.mkdir();prepare_tree(PACKAGE,stage/'tls','tls');prepare_tree(net,stage/'net_core','net_core');moved=out/'moved';stage.rename(moved)
        # Keep the relocated package's public Git origins intact.
        public_manifest=(moved/'tls/package.yaml').read_bytes()
        consumer=moved/'consumer';consumer.mkdir()
        origin=lock['net_core']
        (consumer/'package.yaml').write_text('name: tls_consumer\ndependencies:\n  tls:\n    path: ../tls\n  net_core:\n    git: '+origin['url']+'\n    rev: '+origin['commit']+'\n')
        manager=(sdk/metadata['tools']['nyra']['path']).resolve()
        if sdk.resolve() not in manager.parents or digest(manager)!=metadata['tools']['nyra']['sha256']:
            raise ValueError('SDK package-manager identity mismatch')
        run('consumer-lock',[manager,'lock',consumer,'--cache-scope','local','--json'],env)
        run('consumer-fetch-frozen',[manager,'fetch',consumer,'--cache-scope','local','--frozen','--offline','--json'],env)
        locked=(consumer/'nyra.lock').read_text()
        if not re.search(r'commit:\s*"?'+re.escape(origin['commit'])+r'"?\s*$',locked,re.M):
            raise ValueError('relocated consumer did not lock the declared net_core commit')
        if (moved/'tls/package.yaml').read_bytes()!=public_manifest:
            raise ValueError('portable consumer changed the public package manifest')
        report['portable_git_dependencies']='passed'
        report['consumer_lock_sha256']=digest(consumer/'nyra.lock')
        ca=json.dumps(str(out/'acceptance/native-acceptance/ca.pem'))
        (consumer/'main.ny').write_text('''/** @brief Relocated source consumer using implicit public SDK runtimes. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "tls:tls.ny";
func main() -> int32 {
  var made: Result<TlsSession,TlsError> = TlsSession.NewClient(TlsClientConfig{peer_name:"localhost",ca_file:CA_PATH});
  if made.IsErr() { return 1; }
  var session: TlsSession = move((made.get_if<TlsSession>()) as TlsSession);
  let step: Result<TlsProgress,TlsError> = session.HandshakeStep(NetOperationOptions{});
  if step.IsErr() || session.PendingCiphertext() == 0 { return 2; }
  return 0;
}
'''.replace('CA_PATH',ca))
        links=['--platform-archive='+str(sdk_package(sdk, host, 'stdlib') / 'lib/libnyra_platform.a'),'--link-arg='+str(out/'tls-native/libtls_native.a'),'--link-arg='+str(ssl/('libssl.lib' if win else 'libssl.a')),'--link-arg='+str(ssl/('libcrypto.lib' if win else 'libcrypto.a')),'--link-arg='+str(out/'acceptance/net-production-native/libnet_core_native.a')]
        links+=['--link-arg=-l'+v for v in (('ws2_32','iphlpapi','gdi32','advapi32','crypt32','user32') if win else ('pthread','dl') if platform.system()=='Linux' else ('pthread',))]
        binary=out/('portable-consumer'+suffix);run('consumer-build',[tool,'build',consumer/'main.ny','--link','-O2','--out-dir',out/'consumer-objects','-o',binary,*links],env);run('consumer',[binary],env);report['relocated_consumer']='passed'
        if accepted['status']!='passed' or accepted['compiler_origin']!='public-sdk':raise ValueError('public SDK acceptance required')
        report['status']='passed'
    except (OSError,ValueError,subprocess.SubprocessError) as error:report['status']='failed';report['error']=str(error);print(str(error),file=sys.stderr)
    save();return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
