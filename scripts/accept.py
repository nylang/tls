#!/usr/bin/env python3
"""Accept the TLS facade using a supplied public SDK and sibling net_core sources."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parents[1]

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--native-cc', default=shutil.which('clang') or 'clang', help='host C compiler with a compatible sanitizer runtime')
    parser.add_argument('--net-core', type=Path, default=PACKAGE.parent / 'net_core')
    parser.add_argument('--openssl-root', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    sdk, net, ssl, output = [p.expanduser().resolve() for p in (args.sdk, args.net_core, args.openssl_root, args.out_dir)]
    host = platform.system().lower() + '-' + {'aarch64': 'arm64', 'amd64': 'x86_64'}.get(platform.machine().lower(), platform.machine().lower())
    if host not in ('darwin-arm64', 'darwin-x86_64', 'linux-x86_64'):
        parser.error('initial acceptance supports native POSIX desktop hosts only')
    if output == PACKAGE or PACKAGE in output.parents or output == net or net in output.parents:
        parser.error('use an external output directory')
    if output.exists() and any(output.iterdir()):
        parser.error('--out-dir must be new or empty')
    metadata = json.loads((sdk / 'manifest.json').read_text())
    if metadata['host'] != host:
        parser.error('SDK host mismatch')
    compiler = (sdk / metadata['tools']['nyrac']['path']).resolve()
    if sdk not in compiler.parents or digest(compiler) != metadata['tools']['nyrac']['sha256']:
        parser.error('invalid SDK compiler path/hash')
    toolkit = sdk / 'hosts' / host / 'llvm/bin'
    stdlib = sdk / 'targets' / host / 'stdlib'
    output.mkdir(parents=True, exist_ok=True)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('NYRA', 'DYLD_', 'LD_')) and k != 'LLVM_PREFIX'}
    environment.update(CC=str(toolkit / 'clang'), AR=str(toolkit / 'llvm-ar'),
        PATH=str(toolkit) + os.pathsep + environment.get('PATH', ''), NYRA_KERNEL_ROOT=str(output / 'source-fallback-disabled'))
    if host.startswith('darwin-'):
        environment['SDKROOT'] = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    report = {'format': 'nyra-tls-sdk-acceptance-v1', 'status': 'running', 'host': platform.platform(),
              'sdk_version': metadata['version'], 'sdk_manifest_sha256': digest(sdk / 'manifest.json'),
              'compiler_sha256': digest(compiler), 'source_fallback_disabled': True, 'commands': [],
              'openssl_pin_sha256': digest(PACKAGE / 'openssl.lock.json'),
              'net_core_source_sha256': {p.relative_to(net).as_posix(): digest(p) for p in sorted(net.rglob('*'))
                  if p.is_file() and p.suffix in ('.ny', '.ni', '.c', '.h', '.py', '.yaml') and '.git' not in p.parts},
              'source_sha256': {p.relative_to(PACKAGE).as_posix(): digest(p) for p in sorted(PACKAGE.rglob('*'))
                  if p.is_file() and p.suffix in ('.ny', '.ni', '.c', '.h', '.py', '.yaml') and '.git' not in p.parts}}
    def save() -> None:
        (output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
    def run(name: str, command: list[str]) -> str:
        report['commands'].append({'name': name, 'command': command}); save()
        print('BEGIN ' + name, flush=True)
        with (output / (name + '.log')).open('w') as log:
            result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        if result.returncode:
            raise RuntimeError(name + ' failed; see ' + str(output / (name + '.log')))
        print('END ' + name, flush=True)
        return (output / (name + '.log')).read_text()
    try:
        run('native', [sys.executable, str(PACKAGE / 'scripts/accept_native.py'), '--openssl-root', str(ssl), '--out-dir', str(output / 'native-acceptance'), '--cc', args.native_cc, '--sanitize'])
        stage = output / 'project'
        for source, name in ((PACKAGE, 'tls'), (net, 'net_core')):
            shutil.copytree(source, stage / name, ignore=shutil.ignore_patterns('.git', '__pycache__', 'cache', 'bin', 'lib', 'out'))
        for name in ('tls', 'net_core'):
            extra = '  net_core:\n    path: ../net_core\n' if name == 'tls' else ''
            (stage / name / 'package.yaml').write_text('name: ' + name + '\nversion: 0.1.0\nlicense: MIT\ndependencies:\n  stdlib:\n    precompiled: ' + json.dumps(str(stdlib)) + '\n' + extra + 'directories:\n  interface:\n    - interface\n  private:\n    - private\n    - tests\n')
        report['staged_manifest_sha256'] = {name: digest(stage / name / 'package.yaml') for name in ('tls', 'net_core')}
        run('net-native', [sys.executable, str(net / 'scripts/build_native.py'), '--out-dir', str(output / 'net-native')])
        fixture = output / 'config_fixture.o'
        ca_file = output / 'native-acceptance/ca.pem'
        run('fixture', [str(toolkit / 'clang'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-DNYRA_TLS_TEST_CA_FILE=' + json.dumps(str(ca_file)), '-c', str(PACKAGE / 'tests/native/config_fixture.c'), '-o', str(fixture)])
        binary = output / 'tls-tests'
        links = [output / 'native-acceptance/native/libtls_native.a', ssl / 'libssl.a', ssl / 'libcrypto.a', output / 'net-native/libnet_core_native.a', fixture]
        run('tests', [str(compiler), 'test', str(stage / 'tls'), '--tag', 'tls_engine', '-O2', '-j', '4',
            '--out-dir', str(output / 'objects'), '-o', str(binary), '--platform-archive=' + str(stdlib / 'lib/libnyra_platform.a'),
            *['--link-arg=' + str(p) for p in links], *(['--link-arg=-ldl', '--link-arg=-lpthread'] if host.startswith('linux-') else []),
            '--report', str(output / 'tests.json')])
        tests = json.loads((output / 'tests.json').read_text())
        if tests['passed'] != 6 or tests['failed'] or tests['ignored'] or tests['skipped']:
            raise RuntimeError('not all six TLS facade cases passed')
        report['tests'] = tests
        for index in range(tests['passed']):
            run('case-' + str(index), [str(binary), str(index)])
        report['isolated_replays'] = tests['passed']
        run('production', [str(compiler), 'precompile', str(stage / 'tls/tls.ny'), '-O2', '-j', '4', '--out-dir', str(output / 'production-objects'), '-o', str(output / 'production')])
        imports = run('production-imports', [str(toolkit / 'llvm-nm'), '-u', str(output / 'production/lib/libpackage.a')])
        if 'nyra_tls_test_' in imports or 'AddFail' in imports:
            raise RuntimeError('test fixture/harness imports leaked into production')
        report['production_fixture_imports'] = []
        native = json.loads((output / 'native-acceptance/acceptance.json').read_text())
        report['native_cases'] = native['cases']
        report['native_artifacts'] = native['native']
        for name, expected in report['net_core_source_sha256'].items():
            if digest(net / name) != expected:
                raise RuntimeError('net_core source changed during acceptance: ' + name)
        if digest(PACKAGE / 'openssl.lock.json') != report['openssl_pin_sha256']:
            raise RuntimeError('OpenSSL pin changed during acceptance')
        for name, expected in report['source_sha256'].items():
            if digest(PACKAGE / name) != expected:
                raise RuntimeError('package source changed during acceptance: ' + name)
        report['status'] = 'passed'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['status'] = 'failed'; report['error'] = str(error); print(str(error), file=sys.stderr)
    save(); print(output / 'acceptance.json')
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
