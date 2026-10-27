#!/usr/bin/env python3
"""Exercise the pinned TLS bridge with local certificates and a fragmented in-process peer."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from native_support import static_libraries, system_libraries
from certificate_fixtures import generate as generate_certificate_fixtures

PACKAGE = Path(__file__).resolve().parents[1]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-root', type=Path, required=True)
    parser.add_argument('--openssl-cli', help='CLI for test-only certificates; defaults to the pinned build CLI when present')
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC') or 'clang')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    output = args.out_dir.expanduser().resolve()
    ssl = args.openssl_root.expanduser().resolve()
    windows = platform.system() == 'Windows'
    local_cli = ssl / 'apps' / ('openssl.exe' if windows else 'openssl')
    args.openssl_cli = args.openssl_cli or (str(local_cli) if local_cli.is_file() else 'openssl')
    executable = output / ('engine-test.exe' if windows else 'engine-test')
    if output == PACKAGE or PACKAGE in output.parents:
        parser.error('use an external output directory')
    if output.exists() and any(output.iterdir()):
        parser.error('--out-dir must be new or empty')
    output.mkdir(parents=True, exist_ok=True)
    config = output / 'openssl-test.cnf'
    config.write_text('[req]\ndistinguished_name = dn\n[dn]\n')
    environment = os.environ | {'OPENSSL_CONF': str(config)}
    report = {'format': 'nyra-tls-native-acceptance-v1', 'status': 'running',
              'host': platform.platform(), 'sanitizers': args.sanitize, 'commands': [],
              'source_sha256': {p.relative_to(PACKAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(PACKAGE.rglob('*')) if p.is_file() and (p.suffix in ('.c', '.h', '.py') or p.name == 'openssl.lock.json') and '.git' not in p.parts},
              'scope': 'controlled certificates and in-process TLS; no socket or cross-host acceptance'}
    def save() -> None:
        (output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
    def run(command: list[str], timeout: int = 120) -> str:
        number = len(report['commands'])
        report['commands'].append(command); save()
        print('BEGIN TLS step ' + str(number), flush=True)
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=environment)
        (output / ('step-' + str(number) + '.log')).write_text(result.stdout + result.stderr)
        result.check_returncode()
        print('END TLS step ' + str(number), flush=True)
        return result.stdout
    try:
        run([sys.executable, str(PACKAGE / 'scripts/build_native.py'), '--openssl-root', str(ssl),
             '--out-dir', str(output / 'native'), '--cc', args.cc])
        report['fixture_cli'] = run([args.openssl_cli, 'version']).strip()
        for prefix in ('ca', 'other'):
            run([args.openssl_cli, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2',
                 '-subj', '/CN=Nyra TLS acceptance ' + prefix, '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-keyout', str(output / (prefix + '.key')), '-out', str(output / (prefix + '.pem'))])
        run([args.openssl_cli, 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
             '-keyout', str(output / 'peer.key'), '-out', str(output / 'peer.csr')])
        (output / 'peer.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        run([args.openssl_cli, 'x509', '-req', '-in', str(output / 'peer.csr'), '-CA', str(output / 'ca.pem'),
             '-CAkey', str(output / 'ca.key'), '-CAcreateserial', '-days', '2', '-sha256',
             '-extfile', str(output / 'peer.ext'), '-out', str(output / 'peer.pem')])
        run([args.openssl_cli, 'x509', '-req', '-in', str(output / 'peer.csr'), '-CA', str(output / 'ca.pem'),
             '-CAkey', str(output / 'ca.key'), '-CAcreateserial', '-not_before', '20200101000000Z', '-not_after', '20200102000000Z', '-sha256',
             '-extfile', str(output / 'peer.ext'), '-out', str(output / 'expired.pem')])
        (output / 'cn-only.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        run([args.openssl_cli, 'x509', '-req', '-in', str(output / 'peer.csr'), '-CA', str(output / 'ca.pem'),
             '-CAkey', str(output / 'ca.key'), '-CAcreateserial', '-days', '2', '-sha256',
             '-extfile', str(output / 'cn-only.ext'), '-out', str(output / 'cn-only.pem')])
        generate_certificate_fixtures(run, output, args.openssl_cli)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if args.sanitize else []
        run([args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
             '-I' + str(ssl / 'include'), '-I' + str(PACKAGE / 'private/native'),
             str(PACKAGE / 'tests/native/engine_test.c'),
             str(PACKAGE / 'private/native/tls_engine.c'), *map(str, static_libraries(ssl, windows)),
             *system_libraries(windows, platform.system() == 'Linux'), '-o', str(executable)])
        result = run([str(executable), *[str(output / name) for name in ('ca.pem', 'peer.pem', 'peer.key', 'other.pem', 'expired.pem', 'cn-only.pem')], str(output)])
        report['cases'] = [line[5:] for line in result.splitlines() if line.startswith('PASS ')]
        if not report['cases']:
            raise ValueError('no native behavior cases executed')
        injected = output / 'resource-engine.o'
        resource_executable = output / ('resource-test.exe' if windows else 'resource-test')
        run([args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
             '-I' + str(ssl / 'include'), '-I' + str(PACKAGE / 'private/native'),
             '-include', str(PACKAGE / 'tests/native/resource_hooks.h'),
             '-DNYRA_TLS_TEST_RESOURCE_INJECTION', '-c', str(PACKAGE / 'private/native/tls_engine.c'),
             '-o', str(injected)])
        run([args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
             '-I' + str(ssl / 'include'), '-I' + str(PACKAGE / 'private/native'),
             str(PACKAGE / 'tests/native/resource_test.c'), str(injected),
             *map(str, static_libraries(ssl, windows)),
             *system_libraries(windows, platform.system() == 'Linux'), '-o', str(resource_executable)])
        resources = run([str(resource_executable), str(output / 'ca.pem')])
        report['resource_cases'] = [line[5:] for line in resources.splitlines() if line.startswith('PASS ')]
        if len(report['resource_cases']) != 11:
            raise ValueError('not all constructor resource-failure scenarios executed')
        report['cases'].extend(report['resource_cases'])
        report['native'] = json.loads((output / 'native/native-manifest.json').read_text())
        for name, expected in report['source_sha256'].items():
            if hashlib.sha256((PACKAGE / name).read_bytes()).hexdigest() != expected:
                raise ValueError('package source changed during acceptance: ' + name)
        report['status'] = 'passed'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report['status'] = 'failed'; report['error'] = str(error)
        print(str(error), file=sys.stderr)
    save()
    print(output / 'acceptance.json')
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
