#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Build the exact pinned OpenSSL static libraries in an external, empty cache."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import tarfile
import urllib.request
from native_support import static_libraries

PACKAGE = Path(__file__).resolve().parents[1]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='reuse a downloaded archive; checksum is still verified')
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--perl', default='perl', help='native Perl; Strawberry Perl for MSVC builds')
    parser.add_argument('--make', help='make program; defaults to nmake on Windows, make elsewhere')
    parser.add_argument('--build-cli', action='store_true', help='also build the pinned test certificate CLI')
    args = parser.parse_args()
    if os.name == 'nt' and platform.machine().lower() not in ('amd64', 'x86_64'):
        parser.error('the native Windows build currently supports x86_64 only')
    output = args.out_dir.expanduser().resolve()
    if output == PACKAGE or PACKAGE in output.parents or args.jobs < 1:
        parser.error('use an external output directory and positive job count')
    if output.exists() and any(output.iterdir()):
        parser.error('--out-dir must be new or empty')
    output.mkdir(parents=True, exist_ok=True)
    pin = json.loads((PACKAGE / 'openssl.lock.json').read_text())
    archive = args.archive.expanduser().resolve() if args.archive else output / 'openssl.tar.gz'
    if not args.archive:
        with urllib.request.urlopen(pin['url'], timeout=120) as source, archive.open('wb') as target:
            import shutil
            shutil.copyfileobj(source, target)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != pin['sha256']:
        raise ValueError('OpenSSL archive SHA-256 mismatch')
    name = 'openssl-' + pin['version']
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != name or '..' in parts:
                raise ValueError('unsafe OpenSSL archive entry')
        bundle.extractall(output, filter='data')
    source = output / name
    windows = os.name == 'nt'
    make = args.make or ('nmake' if windows else 'make')
    commands = [[args.perl, 'Configure', *(['VC-WIN64A', 'no-asm'] if windows else []),
                 'no-shared', 'no-tests', 'no-module', '--prefix=' + str(output / 'install')],
                [make, *([] if windows else ['-j' + str(args.jobs)]), 'build_libs']]
    if args.build_cli:
        commands.append([make, *([] if windows else ['-j' + str(args.jobs)]),
                         'apps/openssl.exe' if windows else 'apps/openssl'])
    for index, command in enumerate(commands):
        print('BEGIN OpenSSL step ' + str(index), flush=True)
        with (output / ('build-' + str(index) + '.log')).open('w') as log:
            subprocess.run(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        print('END OpenSSL step ' + str(index), flush=True)
    artifacts = static_libraries(source, windows)
    if args.build_cli:
        artifacts.append(source / 'apps' / ('openssl.exe' if windows else 'openssl'))
    receipt = {'pin': pin, 'archive_sha256': digest, 'commands': commands,
               'windows_assembly': False if windows else None,
               'artifacts': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                             for name in (p.relative_to(source).as_posix() for p in artifacts)},
               'scope': 'host static library build only; upstream test suite not run'}
    (output / 'openssl-build.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(source, flush=True)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
