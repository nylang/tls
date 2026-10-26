#!/usr/bin/env python3
"""Build the exact pinned OpenSSL static libraries in an external, empty cache."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

PACKAGE = Path(__file__).resolve().parents[1]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='reuse a downloaded archive; checksum is still verified')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
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
    commands = [
        ['perl', 'Configure', 'no-shared', 'no-tests', 'no-module', '--prefix=' + str(output / 'install')],
        ['make', '-j' + str(args.jobs), 'build_libs'],
    ]
    for index, command in enumerate(commands):
        print('BEGIN OpenSSL step ' + str(index), flush=True)
        with (output / ('build-' + str(index) + '.log')).open('w') as log:
            subprocess.run(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        print('END OpenSSL step ' + str(index), flush=True)
    receipt = {'pin': pin, 'archive_sha256': digest, 'commands': commands,
               'artifacts': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                             for name in ('libssl.a', 'libcrypto.a')},
               'scope': 'host static library build only; upstream test suite not run'}
    (output / 'openssl-build.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(source, flush=True)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
