#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Build the private TLS bridge against an explicitly selected pinned OpenSSL tree."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from native_support import object_flags, static_libraries, system_libraries

PACKAGE = Path(__file__).resolve().parents[1]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-root', type=Path, required=True, help='built OpenSSL 3.5.9 source tree')
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC') or 'clang')
    parser.add_argument('--ar', default=os.environ.get('AR') or shutil.which('llvm-ar') or 'ar')
    args = parser.parse_args()
    output = args.out_dir.expanduser().resolve()
    ssl = args.openssl_root.expanduser().resolve()
    if output == PACKAGE or PACKAGE in output.parents:
        parser.error('outputs must be outside the package')
    if output.exists() and any(output.iterdir()):
        parser.error('--out-dir must be new or empty')
    output.mkdir(parents=True, exist_ok=True)
    pin = json.loads((PACKAGE / 'openssl.lock.json').read_text())
    target = subprocess.check_output([args.cc, '-dumpmachine'], text=True).strip()
    windows = any(marker in target.lower() for marker in ('windows', 'mingw', 'win32'))
    libraries = static_libraries(ssl, windows)
    if not all(p.is_file() for p in libraries):
        parser.error('missing pinned static libraries; run build_openssl.py first')
    source = PACKAGE / 'private/native/tls_engine.c'
    command = [args.cc, '-std=c11', '-O2', *object_flags(windows), '-Wall', '-Wextra', '-Werror',
               '-I' + str(ssl / 'include'), '-c', str(source), '-o', str(output / 'tls_engine.o')]
    subprocess.run(command, check=True)
    if Path(args.ar).name.lower() in ('lib', 'lib.exe', 'llvm-lib', 'llvm-lib.exe'):
        archive_command = [args.ar, '/NOLOGO', '/OUT:' + str(output / 'libtls_native.a'), str(output / 'tls_engine.o')]
    else:
        archive_command = [args.ar, 'rcs', str(output / 'libtls_native.a'), str(output / 'tls_engine.o')]
    subprocess.run(archive_command, check=True)
    shutil.copy2(PACKAGE / 'LICENSE', output / 'LICENSE')
    shutil.copy2(ssl / 'LICENSE.txt', output / 'OPENSSL-LICENSE.txt')
    record = {'format': 'nyra-tls-native-v1', 'openssl': pin,
              'target': target, 'compile': command, 'archive_command': archive_command,
              'system_libraries': system_libraries(windows, 'linux' in target.lower()),
              'link_inputs': [str(output / 'libtls_native.a'), *map(str, libraries)],
              'inputs_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (source, source.with_suffix('.h'), *libraries)}}
    (output / 'native-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(output / 'libtls_native.a', flush=True)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
