# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT
"""Reuse an installed static OpenSSL provider with the existing source-layout tools."""
from pathlib import Path


def source_layout(root: Path, output: Path, windows: bool) -> Path:
    root = root.resolve()
    names = ['libssl' + ('.lib' if windows else '.a'), 'libcrypto' + ('.lib' if windows else '.a')]
    if all((root / name).is_file() for name in names):
        return root
    if not all((root / 'lib' / name).is_file() for name in names):
        raise ValueError('missing complete managed static OpenSSL provider')
    if not (root / 'include').is_dir() or not (root / 'LICENSE.txt').is_file():
        raise ValueError('managed OpenSSL headers/license missing')
    output.mkdir()
    (output / 'include').symlink_to(root / 'include', target_is_directory=True)
    (output / 'LICENSE.txt').symlink_to(root / 'LICENSE.txt')
    for name in names:
        (output / name).symlink_to(root / 'lib' / name)
    executable = 'openssl.exe' if windows else 'openssl'
    if (root / 'bin' / executable).is_file():
        (output / 'apps').mkdir()
        (output / 'apps' / executable).symlink_to(root / 'bin' / executable)
    return output.resolve()
