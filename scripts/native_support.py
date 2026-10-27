"""Host build conventions shared by the standalone TLS acceptance tools."""
from pathlib import Path


def static_libraries(root: Path, windows: bool) -> list[Path]:
    suffix = '.lib' if windows else '.a'
    return [root / ('lib' + name + suffix) for name in ('ssl', 'crypto')]


def system_libraries(windows: bool, linux: bool = False) -> list[str]:
    if windows:
        return ['-l' + name for name in ('ws2_32', 'gdi32', 'advapi32', 'crypt32', 'user32')]
    return ['-lpthread', '-ldl'] if linux else ['-lpthread']


def object_flags(windows: bool) -> list[str]:
    return ['-mno-incremental-linker-compatible'] if windows else ['-fPIC']
