"""Sweep observed operation-window provider allocations in fresh processes."""
from pathlib import Path


def exercise(run, executable: Path, fixtures: Path) -> list[dict]:
    cases = []
    labels = ['initial ClientHello', 'authenticated read', 'first application write',
              'first close_notify', 'requested KeyUpdate read', 'remaining authenticated handshake']
    for version in (12, 13):
        for operation in ([0, 1, 2, 3, 5] if version == 12 else range(6)):
            command = [str(executable), *[str(fixtures / name) for name in
                       ('ca.pem', 'peer.pem', 'peer.key')], str(version), str(operation)]
            def execute(index):
                result = run([*command, str(index)]).strip().split()
                if len(result) != 4 or result[0] != 'RESULT':
                    raise ValueError('missing runtime allocation result')
                return tuple(map(int, result[1:]))
            allocations, hits, error = execute(0)
            if not 0 <= allocations <= 4096 or hits or error:
                raise ValueError('invalid healthy allocation baseline')
            record = {'name': f'TLS 1.{version - 10} {labels[operation]} provider allocation sweep',
                      'version': version, 'operation': operation,
                      'baseline_allocations': allocations, 'injected_failures': allocations,
                      'resource_failures': [], 'protocol_failures': [], 'certificate_failures': [],
                      'name_failures': [], 'tolerated_failures': []}
            for index in range(1, allocations + 1):
                _, hits, error = execute(index)
                if hits != 1 or error not in ((0, 3, 4, 5, 9) if operation == 5 else (0, 5, 9)):
                    raise ValueError('invalid runtime allocation failure result')
                field = {0: 'tolerated_failures', 3: 'certificate_failures', 4: 'name_failures',
                         5: 'protocol_failures', 9: 'resource_failures'}[error]
                record[field].append(index)
            cases.append(record)
    return cases
