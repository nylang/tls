"""Generate local chain/size boundaries using the acceptance-owned CA and keys."""
from pathlib import Path


def generate(run, output: Path, cli: str) -> None:
    peer_extensions = (output / 'peer.ext').read_text()

    def request(name: str, subject: str, key: str | None = None) -> None:
        options = ['-key', str(output / key)] if key else [
            '-newkey', 'rsa:2048', '-nodes', '-keyout', str(output / (name + '.key'))]
        run([cli, 'req', '-new', *options, '-subj', '/CN=' + subject,
             '-out', str(output / (name + '.csr'))])

    def sign(name: str, csr: str, issuer: str, issuer_key: str, extensions: str,
             dates: list[str] | None = None) -> None:
        ext = output / (name + '.ext'); ext.write_text(extensions)
        run([cli, 'x509', '-req', '-in', str(output / csr), '-CA', str(output / issuer),
             '-CAkey', str(output / issuer_key), '-CAcreateserial',
             *(dates or ['-days', '2']), '-sha256', '-extfile', str(ext),
             '-out', str(output / (name + '.pem'))])

    def chain(name: str, leaf: str, intermediates: list[str]) -> None:
        (output / name).write_bytes(b''.join((output / p).read_bytes()
                                            for p in [leaf, *intermediates]))

    ca = 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n'
    request('intermediate', 'Nyra TLS intermediate')
    sign('intermediate', 'intermediate.csr', 'ca.pem', 'ca.key', ca)
    sign('chain-leaf', 'peer.csr', 'intermediate.pem', 'intermediate.key', peer_extensions)
    chain('chain.pem', 'chain-leaf.pem', ['intermediate.pem'])
    request('wrong-intermediate', 'Nyra TLS intermediate')
    sign('wrong-intermediate', 'wrong-intermediate.csr', 'ca.pem', 'ca.key', ca)
    chain('wrong-chain.pem', 'chain-leaf.pem', ['wrong-intermediate.pem'])
    sign('not-ca', 'intermediate.csr', 'ca.pem', 'ca.key',
         'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyCertSign\n')
    sign('not-ca-leaf', 'peer.csr', 'not-ca.pem', 'intermediate.key', peer_extensions)
    chain('not-ca-chain.pem', 'not-ca-leaf.pem', ['not-ca.pem'])
    request('sub-intermediate', 'Nyra TLS sub intermediate')
    sign('sub-intermediate', 'sub-intermediate.csr', 'intermediate.pem', 'intermediate.key', ca)
    sign('pathlen-leaf', 'peer.csr', 'sub-intermediate.pem', 'sub-intermediate.key', peer_extensions)
    chain('pathlen-chain.pem', 'pathlen-leaf.pem', ['sub-intermediate.pem', 'intermediate.pem'])
    sign('wrong-eku', 'peer.csr', 'ca.pem', 'ca.key', peer_extensions.replace('serverAuth', 'clientAuth'))
    sign('future', 'peer.csr', 'ca.pem', 'ca.key', peer_extensions,
         ['-not_before', '20990101000000Z', '-not_after', '20990102000000Z'])

    # Distinct issuer names make this a real depth boundary. Reusing the fixture
    # key avoids generating nine unrelated RSA keys; signature verification stays on.
    issuer, issuer_key = 'ca.pem', 'ca.key'
    intermediates: list[str] = []
    for depth in range(1, 10):
        name = 'depth-' + str(depth)
        request(name, 'Nyra TLS depth ' + str(depth), 'intermediate.key')
        sign(name, name + '.csr', issuer, issuer_key, ca.replace('pathlen:0', 'pathlen:16'))
        issuer, issuer_key = name + '.pem', 'intermediate.key'
        intermediates.insert(0, issuer)
        if depth in (8, 9):
            leaf = 'depth-leaf-' + str(depth)
            sign(leaf, 'peer.csr', issuer, issuer_key, peer_extensions)
            chain('depth-chain-' + str(depth) + '.pem', leaf + '.pem', intermediates)

    # Non-critical opaque extensions change encoded certificate size without
    # changing identity, signing key, EKU or chain validity.
    for name, count in [('near-limit', 8), ('over-limit', 9)]:
        extensions = peer_extensions + ''.join(
            '1.3.6.1.4.1.55555.' + str(i + 1) + '=DER:04827d00' + '00' * 32000 + '\n'
            for i in range(count))
        sign(name, 'peer.csr', 'ca.pem', 'ca.key', extensions)
