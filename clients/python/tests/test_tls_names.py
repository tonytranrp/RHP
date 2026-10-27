"""With a CA file, the host's certificate must name the host the client dialed (not just chain to the CA)."""

import datetime
import ipaddress
import socket
import ssl
import threading

import pytest

from rhp_client._errors import RhpError
from rhp_client._transport import TlsStream, certificate_names_host

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def make_certificate(common_name, dns=(), ips=(), issuer=None, ca=False):
    """A certificate and its key, self-signed or signed by `issuer` (certificate, key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer[0].subject if issuer else subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    names = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(issuer[1] if issuer else key, hashes.SHA256()), key


def test_certificate_names_the_host():
    cert, _ = make_certificate("rhp", dns=["game.example", "*.lan.example"], ips=["127.0.0.1", "::1"])
    for host in ("game.example", "GAME.Example", "game.example.", "a.lan.example", "127.0.0.1", "::1", "[::1]"):
        assert certificate_names_host(cert, host), host
    for host in ("example", "other.example", "lan.example", "a.b.lan.example", "10.0.0.1", "127.0.0.2", ""):
        assert not certificate_names_host(cert, host), host
    # The common name doesn't count; no certificate never matches.
    named_only_in_cn, _ = make_certificate("game.example")
    assert not certificate_names_host(named_only_in_cn, "game.example")
    assert not certificate_names_host(None, "game.example")
    # An address must be listed as an address, not as a DNS name.
    dns_ip, _ = make_certificate("rhp", dns=["127.0.0.1"])
    assert not certificate_names_host(dns_ip, "127.0.0.1")


def test_tls_stream_checks_the_name_with_a_ca(tmp_path):
    pytest.importorskip("OpenSSL")
    ca = make_certificate("rhp test ca", ca=True)
    leaf, leaf_key = make_certificate("localhost", dns=["localhost"], issuer=ca)
    (tmp_path / "ca.pem").write_bytes(ca[0].public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.key").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(str(tmp_path / "leaf.pem"), str(tmp_path / "leaf.key"))
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve(count):
        for _ in range(count):
            raw, _ = listener.accept()
            try:
                with server.wrap_socket(raw, server_side=True) as conn:
                    conn.recv(1)
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, args=(2,), daemon=True)
    thread.start()
    try:
        good = TlsStream(socket.create_connection(("127.0.0.1", port)), "localhost", str(tmp_path / "ca.pem"))
        assert len(good.binding) == 32
        good.close()
        # The chain is fine but the certificate isn't for 127.0.0.1.
        with pytest.raises(RhpError) as wrong:
            TlsStream(socket.create_connection(("127.0.0.1", port)), "127.0.0.1", str(tmp_path / "ca.pem"))
        assert "isn't for 127.0.0.1" in str(wrong.value)
    finally:
        thread.join(10)
        listener.close()
