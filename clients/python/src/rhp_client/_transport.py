"""Byte streams a session runs over: plain TCP, or TLS 1.3 through pyOpenSSL (the one Python TLS
stack that exposes RFC 9266's tls-exporter, which RHP mixes into its handshake).
"""

from __future__ import annotations

import ipaddress
import select
import socket
from typing import Optional

from ._errors import RhpError

__all__ = ["Stream", "TcpStream", "TlsStream", "open_stream", "is_loopback", "certificate_names_host"]

# The tls-exporter channel binding (RFC 9266): 32 bytes, this label, no context.
_EXPORTER_LABEL = b"EXPORTER-Channel-Binding"


def is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Stream:
    """A connected byte stream. `encrypted` frames leave their CRC out; `binding` is mixed into the
    handshake transcript and the resume proofs (empty without TLS)."""

    encrypted = False
    binding = b""

    def send_all(self, data: bytes) -> None:
        raise NotImplementedError

    def receive(self, timeout: Optional[float]) -> Optional[bytes]:
        """Bytes, b"" when the peer closed, or None when `timeout` passed with nothing to read."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class TcpStream(Stream):
    def __init__(self, sock: socket.socket):
        self._sock = sock
        sock.setblocking(True)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:  # pragma: no cover - not every socket supports it
            pass

    def send_all(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise RhpError("transport", str(exc), "client") from None

    def receive(self, timeout: Optional[float]) -> Optional[bytes]:
        try:
            ready, _, _ = select.select([self._sock], [], [], timeout)
            if not ready:
                return None
            return self._sock.recv(65536)
        except (OSError, ValueError) as exc:
            raise RhpError("transport", str(exc), "client") from None

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


class TlsStream(Stream):
    """TLS 1.3 over a TCP socket with pyOpenSSL. With `ca_file` the host's certificate must chain to it
    and name `server_name` (certificate_names_host). Without it the certificate isn't checked: the
    pre-shared key proofs are bound to this connection's tls-exporter value, so a relay that
    terminates TLS can't complete the handshake (as RHP's own clients do)."""

    encrypted = True

    def __init__(self, sock: socket.socket, server_name: Optional[str], ca_file: Optional[str] = None):
        try:
            from OpenSSL import SSL  # type: ignore
        except ImportError:
            raise RhpError("disabled", "TLS needs pyOpenSSL: pip install 'rhp-client[tls]'", "client") from None
        self._ssl = SSL
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_min_proto_version(SSL.TLS1_3_VERSION)
        context.set_max_proto_version(SSL.TLS1_3_VERSION)
        if ca_file:
            context.load_verify_locations(ca_file)
            context.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: bool(ok))
        else:
            context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
        self._sock = sock
        sock.setblocking(True)
        conn = SSL.Connection(context, sock)
        if server_name and not _is_ip(server_name):
            conn.set_tlsext_host_name(server_name.encode("idna"))
        conn.set_connect_state()
        try:
            conn.do_handshake()
        except SSL.Error as exc:
            raise RhpError("tls", "TLS handshake failed: %s" % (exc,), "client") from None
        self._conn = conn
        # OpenSSL checked the chain; the name is checked here (pyOpenSSL has no hostname option).
        if ca_file and not certificate_names_host(_peer_certificate(conn), server_name or ""):
            self.close()
            raise RhpError("tls", "the host's certificate isn't for %s" % (server_name,), "client")
        self.binding = conn.export_keying_material(_EXPORTER_LABEL, 32, None)

    def send_all(self, data: bytes) -> None:
        try:
            self._conn.sendall(data)
        except (self._ssl.Error, OSError) as exc:
            raise RhpError("transport", str(exc), "client") from None

    def receive(self, timeout: Optional[float]) -> Optional[bytes]:
        try:
            if self._conn.pending() == 0:
                ready, _, _ = select.select([self._sock], [], [], timeout)
                if not ready:
                    return None
            return self._conn.recv(65536)
        except self._ssl.ZeroReturnError:
            return b""
        except self._ssl.WantReadError:
            return None
        except (self._ssl.Error, OSError, ValueError) as exc:
            raise RhpError("transport", str(exc), "client") from None

    def close(self) -> None:
        try:
            self._conn.shutdown()
        except Exception:  # noqa: BLE001 - closing anyway
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _peer_certificate(conn):
    """The host's certificate as a `cryptography` x509.Certificate (pyOpenSSL depends on it), or None."""
    try:
        return conn.get_peer_certificate(as_cryptography=True)  # pyOpenSSL 24.3+
    except TypeError:
        certificate = conn.get_peer_certificate()
        return certificate.to_cryptography() if certificate is not None else None


def certificate_names_host(certificate, host: str) -> bool:
    """Whether `certificate` (a `cryptography` x509.Certificate) is for `host`: an IP address must be
    one of its subject alternative name IP addresses, a name one of its DNS names (case-insensitive; a
    leading "*." stands for exactly one label). The subject's common name doesn't count (RFC 6125)."""
    if certificate is None or not host:
        return False
    from cryptography import x509  # type: ignore

    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        return ipaddress.ip_address(host.strip("[]")) in names.get_values_for_type(x509.IPAddress)
    except ValueError:
        pass
    try:
        wanted = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    label, _, parent = wanted.partition(".")
    for pattern in names.get_values_for_type(x509.DNSName):
        pattern = pattern.rstrip(".").lower()
        if pattern == wanted or (pattern.startswith("*.") and label and parent and pattern[2:] == parent):
            return True
    return False


def open_stream(host: str, port: int, tls: bool, ca_file: Optional[str], timeout: float) -> Stream:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise RhpError("transport", "can't connect to %s:%d: %s" % (host, port, exc), "client") from None
    if tls:
        return TlsStream(sock, host, ca_file)
    return TcpStream(sock)
