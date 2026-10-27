# Reliable UDP

`Rhp::config<>::transport<Rhp::net::udp_reliable>`: the byte stream of TCP over UDP. Sessions, roles, signing, TLS and resume run on top unchanged.

- Packet format and constants: `detail/packet.hpp` (40-byte header, at most 480 bytes of payload, CRC-32C trailer; its own revision byte, independent of the RHP protocol revision).
- Sending: up to 4 packets in flight at first, growing to 64; queued application bytes are capped at 16 MiB and fragmented only as the window opens.
- Loss: a hole with three later packets acknowledged is resent at once (fast retransmit, once per RTT, one window halving per recovery). Otherwise the RFC 6298 timeout fires (estimated from first transmissions, 25 ms to 2 s), resending what expired and doubling until progress. Ten seconds without progress closes the link.
- The per-link timer runs only for the next deadline; an idle link costs nothing.
- Receiving: up to 64 out-of-order packets are kept; bytes are delivered in order after `start()`.
- A listening socket keeps at most 1024 live links. FIN follows the queued data; a receiver keeps up to 4096 FIN tombstones for 12 s so a lost final ACK can still be answered after the link is gone.
- ACKs: a receive drains the datagrams already waiting on the socket (up to 64 more, so a busy socket can't hold the thread), and each peer that got packets owes one ACK until the drain ends; that ACK (cumulative + selective) then covers them all. A packet the peer sends meanwhile carries the latest ACK in its header and settles what is owed. Outside a drain an ACK goes at once. (Posting each ACK to the end of the I/O round instead was measured slower: every datagram was its own receive completion.)
- Port 0 listens on any free port (`host.port()` says which). DNS-SD publishes it under `_rhp._udp`.
- The CRC catches corruption only. ACKs aren't authenticated (an on-path attacker can stall a link, as with TCP); the session MAC or TLS rejects any injected data.
