# DNS-SD discovery

Discovery policies for `Rhp::config<>::discovery<D>`. Nothing is published until `host.advertise()`.

| Policy | Windows | Apple | Linux, Android |
|---|---|---|---|
| `mdns` (default) | DNS-SD API (`windns.h`); a listener bound to one address uses the wire responder, which can publish that address | `dns_sd`, owning the address and service records; local-only for loopback | the wire responder |
| `mdns_wire` | own multicast responder and querier everywhere | | |

- `detail/dns.hpp` is the sans-IO DNS codec (`rr_type`, `read_dns`, `dns_service_packet`, `dns_query`); `detail/metadata.hpp` maps `service_record` to DNS-SD names and TXT.
- The wire responder (`wire.cpp`): probes 3 × 250 ms, announces twice, then only answers queries; sends goodbyes; re-probes a renamed record, re-announces an updated one; resolves host-name listen addresses asynchronously. The querier: continuous queries from 1 s doubling to a minute, follow-up queries for missing records, a TTL cache. Both share one CRTP `multicast_endpoint` (IPv4 224.0.0.251 and IPv6 ff02::fb).
- Bounds: 9000-byte packets, 128 records per packet, 1024 cached records, 255-byte TXT items, 1200 bytes of TXT in total.
- Records are untrusted hints: clients authenticate every host they dial. Keys never enter a record; library names only with `include_libs`.
- Native callbacks copy their results and post to the I/O thread (`io_context::shared_poster`); everything else runs on the I/O thread. A DLL must let native callbacks finish before it unloads.
- Android apps on Wi-Fi need the multicast lock for the wire responder; iOS apps need their Bonjour and local-network declarations.
- The Apple backend is checked against the `dns_sd` header only: it hasn't been built or run (see `Docs/TODO.md`).
