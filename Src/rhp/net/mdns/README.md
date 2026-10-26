# DNS-SD discovery

Discovery policies for `Rhp::config<>::discovery<D>`. Nothing is published until `host.advertise()`; clients find hosts with `Rhp::discover<Cfg>()`, `Rhp::fleet::discover()` or `rhp-cli discover`. Stream transports publish under `_rhp._tcp`, reliable UDP under `_rhp._udp` (`dns_sd_service`).

| Policy | Windows | Apple | Linux, Android |
|---|---|---|---|
| `mdns` (default) | DNS-SD API (`windns.h`); a listener bound to one address uses the wire responder, which can publish that address | `dns_sd`, owning the address and service records; local-only for loopback | the wire responder |
| `mdns_wire` | own multicast responder and querier everywhere | | |
| `no_discovery` | the opt-out: `advertise` and browsing report `kDisabled` | | |

```cpp
Rhp::net::advertise_options ad;
ad.app = "my_game";
ad.build = "1234";
(void)host.advertise(ad);                                   // pump thread, after install<>()
auto found = Rhp::discover<>(Rhp::net::browse_options{.app = "my_game"});
```

- `detail/dns.hpp` is the sans-IO DNS codec (`rr_type`, `dns_record`, `read_dns`, `dns_service_packet`, `dns_query`); `detail/metadata.hpp` maps a `service_record` to DNS-SD names and TXT and back (`service_txt`, `read_service_txt`, `matches`).
- The wire responder (`wire.cpp`): probes 3 × 250 ms (after a random 0–250 ms delay), announces twice a second apart, then only answers queries; sends goodbyes (TTL 0); re-probes a renamed record, re-announces an updated one; resolves host-name listen addresses asynchronously. An answer puts the records the query asked for in the answer section and the rest in the additional section (RFC 6763 §12), as Windows' own responder does; announcements put every record in the answer section. (Windows' `DnsServiceResolve` ignores an SRV or TXT among unasked answers and re-asks without end.)
- The querier: continuous queries from 1 s doubling to a minute, follow-up queries for missing records, a TTL cache. Responder and querier share one CRTP `multicast_endpoint` (IPv4 224.0.0.251 and IPv6 ff02::fb, UDP 5353).
- Bounds: 9000-byte packets, 128 questions + records per packet, 1024 cached records, 255-byte TXT items, 1200 bytes of TXT in total.
- Records are untrusted hints: clients authenticate every host they dial, and a record can't enable plaintext. Keys never enter a record; library names only with `include_libs`.
- Native callbacks copy their results and post to the I/O thread (`io_context::shared_poster`); everything else runs on the I/O thread. A DLL must let native callbacks finish before it unloads.
- Android apps on Wi-Fi need the multicast lock for the wire responder; iOS apps need their Bonjour and local-network declarations.
- Tests that use real multicast are tagged `[multicast]` (one ctest `RESOURCE_LOCK`, label `multicast`). The Apple backend is built by hosted CI (macOS, iOS simulator, iOS device) but hasn't run against real multicast yet (see `Docs/TODO.md`).
