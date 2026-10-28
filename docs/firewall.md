# Firewall behavior and compatibility

GeoLatch uses a single owned `inet geolatch` table. A matching name without the GeoLatch ownership marker is treated as a collision, not as permission to delete someone else's table. Every replace/delete transaction is limited to that owned table; no global ruleset flush is used.

The prerouting filter chain has priority `-150`. Linux conntrack attaches around `-200`, and conventional destination NAT runs at `-100`, so GeoLatch observes original incoming destination addresses while connection state is available. This includes normal local services and conventional host-side DNAT/published container ports. Custom earlier DNAT hooks can change these assumptions.

Rules constrain ingress interface, IP family, source country and chosen destination. Identical country data is reused through interval sets; networks are normalized and overlapping/adjacent entries collapsed before rules generation. No rule is generated for every individual prefix. Drops carry nftables counters rather than packet logging.

Trusted sources, required IPv6 Neighbor Discovery and preserved established/related connections return from GeoLatch's chain. They still encounter other base chains and security controls. There is no unconditional global accept. Conntrack original direction is used so inbound replies to server-originated connections are not classified as incoming country blocks. Existing TCP/UDP flows are preserved by default; disabling that setting can interrupt them and needs a safe apply.

| Environment | What to verify |
| --- | --- |
| UFW / iptables-nft | No third-party reload deletes `inet geolatch`; base-chain ordering remains expected. |
| Docker | Actual packet arrives on a selected ingress interface and uses the selected pre-DNAT host address. |
| Nginx / HAProxy | Client packets reach this server; if a remote reverse proxy terminates traffic, its IP is the source. |
| Xray / VPN | Outer ingress and tunnel traffic have different interfaces and source/destination visibility. |
| Provider NAT | This host may see a private destination rather than the advertised public address. |
| IPv6 | Selected addresses exist, IPv6 is enabled, essential Neighbor Discovery survives and chosen GeoIP source has data. |
| notrack | Conntrack-dependent semantics do not apply normally; investigate doctor warnings and do not claim compatibility without a packet test. |
| Flowtables/offload | Already offloaded traffic may bypass normal hooks; separately test or exclude affected flows. |

Atomic replacement is one nftables batch after a syntax/kernel check. It does not temporarily empty the live table while data downloads. A failed transaction should leave the old table in place; post-apply verification failures trigger recovery. Counters reset when the table is replaced and are not a persistent accounting system.

Kernel integration tests run only in network namespaces. Their results are scoped to the test kernel and nftables version. Reboot, UFW reload, real Docker, VPN, proxy and high-throughput behavior need validation on the target machine; successful rule generation is insufficient evidence.
