# Security

Report a suspected vulnerability privately to [@artemkaa_2001](https://t.me/artemkaa_2001). Include the affected version, distribution/kernel/nftables versions, reproduction steps and impact. Do not publish a live server's administrative addresses, credentials or unredacted configuration in a public issue.

Only the current code line is maintained; no guaranteed response time or security support period is promised. Review changes before installing them as root.

GeoLatch deliberately controls only its owned nftables table. Invalid or suspicious data must leave the previous rules active. An SSH rollback watchdog reduces the risk of accidental lockout but cannot guarantee connectivity through unrelated firewalls, provider NAT or external failures. Maintain a provider console or another independent administrative path. See [security design and recovery](docs/security.md).

No API keys are required for the supported GeoIP sources. Source and local hash validation do not provide an independent cryptographic upstream signature. GeoIP attribution is approximate and should not be an authorization boundary.
