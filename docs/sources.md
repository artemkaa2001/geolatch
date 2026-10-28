# GeoIP sources and data licenses

GeoLatch fetches country/family CIDR text files directly from the selected upstream. It does not ship the GeoIP datasets and does not use MaxMind mirrors.

| Configuration | Upstream | Meaning |
| --- | --- | --- |
| `ipverse-geo` | [ipverse/geo-ip-blocks](https://github.com/ipverse/geo-ip-blocks) | Granular country lists derived from network registration records; not proof of physical location. |
| `ipverse-rir` | [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) | Compact lists derived from regional registry allocations; registration country differs from end-user location. |

Live GitHub source inspection on 2026-10-28 verified both repositories' `master` branch layouts. The granular source uses `country/{cc}/{cc}-ipv4.txt` and `country/{cc}/{cc}-ipv6.txt`, checked against the Marshall Islands (`mh`) files. The compact source uses `country/{cc}/ipv4-aggregated.txt` and `country/{cc}/ipv6-aggregated.txt`, checked against Andorra (`ad`). Missing countries/families, upstream layout changes and HTML responses are errors; GeoLatch does not silently switch source or apply an empty substitute.

Both upstream `LICENSE` files were verified as **CC0 1.0 Universal** on 2026-10-28: [geo license](https://github.com/ipverse/geo-ip-blocks/blob/master/LICENSE), [RIR license](https://github.com/ipverse/country-ip-blocks/blob/master/LICENSE). Both had Git blob SHA `0e259d42c996742e9e3cba14c677129b2c1b6311` during that inspection. These terms are independent of GeoLatch's MIT application license. Check the current upstream source notices and terms before redistributing downloaded data; no upstream CIDR dataset is bundled here.

The granular upstream notes that documentation, benchmark and CGNAT ranges were removed on 2026-09-28, and limits its published prefix lengths to IPv4 `/28` and IPv6 `/56`. Its country attribution is based on network registration data; the RIR provider uses coarser delegation records. Neither source establishes an end user's physical location.

MaxMind GeoLite2 is not required. Official GeoLite2 distribution requires an account/license key and has redistribution conditions; adding it would need a separate reviewed provider and documentation.

Localized country display names are derived from Debian `iso-codes`; see the bundled LGPL-2.1-or-later notice in `geolatch/locales/COUNTRIES-LICENSE.txt`. Those names do not contain GeoIP network data.
