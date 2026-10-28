# Localization

The user interface supports `en` and `ru`. Translation catalogs live in `geolatch/locales` and the TUI catalogs under `geolatch/tui/locales`. Stable keys are shared by callers; messages interpolate named arguments. JSON machine keys, nftables identifiers, YAML keys, ISO country codes and raw system error details are technical values and stay unchanged.

The first setup screen offers both languages before displaying a localized wizard. The saved language is reused at the next launch. Settings → Language changes the current application immediately. `geolatch --lang ru status` overrides a CLI invocation without editing the saved preference.

English fallback is available for an absent key, but complete English/Russian key and interpolation parity is tested so missing translations do not silently become normal behavior. The formatter handles Unicode, dates and Russian one/few/many plural forms. Keep machine JSON independent of locale.

Country labels contain all ISO 3166-1 country codes with English and Russian display names derived from Debian `iso-codes`. Those display-name data have a separate LGPL-2.1-or-later notice; see `geolatch/locales/COUNTRIES-LICENSE.txt`. Country codes remain the source identifiers. GeoIP availability can differ by provider and family, so appearing in a country list is not a guarantee of a nonempty upstream IPv6 dataset.

When adding a user-facing message, add it to both catalogs, preserve named placeholder parity, and add a behavior test where it helps. Keep user strings out of business logic except technical errors whose context is translated by a caller.
