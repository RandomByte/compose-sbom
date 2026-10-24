# SBOM Scan Summary

Scanned with grype 0.0.0-test, vulnerability database built 2026-10-01T00:00:00Z. Findings alert at severity `critical` and above, at severity `high` from an EPSS of 0.1 on, for entries in the CISA KEV catalog, and for end-of-life distributions. Findings that the VEX document marks as `not_affected` or `fixed` do not alert. Tables list known exploited first, then by EPSS.

## Images

Counts are distinct vulnerability IDs.

| Image | Critical | High | Medium | Low | EOL distro |
| --- | --- | --- | --- | --- | --- |
| `app:1.0` | 3 | 4 | 1 | 0 |  |
| `db:2` | 0 | 0 | 0 | 1 | alpine 3.18 |

## New Alerts

| Image | ID | Severity | KEV | EPSS | Packages | Versions | Fixed in |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `app:1.0` | CVE-2026-5000 | critical | yes | 15% | chromium, chromium-common | 120.0 | 120.1 |
| `db:2` | distro-eol | eol |  | 0% | alpine | 3.18 |  |
| `app:1.0` | CVE-2026-4000 | high |  | 12% | curl | 8.0.0 |  |
| `app:1.0` | GHSA-aaaa-bbbb-cccc (CVE-2026-1000) | critical |  | 2% | libfoo | 1.2.3 | 1.2.4, 2.0.1 |

## All Alerts

| Image | ID | Severity | KEV | EPSS | Packages | Versions | Fixed in |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `app:1.0` | CVE-2026-5000 | critical | yes | 15% | chromium, chromium-common | 120.0 | 120.1 |
| `db:2` | distro-eol | eol |  | 0% | alpine | 3.18 |  |
| `app:1.0` | CVE-2026-2000 | high |  | 30% | openssl | 3.0.1 |  |
| `app:1.0` | CVE-2026-3000 | high |  | 12% | zlib | 1.2.13 |  |
| `app:1.0` | CVE-2026-4000 | high |  | 12% | curl | 8.0.0 |  |
| `app:1.0` | GHSA-aaaa-bbbb-cccc (CVE-2026-1000) | critical |  | 2% | libfoo | 1.2.3 | 1.2.4, 2.0.1 |

## Not Affected According to VEX

Findings that would alert without the statements in the VEX document.

| Image | ID | Severity | Packages | Status | Justification |
| --- | --- | --- | --- | --- | --- |
| `app:1.0` | CVE-2026-6000 | critical | libbar | not_affected | vulnerable_code_not_present |
