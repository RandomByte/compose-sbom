# VEX Document Reference

This file describes the OpenVEX document that `sbom.sh scan` reads, the rules by which it matches statements to findings, and how to choose the scope of a statement.

## Contents

- Document Format
- Statuses
- Justifications
- Matching Rules
- Scope of a Statement
- Examples

## Document Format

The workflow input `vex-file` sets the path, default `sbom/vex.json`. If the file does not exist, create it with this skeleton. Take the `@id` from the repository URL, and ask the user for the `author` if it is not clear from the git configuration.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/OWNER/REPOSITORY/blob/main/sbom/vex.json",
  "author": "NAME",
  "timestamp": "2026-10-24T00:00:00Z",
  "version": 1,
  "statements": []
}
```

A statement has these fields:

| Field | Content |
| --- | --- |
| `vulnerability.name` | The vulnerability ID, for example `CVE-2023-44487` |
| `vulnerability.aliases` | Optional, more IDs of the same vulnerability |
| `products` | List of images, each `{"@id": "<image>"}`, optionally with `subcomponents` |
| `products[].subcomponents` | Optional, list of packages, each `{"@id": "<package>"}` |
| `status` | See "Statuses" |
| `justification` | Required for `not_affected`, see "Justifications" |
| `impact_statement` | The reasoning, for `not_affected` |
| `action_statement` | What the maintainer does, for `affected` |
| `timestamp` | Date of the decision |

Keep the existing formatting of the document. If the document has no formatting yet, use two-space indentation and one line for short objects such as `vulnerability`.

## Statuses

| Status | Effect in compose-sbom |
| --- | --- |
| `not_affected` | The findings do not alert. `summary.md` lists them under "Not Affected According to VEX". |
| `fixed` | The same as `not_affected`. Use only if the image contains a fix that the scanner cannot see. |
| `affected` | The findings still alert. Records that the maintainer accepts the alert, with an `action_statement`. |
| `under_investigation` | The findings still alert. |

`affected` and `under_investigation` change no alert. Write them only if the user wants the decision on record. Because the last matching statement applies, an `affected` statement after a `not_affected` statement opens the alert again.

## Justifications

A `not_affected` statement needs exactly one justification. The evidence column lists what the impact statement has to show.

| Justification | Use when | Evidence |
| --- | --- | --- |
| `component_not_present` | The scanner lists the package, but the image does not contain it. | The path from the SBOM does not exist in the image, or the finding comes from a CPE match on a different product. |
| `vulnerable_code_not_present` | The installed build does not contain the vulnerable code. | A build option, a distribution patch, or a version range of the vulnerable code that the installed build is outside of, with a source. |
| `vulnerable_code_not_in_execute_path` | The service never runs the vulnerable code. | The vulnerable function or feature, and why the service does not call it, for example the binary that contains it and when that binary runs. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | The vulnerable code runs, but no attacker-controlled input reaches it. | The input that the attack needs, and where the service gets that input from instead. |
| `inline_mitigations_already_exist` | A component in front of the service, or a configuration setting, prevents the attack. | The component or setting, with the file and line that configure it, and the paths that do not go through it. |

## Matching Rules

`sbom.sh` matches the statements itself, because grype does not apply OpenVEX documents to SBOM input. A statement covers a finding if all of these conditions apply:

1. `vulnerability.name` or one of `vulnerability.aliases` equals the `id` or one of the `aliases` of the finding. grype reports some vulnerabilities with a GHSA or GO ID and the CVE as alias, so the CVE ID is sufficient.
2. One of the `products` is the image of the finding:
   - A product with a tag or digest covers only that exact reference, for example `postgres:18.6`.
   - A product without a tag or digest covers every tag of the image, for example `postgres` covers `postgres:18.6` and `postgres:18.7`.
   - The comparison is a string comparison against the image reference as written in the compose file. `postgres`, `docker.io/postgres` and `docker.io/library/postgres` are three different products. Copy the reference from the `image` field of `findings.jsonl`.
3. If the product has `subcomponents`, the `package` of the finding is one of them:
   - Write a package as `name` or as `name@version`. Copy name and version from the `package` and `version` fields of `findings.jsonl`, for example `golang.org/x/net@v0.59.0` or `@langchain/redis@1.0.0`. The name must equal the full `package` field. A package with a version covers only that version.
   - A package URL such as `pkg:deb/debian/nginx@1.22.1-9+deb12u10` also works, but only with the version as plain text. The package URLs in the SBOM files percent-encode the version (`%2B` for `+`, `%3A` for `:`) and the npm scope (`%40` for `@`), and in that form they do not match. A package URL also matches a package named like its last path segment, so `pkg:golang/golang.org/x/net` also covers a package `net`. Prefer the plain `name@version` form.
   - Without `subcomponents`, the statement covers every package of the image that has this vulnerability.

If several statements cover a finding, the last statement in the document applies. `sbom.sh` does not check `status_notes`, `action_statement` or the timestamps.

## Scope of a Statement

A narrow statement stops matching when something changes, and the alert opens again. This forces a new review. A broad statement keeps matching after updates. Choose the scope by what the reasoning depends on:

| The reasoning depends on | Product | Subcomponents |
| --- | --- | --- |
| The deployment: a reverse proxy, a network, a setting in this repository | Image without tag | Package names without version |
| How the image uses the package: which binary contains it, when that binary runs | Image without tag | Package names without version |
| The contents of one build: code not present, a CPE match on a different product, a backported fix | Image with tag | Packages with version |

List the packages in `subcomponents` whenever possible, so that the statement does not cover other packages of the image that later report the same vulnerability. Use one statement for several images only if the reasoning is the same for all of them. Otherwise, write one statement per image.

## Examples

These examples show the shape of a statement. The reasoning in them applies only to the deployment that they describe.

example: the reasoning depends on the deployment, so the product has no tag.

```json
{
  "vulnerability": {"name": "CVE-2023-44487"},
  "products": [{"@id": "redimp/otterwiki", "subcomponents": [{"@id": "nginx"}, {"@id": "nginx-common"}]}],
  "status": "not_affected",
  "justification": "inline_mitigations_already_exist",
  "impact_statement": "HTTP/2 Rapid Reset needs an HTTP/2 connection to nginx. otterwiki publishes no ports, and traefik terminates HTTP/2 from clients and connects to nginx with HTTP/1.1 (no h2c scheme on the router in docker-compose.yml). Other containers on traefik-net can still connect to nginx directly.",
  "timestamp": "2026-10-24T00:00:00Z"
}
```

example: the reasoning depends on one build, so the product has a tag and the package has a version.

```json
{
  "vulnerability": {"name": "CVE-2026-12345"},
  "products": [{"@id": "telegraf:1.40.2", "subcomponents": [{"@id": "libfoo@1.2.3-1+deb12u1"}]}],
  "status": "not_affected",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "The vulnerable parser is behind the build option --enable-bar. The Debian build of libfoo 1.2.3-1+deb12u1 does not set it (debian/rules), and the Debian tracker marks bookworm as not affected.",
  "timestamp": "2026-10-24T00:00:00Z"
}
```
