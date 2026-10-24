# compose-sbom

compose-sbom keeps a CycloneDX SBOM for every container image in the compose files of a repository and scans the SBOMs for known vulnerabilities. A reusable GitHub Actions workflow runs it, typically every night and on pushes that change the compose files. The run commits the results to a data branch of the calling repository. When the run finds new alerts, it fails, and GitHub sends a failure notification.

[syft](https://github.com/anchore/syft) creates the SBOMs and [grype](https://github.com/anchore/grype) scans them. syft also detects runtimes that official images compile from source, for example PHP in `php:*` or PostgreSQL in `postgres:*`. Trivy does not list these runtimes, because no package manager records them.

## Setup in a Repository

1. Add the workflow `.github/workflows/sbom.yml`:

   ```yaml
   name: SBOM scan

   on:
     schedule:
       - cron: "17 4 * * *"
     push:
       branches: [main]
       paths:
         - docker-compose.yml
         - sbom/vex.json
         - .github/workflows/sbom.yml
     workflow_dispatch:

   permissions: {}

   concurrency:
     group: sbom
     cancel-in-progress: false

   jobs:
     sbom:
       # Upper bound for the jobs of the reusable workflow. Only its publish
       # job gets contents: write.
       permissions:
         contents: write
         packages: read
       uses: RandomByte/compose-sbom/.github/workflows/scan.yml@COMMIT_SHA # vX.Y.Z
       with:
         compose-files: docker-compose.yml
         # influx-url: ${{ vars.SBOM_INFLUX_URL }}
         # influx-org: ${{ vars.SBOM_INFLUX_ORG }}
       secrets:
         DOCKERHUB_USERNAME: ${{ secrets.DOCKERHUB_USERNAME }}
         DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}
         SBOM_INFLUX_TOKEN: ${{ secrets.SBOM_INFLUX_TOKEN }}
         SBOM_ALERT_WEBHOOK_URL: ${{ secrets.SBOM_ALERT_WEBHOOK_URL }}
   ```

   Replace `COMMIT_SHA` with the full commit SHA of a release. A tag can later move to other code, but a commit SHA always identifies the same code. Dependabot (ecosystem `github-actions`) updates the SHA and the version comment.

2. Set the inputs that the project needs (see "Inputs"). Change the `push.paths` filter so that it lists the compose files.
3. For private images on ghcr.io, open the package settings on GitHub and give the calling repository read access under "Manage Actions access". For now, the workflow does not support private images on other registries. To skip images, set the input `exclude`.
4. Optionally add the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (a read-only access token). Docker Hub limits anonymous pulls, and the first run pulls every image.
5. Add `sbom/data/` to `.gitignore`. This path holds the local worktree of the data branch (see "Local Queries").
6. Start the workflow once with "Run workflow". The first run creates the data branch and reports the baseline.

GitHub sends the failure notification of a scheduled run to the user who last changed the `cron` line.

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `compose-files` | `docker-compose.yml` | Compose files, separated by whitespace |
| `exclude` | | Extended regular expression of image references to skip |
| `extra-images` | | More image references to scan, separated by whitespace |
| `alert-severity` | `critical` | Lowest severity that alerts |
| `alert-epss` | `0.1` | Lowest EPSS score at which `high` findings alert |
| `platform` | `linux/amd64` | Image platform to analyze, must match the server |
| `vex-file` | `sbom/vex.json` | OpenVEX document, see "Triage With VEX" |
| `data-branch` | `sbom-data` | Branch that stores the SBOMs and scan results |
| `project` | repository name | Project name in InfluxDB and the webhook payload |
| `influx-url` | | InfluxDB 2 base URL, for example `https://host:8086` |
| `influx-org` | | InfluxDB organization |
| `influx-bucket` | `sbom` | InfluxDB bucket |

All secrets are optional: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `SBOM_INFLUX_TOKEN` and `SBOM_ALERT_WEBHOOK_URL`. The output `new-alerts` holds the number of new alerts.

## Data Branch Contents

| File | Content |
| --- | --- |
| `index.json` | Image reference, digest and SBOM file for every image |
| `sboms/*.cdx.json` | One CycloneDX SBOM per image |
| `findings.jsonl` | All findings of the last scan, one JSON object per line |
| `new.jsonl` | Alerts that the previous scan did not report |
| `summary.md` | Counts per image and a table of all alerts |

`generate` creates an SBOM only when the registry serves a new digest for the image reference. It also removes the SBOMs of images that the compose files no longer use. `scan` matches all SBOMs against the current vulnerability database, so a CVE published today appears for an image that has not changed in months.

## Alerts

A finding alerts if one of these conditions applies:

- Its severity is `alert-severity` (default `critical`) or higher.
- Its severity is `high` or higher and its [EPSS](https://www.first.org/epss/) score is `alert-epss` (default `0.1`) or higher. EPSS estimates the probability that a CVE is exploited in the next 30 days.
- Its CVE is in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) of exploited vulnerabilities, at any severity.
- The image is based on an end-of-life distribution (ID `distro-eol`).

Findings that the VEX document marks as `not_affected` or `fixed` do not alert (see "Triage With VEX").

The EPSS rule applies only from severity `high`, because EPSS does not measure impact. Old, well-known CVEs such as CVE-2011-3389 have high EPSS scores and severity `negligible`. Critical findings alert at any EPSS score, because a new CVE has a low score until exploitation data exists.

All findings of one vulnerability ID in one image form one alert, for example the same CVE in the packages `chromium` and `chromium-common`.

An alert is new if the previous scan did not report it. The comparison key is the image reference plus the vulnerability ID. Therefore a tag change, for example from `postgres:18.6` to `postgres:18.7`, reports again every alert that the new version still has. The first run reports every alert as new.

For the previous scan, the comparison uses half the EPSS threshold. A score that moves up and down around the threshold from day to day therefore alerts only once.

The summary and the dashboard sort alerts in this order: known exploited vulnerabilities, then end-of-life distributions, then all others by EPSS score.

To send notifications to a channel other than GitHub, pass the secret `SBOM_ALERT_WEBHOOK_URL`. `sbom.sh notify` then sends the new alerts as JSON in a `POST` request:

```json
{"project": "example", "run_url": "https://github.com/...", "count": 1, "findings": [{"image": "postgres:14.5-alpine", "id": "CVE-2025-1094", "aliases": [], "severity": "high", "kev": false, "epss": 0.9003, "package": "postgresql", "version": "14.5", "type": "binary", "fix": "13.19, 14.16, 15.11, 16.7, 17.3"}]}
```

## Triage With VEX

Many findings do not apply to the way a service uses its image, for example a vulnerable library function that the service never calls. Record such decisions in an [OpenVEX](https://github.com/openvex/spec) document at `sbom/vex.json` in the calling repository. `sbom.sh scan` adds the fields `vex` and `vex_justification` to the findings in `findings.jsonl` that a statement covers. Findings with the status `not_affected` or `fixed` do not alert, and `summary.md` lists them in the section "Not Affected According to VEX".

A statement covers a finding if all of these conditions apply:

- `vulnerability.name` or one of `vulnerability.aliases` equals the ID or an alias of the finding. grype reports some vulnerabilities with a GHSA ID and the CVE as alias, so the CVE ID is sufficient.
- One of the `products` is the image, written as in the compose file. A product with a tag or digest covers only that reference. A product without a tag or digest covers every tag of the image.
- If the product has `subcomponents`, the package of the finding is one of them. Write a package as a package URL (`pkg:deb/debian/nginx@1.22.1-9+deb12u10`) or as a plain name (`nginx`). A package with a version covers only that version, so an update of the package needs a new decision.

If several statements cover a finding, the last statement in the document applies.

A statement with the status `not_affected` needs one of the OpenVEX justifications:

| Justification | Use when |
| --- | --- |
| `component_not_present` | The package is listed but not part of the image. |
| `vulnerable_code_not_present` | The installed build does not contain the vulnerable code. |
| `vulnerable_code_not_in_execute_path` | The service never runs the vulnerable code. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | No attacker-controlled input reaches the vulnerable code. |
| `inline_mitigations_already_exist` | A component in front of the service, for example a reverse proxy, prevents the attack. |

Write the reasoning into `impact_statement`, and set `timestamp` to the date of the decision. Example:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/OWNER/REPOSITORY/blob/main/sbom/vex.json",
  "author": "NAME",
  "timestamp": "2026-10-24T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2023-44487"},
      "products": [{"@id": "redimp/otterwiki", "subcomponents": [{"@id": "nginx"}, {"@id": "nginx-common"}]}],
      "status": "not_affected",
      "justification": "inline_mitigations_already_exist",
      "impact_statement": "A reverse proxy terminates HTTP/2 and talks HTTP/1.1 to nginx.",
      "timestamp": "2026-10-24T00:00:00Z"
    }
  ]
}
```

`sbom.sh` matches the statements itself, because grype applies OpenVEX documents (`--vex`) only to image scans and not to SBOM files. The products are image references as written in the compose file. Other tools that read OpenVEX expect package URLs such as `pkg:oci/otterwiki?repository_url=index.docker.io/redimp/otterwiki`, so they do not match these products.

Ignore rules in `.grype.yaml` in the root of the calling repository also apply, because grype reads this file automatically. Matches that an ignore rule removes do not appear in `findings.jsonl`.

## Grafana Dashboard

If the input `influx-url` is set, the workflow writes the results of every run to InfluxDB 2 with `sbom.sh influx`. `grafana-dashboard.json` shows these results:

- Counts with trends
- The images with their severity counts
- Open alerts per image
- All open alerts with links to OSV
- The alerts that each scan added

Several projects can write to the same bucket. Every point has the tag `project`, which holds the input `project` or, if that input is empty, the repository name. The dashboard has a `Project` selector, and its tables use the latest scan of each project. Each project keeps its own SBOMs, data branch and notifications, so its alerts do not depend on the central InfluxDB.

`sbom.sh influx` writes three measurements, all with the timestamp of the run:

| Measurement | Tags | Fields |
| --- | --- | --- |
| `sbom_scan` | `project` | `images`, `findings`, `alerts`, `new_alerts`, `kev`, `eol`, `suppressed` (alerts that VEX statements cover) |
| `sbom_image` | `project`, `image` | `critical`, `high`, `medium`, `low` (distinct vulnerability IDs), `alerts`, `kev`, `eol`, `eol_distro`, `components` |
| `sbom_alert` | `project`, `image`, `id` | `severity`, `kev`, `epss`, `new`, `packages`, `versions`, `fix`, `aliases` |

Without `SBOM_INFLUX_URL`, `sbom.sh influx` prints the line protocol instead.

### Dashboard Setup

1. Create the bucket and a token that can only write to it:

   ```sh
   bucket_id=$(influx bucket create -o ORG -n sbom -r 400d --json | jq -r .id)
   influx auth create -o ORG --write-bucket "$bucket_id" -d "sbom workflow PROJECT" --json | jq -r .token
   ```

   Create one token for each project. For each further project, look up the bucket ID with `influx bucket list -o ORG -n sbom --json | jq -r '.[0].id'` and create only the token.

2. In the calling repository, pass the inputs `influx-url` and `influx-org`, for example from repository variables. Add the secret `SBOM_INFLUX_TOKEN`.
3. The dashboard queries use Flux. If no Grafana datasource of type InfluxDB with the query language Flux can read the bucket, create a read token with `influx auth create -o ORG --read-bucket "$bucket_id"` and add such a datasource.
4. In Grafana, open Dashboards > New > Import, and upload `grafana-dashboard.json`. Select the datasource in the `InfluxDB` variable at the top. If the bucket has a different name, change the constant variable `bucket` in the dashboard settings.

## Local Queries

Clone this repository. In the calling repository, check out the data branch as a worktree at the default data directory:

```sh
git fetch origin sbom-data
git worktree add sbom/data origin/sbom-data
```

To update the worktree later, fetch again and run `git -C sbom/data checkout --detach origin/sbom-data`. Run `sbom.sh` from the root of the calling repository. The example queries use `~/src/compose-sbom` as the clone:

```sh
# List the images that contain PHP, with the PHP version
~/src/compose-sbom/sbom.sh find '^php'

# Find CVE-2024-5535 in all images. The CVE can also be an alias of a GHSA ID.
rg CVE-2024-5535 sbom/data/findings.jsonl

# List all critical findings that have a fix
jq -c 'select(.severity == "critical" and .fix != "")' sbom/data/findings.jsonl
```

`sbom.sh generate` and `scan` also run locally. They need `syft`, `grype`, `jq`, `yq` (mikefarah) and `docker` with buildx for digest lookups. Set `SBOM_DATA_DIR` to a scratch directory to keep local results apart from the worktree. `sbom.sh` without arguments lists the commands and environment variables.

## Limits

- The scan covers the digest that the registry serves for a tag at scan time. The digest that runs on the server can be older, for example because Docker Swarm resolves the tag at deploy time.
- The SBOMs do not contain software that is installed or updated at runtime in volumes, for example application plugins. They also do not contain the host OS and Docker Engine.
- `sbom.sh` does not resolve compose variables. It skips image references with variables such as `${TAG}` and prints a warning.
- syft detects compiled binaries only for runtimes that it has a classifier for. grype matches these binaries by CPE, and CPE matching can cause false positives.

## Releases

Each release is a tag `vX.Y.Z` on `main`. Calling repositories pin the commit SHA of the tag. The reusable workflow checks out this repository at the same commit (`job.workflow_sha`), so the workflow and `sbom.sh` always match.

## Updating syft and grype

The workflow installs pinned releases and checks their SHA-256 hashes, because a release tag can later point to modified code (see the [Trivy compromise of March 2026](https://github.com/aquasecurity/trivy/discussions/10425)). To update, verify the checksum file of the new release and copy the `linux_amd64` hash into `.github/workflows/scan.yml`:

```sh
v=1.55.0 n=syft
curl -sLO "https://github.com/anchore/$n/releases/download/v$v/${n}_${v}_checksums.txt"
curl -sLO "https://github.com/anchore/$n/releases/download/v$v/${n}_${v}_checksums.txt.sigstore.json"
cosign verify-blob --bundle "${n}_${v}_checksums.txt.sigstore.json" \
  --certificate-identity "https://github.com/anchore/$n/.github/workflows/release.yaml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "${n}_${v}_checksums.txt"
grep linux_amd64.tar.gz "${n}_${v}_checksums.txt"
```
