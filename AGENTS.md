# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Repository Purpose

compose-sbom is a reusable GitHub Actions workflow plus one Bash script. Other repositories call `.github/workflows/scan.yml`. The workflow runs `sbom.sh` to create a CycloneDX SBOM (syft) for every image in their compose files, scan the SBOMs (grype), and commit the results to a data branch of the calling repository. README.md is the user-facing documentation and describes every input, file format and alert rule in detail.

There is no build step and no test suite. The repository has three code artifacts:

- `sbom.sh`: all logic, as subcommands `generate`, `scan`, `notify`, `influx`, `find`.
- `.github/workflows/scan.yml`: the reusable workflow that calls `sbom.sh`.
- `grafana-dashboard.json`: Flux queries over the InfluxDB points that `sbom.sh influx` writes.

## Lint Commands

```sh
shellcheck sbom.sh
shfmt -d sbom.sh          # default shfmt style: tabs, case labels not indented
actionlint
zizmor .github/workflows/scan.yml
```

`actionlint` currently reports `property "workflow_repository" is not defined` and the same for `workflow_sha` on `job.*`. These are false positives: actionlint does not know these context properties yet. All other linters pass clean.

## Running Locally

Run `sbom.sh` from the root of a calling repository, not from this repository. It needs `syft`, `grype`, `jq`, `yq` (mikefarah, not the Python one) and `docker` with buildx. Point `SBOM_DATA_DIR` at a scratch directory so local results do not mix with a real data branch worktree:

```sh
SBOM_DATA_DIR=/tmp/sbom-test ~/path/to/compose-sbom/sbom.sh generate docker-compose.yml
SBOM_DATA_DIR=/tmp/sbom-test ~/path/to/compose-sbom/sbom.sh scan
SBOM_DATA_DIR=/tmp/sbom-test ~/path/to/compose-sbom/sbom.sh influx   # prints line protocol without SBOM_INFLUX_URL
```

`sbom.sh` without arguments prints all commands and `SBOM_*` environment variables.

## Architecture of `sbom.sh`

Most logic is jq programs held in shell variables and combined at call sites:

- `EXTRACT` turns one grype JSON report into one finding per line (`findings.jsonl` schema). End-of-life distributions become pseudo-findings with `id: "distro-eol"` and `severity: "eol"`.
- `VEX_APPLY` matches OpenVEX statements against findings itself, because `grype --vex` does not work on SBOM input. It adds the fields `vex` and `vex_justification`.
- `ALERTING` is a library of jq `def`s (`alerting`, `alert_worthy`, `suppressed`, `grouped`, `priority`, `key`). Callers prepend it to their own program, as in `"$ALERTING"'...'`, and must pass `"${ALERT_ARGS[@]}"`, which `alert_args` sets and validates.

The alert rule lives only in `ALERTING`, and `scan`, `write_summary` and `influx` all reuse it. Change it there, and keep README.md "Alerts" in sync.

Key behaviors that span several functions:

- `generate` keys `index.json` by the image reference as written in the compose file. It runs syft only when the registry digest changes, and it removes entries for images that the compose files no longer list.
- `scan` computes `new.jsonl` by comparing current alerts against the previous `findings.jsonl` under the current settings. The previous side uses half the EPSS threshold as hysteresis. The alert key is `image|id`.
- `influx` writes all points of one run with the same timestamp. The dashboard relies on this to select "the latest scan" per project. Measurement, tag and field names are a contract with `grafana-dashboard.json` and the README table, so change all three together.

## Workflow Design Constraints

- The workflow checks out this repository at `job.workflow_sha`, so the caller's pinned SHA fixes both the workflow and `sbom.sh`. Do not add a separate version pin for the script.
- Permissions are split: the `scan` job is read-only, and only the `publish` job has `contents: write`. Results move between them as an artifact.
- The `Scan SBOMs` step runs with `!cancelled()` after a failed generate, so partial results are still scanned and published.
- Every third-party action is pinned by commit SHA with a version comment. syft and grype are downloaded at pinned versions with SHA-256 checks in the `env` block. README.md "Updating syft and grype" has the cosign verification procedure for new hashes.
- `# zizmor: ignore[...]` comments mark deliberate exceptions, each with a reason comment above it.
- When adding a workflow input, also add the matching `SBOM_*` variable to `sbom.sh` (defaults and `usage`) and the README "Inputs" table.

## Releases

A release is a tag `vX.Y.Z` on `main`. Calling repositories pin the commit SHA of the tag.
