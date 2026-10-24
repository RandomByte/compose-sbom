# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Repository Purpose

compose-sbom is a reusable GitHub Actions workflow plus one Bash script. Other repositories call `.github/workflows/scan.yml`. The workflow runs `sbom.sh` to create a CycloneDX SBOM (syft) for every image in their compose files, scan the SBOMs (grype), and commit the results to a data branch of the calling repository. README.md is the user-facing documentation and describes every input, file format and alert rule in detail.

There is no build step. The repository has these artifacts:

- `sbom.sh`: all logic, as subcommands `generate`, `scan`, `notify`, `influx`, `find`.
- `.github/workflows/scan.yml`: the reusable workflow that calls `sbom.sh`.
- `.github/workflows/test.yml`: runs the tests and the linters on pushes to `main` and on pull requests.
- `tests/`: the test suite for `sbom.sh`, see "Tests".
- `grafana-dashboard.json`: Flux queries over the InfluxDB points that `sbom.sh influx` writes.
- `skills/sbom-triage/`: an agent skill that calling repositories copy, to triage findings and write VEX statements. It must work without this repository, so it repeats the data branch layout, the `findings.jsonl` schema and the VEX matching rules.

## Lint Commands

```sh
shellcheck sbom.sh tests/run.sh tests/bin/grype
shfmt -d sbom.sh tests/run.sh tests/bin/grype   # default shfmt style: tabs, case labels not indented
actionlint -ignore 'property "workflow_(repository|sha)" is not defined'
zizmor .github/workflows
```

The `-ignore` of `actionlint` suppresses false positives for `job.workflow_repository` and `job.workflow_sha`: actionlint does not know these context properties yet. `.shellcheckrc` sets `external-sources=true`, so shellcheck follows the `source` of `sbom.sh` in `tests/run.sh`. `.github/workflows/test.yml` runs the same commands with pinned versions.

## Tests

```sh
tests/run.sh
```

The tests need only bash and jq. `tests/run.sh` sources `sbom.sh`, which returns before its `case` statement when it is sourced, and calls `VEX_APPLY`, `ALERTING` and `alert_args` directly. For `sbom.sh scan` and `sbom.sh influx`, `tests/bin/grype` replaces grype: it prints the file of `grype sbom:FILE`, so the data directory holds grype JSON reports in place of SBOMs.

- VEX matching and the alert rule are table tests in `tests/run.sh` over the findings in `tests/fixtures/`.
- `tests/scan/` holds one scan scenario: the grype reports of two images, the previous `findings.jsonl` and a VEX document. `tests/scan/expected/` holds the expected `findings.jsonl`, `new.jsonl`, `summary.md` and the InfluxDB line protocol with `TIME` for the timestamp.

When a change to `sbom.sh` changes the scan output on purpose, run `SBOM_TEST_UPDATE=1 tests/run.sh` and review the diff of `tests/scan/expected/`. The expected `summary.md` and `influx.txt` are contracts with the skill and with `grafana-dashboard.json`. When `pkg_match` or `image_match` changes, add rows to the tables in `tests/run.sh`.

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

When changing `EXTRACT`, `VEX_APPLY`, the section names of `summary.md`, the data branch layout or a workflow input that the skill reads, update `skills/sbom-triage/SKILL.md` and `skills/sbom-triage/references/vex.md` as well. The skill reads the open alerts from `summary.md` on purpose, so it does not repeat the alert rule.

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
