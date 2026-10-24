#!/usr/bin/env bash
# Tests for sbom.sh. They need bash and jq only: tests/bin/grype replaces
# grype, and no test pulls an image.
#
# Usage: tests/run.sh
# With SBOM_TEST_UPDATE=1, the scan tests overwrite the files in
# tests/scan/expected with the current output. Review the diff before a
# commit.
set -euo pipefail

TESTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FIXTURES=$TESTS/fixtures
# shellcheck source=SCRIPTDIR/../sbom.sh
source "$TESTS/../sbom.sh"

passed=0
failed=0

# Runs the command and compares its output (stdout and stderr) with the
# expected text. A non-zero exit status is appended to the output.
check() {
	local name=$1 expected=$2 actual
	shift 2
	actual=$("$@" 2>&1) || actual+=" (exit $?)"
	if [[ $actual == "$expected" ]]; then
		passed=$((passed + 1))
	else
		failed=$((failed + 1))
		printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$name" "$expected" "$actual"
	fi
}

# Compares a file with the expected file in tests/scan/expected.
check_file() {
	local name=$1 expected=$TESTS/scan/expected/$2 actual=$3
	if [[ ${SBOM_TEST_UPDATE:-} == 1 ]]; then
		cp "$actual" "$expected"
	fi
	if diff -u "$expected" "$actual" >"$WORK/diff"; then
		passed=$((passed + 1))
	else
		failed=$((failed + 1))
		echo "FAIL $name"
		sed 's/^/  /' "$WORK/diff"
	fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

## VEX matching

# Prints an OpenVEX document with one not_affected statement for
# GO-2026-6612 and the given products.
vex_doc() {
	jq -nc --argjson products "$1" '{statements: [{vulnerability: {name: "GO-2026-6612"}, products: $products, status: "not_affected", justification: "vulnerable_code_not_in_execute_path"}]}'
}

# Prints the field (package or image) of the findings in the fixture file
# that the VEX document covers, sorted and separated by spaces.
covered() {
	jq -c --argjson vex "$3" "$VEX_APPLY" "$FIXTURES/$2" |
		jq -rs --arg field "$1" '[.[] | select(.vex) | .[$field]] | sort | join(" ")'
}

# Prints "package=status" for every finding in vex-packages.jsonl.
statuses() {
	jq -c --argjson vex "$1" "$VEX_APPLY" "$FIXTURES/vex-packages.jsonl" |
		jq -rs 'map("\(.package)=\(.vex // "-")") | join(" ")'
}

subcomponent() {
	check "subcomponent '$1'" "$2" covered package vex-packages.jsonl \
		"$(vex_doc "$(jq -nc --arg s "$1" '[{"@id": "telegraf", subcomponents: [{"@id": $s}]}]')")"
}

subcomponent golang.org/x/net golang.org/x/net
subcomponent golang.org/x/net@v0.59.0 golang.org/x/net
subcomponent golang.org/x/net@v0.58.0 ''
subcomponent @langchain/redis @langchain/redis
subcomponent @langchain/redis@1.0.0 @langchain/redis
subcomponent redis redis
subcomponent stdlib@go1.25.1 stdlib
subcomponent nginx nginx
subcomponent nginx@1.22.1-9+deb12u10 nginx
subcomponent pkg:deb/debian/nginx@1.22.1-9+deb12u10 nginx
subcomponent 'pkg:deb/debian/nginx?arch=amd64' nginx
subcomponent '' ''
subcomponent @ ''
# Known limitations: a package URL also matches its last path segment, and
# percent-encoded versions and scopes do not match.
subcomponent pkg:golang/golang.org/x/net 'golang.org/x/net net'
subcomponent pkg:golang/golang.org/x/net@v0.59.0 'golang.org/x/net net'
subcomponent pkg:deb/debian/nginx@1.22.1-9%2Bdeb12u10 ''
subcomponent 'pkg:npm/%40langchain/redis@1.0.0' redis

product() {
	check "product '$1'" "$2" covered image vex-images.jsonl "$(vex_doc "$(jq -nc --arg p "$1" '[{"@id": $p}]')")"
}

product postgres 'postgres:18.6 postgres:18.7'
product postgres:18.6 postgres:18.6
product postgres:18 ''
product docker.io/postgres ''
product docker.io/library/postgres docker.io/library/postgres:18.6
product localhost:5000/app localhost:5000/app:1.0
product localhost:5000/app:1.0 localhost:5000/app:1.0
product ghcr.io/owner/app ghcr.io/owner/app@sha256:1111
product ghcr.io/owner/app@sha256:1111 ghcr.io/owner/app@sha256:1111
product ghcr.io/owner/app@sha256:2222 ''

all='golang.org/x/net=not_affected net=not_affected stdlib=not_affected nginx=not_affected @langchain/redis=not_affected redis=not_affected'
none='golang.org/x/net=- net=- stdlib=- nginx=- @langchain/redis=- redis=-'
statement() {
	check "$1" "$2" statuses "{\"statements\": [$3]}"
}
P='"products": [{"@id": "telegraf"}], "status": "not_affected"'
statement "vulnerability by name" "$all" "{\"vulnerability\": {\"name\": \"GO-2026-6612\"}, $P}"
statement "vulnerability by @id" "$all" "{\"vulnerability\": {\"@id\": \"GO-2026-6612\"}, $P}"
statement "vulnerability as string" "$all" "{\"vulnerability\": \"GO-2026-6612\", $P}"
statement "vulnerability name is a finding alias" "$all" "{\"vulnerability\": {\"name\": \"CVE-2026-78663\"}, $P}"
statement "vulnerability alias is the finding ID" "$all" "{\"vulnerability\": {\"name\": \"X-1\", \"aliases\": [\"GO-2026-6612\"]}, $P}"
statement "other vulnerability" "$none" "{\"vulnerability\": {\"name\": \"CVE-2026-0001\"}, $P}"
statement "other product" "$none" '{"vulnerability": {"name": "GO-2026-6612"}, "products": [{"@id": "postgres"}], "status": "not_affected"}'
statement "one of several products" "$all" '{"vulnerability": {"name": "GO-2026-6612"}, "products": [{"@id": "postgres"}, {"@id": "telegraf"}], "status": "not_affected"}'
statement "last statement applies" "${all/stdlib=not_affected/stdlib=affected}" \
	"{\"vulnerability\": {\"name\": \"GO-2026-6612\"}, $P}, {\"vulnerability\": {\"name\": \"GO-2026-6612\"}, \"products\": [{\"@id\": \"telegraf\", \"subcomponents\": [{\"@id\": \"stdlib\"}]}], \"status\": \"affected\"}"
check "no statements" "$none" statuses '{}'
check "justification" "vulnerable_code_not_in_execute_path" \
	jq -r --argjson vex "$(vex_doc '[{"@id": "telegraf"}]')" "$VEX_APPLY"' | select(.package == "stdlib") | .vex_justification' "$FIXTURES/vex-packages.jsonl"

# A product or subcomponent without a string "@id" matches nothing. It must
# not fail and must not widen the statement.
malformed() {
	check "malformed: $1" "$2" covered package vex-packages.jsonl "$(vex_doc "$3")"
}
malformed "subcomponent with identifiers only" '' '[{"@id": "telegraf", "subcomponents": [{"identifiers": {"purl": "pkg:golang/golang.org/x/net"}}]}]'
malformed "subcomponent with numeric @id" stdlib '[{"@id": "telegraf", "subcomponents": [{"@id": "stdlib"}, {"@id": 7}]}]'
malformed "subcomponents as string" '' '[{"@id": "telegraf", "subcomponents": "stdlib"}]'
malformed "subcomponents as object" stdlib '[{"@id": "telegraf", "subcomponents": {"@id": "stdlib"}}]'
malformed "empty subcomponents" '@langchain/redis golang.org/x/net net nginx redis stdlib' '[{"@id": "telegraf", "subcomponents": []}]'
malformed "product with identifiers only" '' '[{"identifiers": {"purl": "pkg:oci/telegraf"}}]'
malformed "product as string" '' '["telegraf"]'
malformed "product with empty and null @id" '@langchain/redis golang.org/x/net net nginx redis stdlib' '[{"@id": ""}, {"@id": null}, {"@id": "telegraf:1.40.2"}]'

## Alert rule

# Prints the IDs of the findings in alerts.jsonl that alert.
alerting_ids() {
	ALERT_SEVERITY=$1
	ALERT_EPSS=$2
	alert_args
	jq -rs "${ALERT_ARGS[@]}" "$ALERTING"'[.[] | alerting | .id] | join(" ")' "$FIXTURES/alerts.jsonl"
}

check "alerting: critical, EPSS 0.1" \
	"critical high-epss-at low-kev unknown-kev eol critical-affected critical-under-investigation" \
	alerting_ids critical 0.1
check "alerting: high, EPSS 1" \
	"critical high-epss-below high-epss-at low-kev unknown-kev eol critical-affected critical-under-investigation" \
	alerting_ids high 1
check "alerting: medium, EPSS 0" \
	"critical high-epss-below high-epss-at medium-epss low-kev unknown-kev eol critical-affected critical-under-investigation" \
	alerting_ids medium 0
check "alerting: negligible, EPSS 1" \
	"critical high-epss-below high-epss-at medium-epss low-kev unknown-kev negligible eol critical-affected critical-under-investigation" \
	alerting_ids negligible 1

alert_query() {
	ALERT_SEVERITY=critical
	ALERT_EPSS=0.1
	alert_args
	jq -rs "${ALERT_ARGS[@]}" "$ALERTING$1" "$FIXTURES/alerts.jsonl"
}
# shellcheck disable=SC2016
check "suppressed alerts" "critical-not-affected critical-fixed" \
	alert_query '[.[] | select(suppressed) | alert_worthy($epss) | .id] | join(" ")'
check "priority: KEV, end of life, then EPSS" \
	"unknown-kev low-kev eol high-epss-at critical-affected critical critical-under-investigation" \
	alert_query '[.[] | alerting] | priority | map(.id) | join(" ")'
check "grouped by image and ID" \
	'{"image":"a:1","id":"X","severity":"critical","kev":true,"epss":0.3,"package":"chromium, chromium-common","version":"120.0","type":"deb","fix":"120.1"} {"image":"b:1","id":"X","severity":"low","kev":false,"epss":0,"package":"chromium","version":"119.0","type":"deb","fix":""}' \
	jq -nrc --argjson rank "$SEVERITY_RANK" "$ALERTING"'[
		{image: "a:1", id: "X", severity: "high", kev: false, epss: 0.1, package: "chromium", version: "120.0", type: "deb", fix: ""},
		{image: "a:1", id: "X", severity: "critical", kev: true, epss: 0.3, package: "chromium-common", version: "120.0", type: "deb", fix: "120.1"},
		{image: "b:1", id: "X", severity: "low", kev: false, epss: 0, package: "chromium", version: "119.0", type: "deb", fix: ""}
	] | [grouped | tojson] | join(" ")'

settings() {
	ALERT_SEVERITY=$1
	ALERT_EPSS=$2
	alert_args
	echo ok
}
check "SBOM_ALERT_SEVERITY high" ok settings high 0.1
check "SBOM_ALERT_SEVERITY bogus" "error: SBOM_ALERT_SEVERITY must be one of: negligible, low, medium, high, critical (exit 1)" settings bogus 0.1
check "SBOM_ALERT_EPSS 0" ok settings critical 0
check "SBOM_ALERT_EPSS 1" ok settings critical 1
for epss in 1.5 -0.1 abc ''; do
	check "SBOM_ALERT_EPSS '$epss'" "error: SBOM_ALERT_EPSS must be a number from 0 to 1 (exit 1)" settings critical "$epss"
done

## sbom.sh scan and influx

# Prepares a data directory in $WORK/$1 with the two images of tests/scan.
scan_data() {
	local data=$WORK/$1
	mkdir -p "$data/sboms"
	cp "$TESTS/scan/index.json" "$data/index.json"
	cp "$TESTS/scan/app.grype.json" "$data/sboms/app.json"
	cp "$TESTS/scan/db.grype.json" "$data/sboms/db.json"
}

# Runs sbom.sh in a clean environment with the grype stub.
sbom() {
	env -i HOME="$HOME" PATH="$TESTS/bin:$PATH" SBOM_PROJECT=test SBOM_ALERT_SEVERITY=critical SBOM_ALERT_EPSS=0.1 "$@"
}

# Runs the command with stdout and stderr to $WORK/NAME.out. A non-zero
# exit status counts as a failed test.
run() {
	local name=$1 status=0
	shift
	"$@" >"$WORK/$name.out" 2>&1 || status=$?
	if [[ $status -eq 0 ]]; then
		passed=$((passed + 1))
	else
		failed=$((failed + 1))
		echo "FAIL $name exits with status $status"
		sed 's/^/  /' "$WORK/$name.out"
	fi
}

# Sorts the keys and lines, so the comparison does not depend on the locale.
normalize() {
	jq -cS . "$1" | LC_ALL=C sort
}

scan_data scan
cp "$TESTS/scan/previous.jsonl" "$WORK/scan/findings.jsonl"
run scan sbom SBOM_DATA_DIR="$WORK/scan" SBOM_VEX="$TESTS/scan/vex.json" "$TESTS/../sbom.sh" scan
check "scan output" \
	"warning: $TESTS/scan/vex.json has 1 products or subcomponents without a string \"@id\", they match nothing
10 findings, 4 new alerts" \
	grep -v '^scanning ' "$WORK/scan.out"
normalize "$WORK/scan/findings.jsonl" >"$WORK/findings.jsonl"
check_file "scan findings.jsonl" findings.jsonl "$WORK/findings.jsonl"
normalize "$WORK/scan/new.jsonl" >"$WORK/new.jsonl"
check_file "scan new.jsonl" new.jsonl "$WORK/new.jsonl"
check_file "scan summary.md" summary.md "$WORK/scan/summary.md"

# All points of one run have the same timestamp. The expected file has the
# placeholder TIME instead.
run influx sbom SBOM_DATA_DIR="$WORK/scan" "$TESTS/../sbom.sh" influx
timestamps() {
	awk '{print $NF}' "$WORK/influx.out" | sort -u | wc -l | tr -d ' '
}
check "influx timestamps" 1 timestamps
sed 's/ [0-9]*$/ TIME/' "$WORK/influx.out" >"$WORK/influx.txt"
check_file "influx line protocol" influx.txt "$WORK/influx.txt"

# The first scan has no previous findings and no VEX document, so all 7
# alerts are new, CVE-2026-6000 included.
first_scan() {
	scan_data first
	sbom SBOM_DATA_DIR="$WORK/first" SBOM_VEX="$WORK/missing.json" "$TESTS/../sbom.sh" scan 2>&1 | grep -v '^scanning '
}
check "first scan output" "10 findings, 7 new alerts" first_scan

echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]
