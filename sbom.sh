#!/usr/bin/env bash
# Keep a CycloneDX SBOM for every container image of a compose project and
# scan the SBOMs for known vulnerabilities. Run it from the root of the
# project. README.md next to this file describes the setup.
set -euo pipefail

DATA=${SBOM_DATA_DIR:-sbom/data}
PLATFORM=${SBOM_PLATFORM:-linux/amd64}
ALERT_SEVERITY=${SBOM_ALERT_SEVERITY:-critical}
ALERT_EPSS=${SBOM_ALERT_EPSS:-0.1}
VEX=${SBOM_VEX:-sbom/vex.json}
# Names the project in InfluxDB and in the webhook payload. The default is
# the GitHub repository name in a workflow, else the name of the git
# top-level directory.
PROJECT=${SBOM_PROJECT:-${GITHUB_REPOSITORY#*/}}
[[ -n $PROJECT ]] || PROJECT=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)")

usage() {
	cat <<'EOF'
Usage: sbom.sh <command> [args]

Commands:
  generate [compose files...]  Create an SBOM for every image whose digest
                               changed (default file: docker-compose.yml)
  scan                         Scan all SBOMs and write findings.jsonl,
                               new.jsonl and summary.md
  notify                       POST new.jsonl to $SBOM_ALERT_WEBHOOK_URL
  influx                       Write the scan results to InfluxDB, or print
                               them as line protocol if SBOM_INFLUX_URL is unset
  find <regex>                 List components whose name matches <regex>

Environment:
  SBOM_DATA_DIR           SBOMs and scan results (default: sbom/data)
  SBOM_PLATFORM           Image platform to analyze (default: linux/amd64)
  SBOM_EXCLUDE            Extended regex of image references to skip
  SBOM_EXTRA_IMAGES       More image references, separated by whitespace
  SBOM_ALERT_SEVERITY     Lowest severity that alerts (default: critical)
  SBOM_ALERT_EPSS         EPSS from which high findings alert (default: 0.1)
  SBOM_VEX                OpenVEX document (default: sbom/vex.json)
  SBOM_PROJECT            Project name (default: repository name)
  SBOM_ALERT_WEBHOOK_URL  Webhook URL for notify
  SBOM_RUN_URL            Link added to the webhook payload
  SBOM_INFLUX_URL         InfluxDB 2 base URL, for example https://host:8086
  SBOM_INFLUX_ORG         InfluxDB organization
  SBOM_INFLUX_BUCKET      InfluxDB bucket (default: sbom)
  SBOM_INFLUX_TOKEN       InfluxDB token with write access to the bucket
EOF
}

die() {
	echo "error: $*" >&2
	exit 1
}

# Order of grype severities. Unknown is below everything, so it only alerts
# when the finding is in the CISA KEV catalog.
SEVERITY_RANK='{"unknown":0,"negligible":1,"low":2,"medium":3,"high":4,"critical":5}'

list_images() {
	{
		yq '.services[] | select(has("image")) | .image' "$@"
		# Word splitting is intended here.
		# shellcheck disable=SC2086
		printf '%s\n' ${SBOM_EXTRA_IMAGES:-}
	} | sed '/^$/d' | sort -u | while read -r image; do
		if [[ $image == *'$'* ]]; then
			echo "warning: skipping $image, variables are not resolved" >&2
		elif [[ -n ${SBOM_EXCLUDE:-} && $image =~ $SBOM_EXCLUDE ]]; then
			echo "skipped $image" >&2
		else
			echo "$image"
		fi
	done
}

# Prints the digest that the registry serves for the reference. For a
# multi-platform image this is the digest of the index, which changes when
# any platform is rebuilt.
resolve_digest() {
	if [[ $1 == *@sha256:* ]]; then
		echo "${1##*@}"
	else
		docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -re .digest
	fi
}

cmd_generate() {
	local files=("$@") images image digest file failed=0
	[[ ${#files[@]} -gt 0 ]] || files=(docker-compose.yml)
	mkdir -p "$DATA/sboms"
	[[ -f $DATA/index.json ]] || echo '{}' >"$DATA/index.json"
	images=$(list_images "${files[@]}")

	for image in $images; do
		if ! digest=$(resolve_digest "$image"); then
			echo "error: cannot resolve the digest of $image" >&2
			failed=1
			continue
		fi
		file=$(jq -r --arg i "$image" --arg d "$digest" '.[$i] | select(.digest == $d) | .file' "$DATA/index.json")
		if [[ -n $file && -f $DATA/$file ]]; then
			echo "unchanged $image"
			continue
		fi

		echo "generating $image ($digest)"
		file="sboms/$(tr '/:@' '___' <<<"$image").cdx.json"
		# Analyze the resolved digest, so the SBOM matches the digest in the index
		# even if the tag moves in the meantime.
		if ! syft scan "registry:${image%@*}@$digest" --platform "$PLATFORM" \
			--source-name "$image" --source-version "$digest" \
			-q -o "cyclonedx-json=$DATA/$file.tmp"; then
			echo "error: cannot create an SBOM for $image" >&2
			rm -f "$DATA/$file.tmp"
			failed=1
			continue
		fi
		mv "$DATA/$file.tmp" "$DATA/$file"
		jq --arg i "$image" --arg d "$digest" --arg f "$file" \
			'.[$i] = {digest: $d, file: $f}' "$DATA/index.json" >"$DATA/index.json.tmp"
		mv "$DATA/index.json.tmp" "$DATA/index.json"
	done

	# Remove the images that the compose files no longer use.
	jq -r --arg keep "$images" '($keep | split("\n")) as $k | to_entries[] | select(.key | IN($k[]) | not) | "\(.key)\t\(.value.file)"' \
		"$DATA/index.json" | while IFS=$'\t' read -r image file; do
		echo "removing $image"
		rm -f "${DATA:?}/$file"
		jq --arg i "$image" 'del(.[$i])' "$DATA/index.json" >"$DATA/index.json.tmp"
		mv "$DATA/index.json.tmp" "$DATA/index.json"
	done

	return $failed
}

# Turns one grype JSON report into one finding per line. An end-of-life
# distribution counts as a finding with the severity "eol".
# shellcheck disable=SC2016
EXTRACT='
(.matches[] | {
	image: $image,
	id: .vulnerability.id,
	aliases: ([.relatedVulnerabilities[]?.id] - [.vulnerability.id] | unique),
	severity: (.vulnerability.severity | ascii_downcase),
	kev: ((.vulnerability.knownExploited // []) | length > 0),
	epss: ([.vulnerability.epss[]?.epss] | max // 0),
	package: .artifact.name,
	version: .artifact.version,
	type: .artifact.type,
	fix: (.vulnerability.fix.versions // [] | join(", "))
}),
# grype also reports packages without distribution version as end-of-life,
# for example in images built from sliced Ubuntu packages. Skip those.
([.alertsByPackage[]?.alerts[]? | select(.type == "distro-eol" and (.metadata.version // "") != "") | .metadata] | unique[] | {
	image: $image,
	id: "distro-eol",
	aliases: [],
	severity: "eol",
	kev: false,
	epss: 0,
	package: .name,
	version: .version,
	type: "distro",
	fix: ""
})
'

# Marks the findings that a statement of the OpenVEX document covers with
# its status and justification. A statement covers a finding if its
# vulnerability name or an alias equals the ID or an alias of the finding,
# and one of its products is the image. A product with a tag or digest
# matches only that reference, one without matches every tag of the image.
# Subcomponents, if present, limit the statement to these packages, given
# as package URL or plain name, each optionally with "@version". A product
# or subcomponent without a string "@id" matches nothing. The last matching
# statement in the document applies.
# shellcheck disable=SC2016
VEX_APPLY='
def ids: if type == "string" then [.] else [.name, ."@id"] + (.aliases // []) end | map(select(. != null));
def id: (."@id"? | strings) // "";
def components: (.subcomponents? // []) | if type == "array" then .[] else . end;
def repo: sub("@.*$"; "") | sub(":[^/]*$"; "");
def image_match($img): . == $img or (. != "" and (split("/") | last | test("[:@]") | not) and . == ($img | repo));
# A leading "@" belongs to the name (npm scope). A package URL also matches
# by its last path segment, which drops a namespace such as "debian/".
def pkg_match($f): startswith("pkg:") as $purl
	| (if $purl then sub("^pkg:[^/]+/"; "") | sub("[?#].*$"; "") else . end)
	| capture("^(?<name>@?[^@]+)(@(?<version>.+))?$") as $nv
	| ($nv.name == $f.package or ($purl and ($nv.name | split("/") | last) == $f.package))
		and ($nv.version == null or $nv.version == $f.version);
[$vex.statements[]? | {ids: (.vulnerability | ids), products: [.products[]? | {image: id, subs: [components | id]}], status, justification: (.justification // "")}] as $statements
| . as $f
| ([$statements[] | select(any(.ids[]; . == $f.id or IN($f.aliases[])) and any(.products[]; (.image | image_match($f.image)) and (.subs == [] or any(.subs[]; pkg_match($f)))))] | last) as $st
| if $st then . + {vex: $st.status, vex_justification: $st.justification} else . end
'

# shellcheck disable=SC2016
ALERTING='
def suppressed: (.vex // "") | IN("not_affected", "fixed");
# High findings also alert from the EPSS threshold e on.
def alert_worthy(e): select(.severity == "eol" or .kev or ($rank[.severity] // 0) >= $rank[$min] or (($rank[.severity] // 0) >= $rank.high and (.epss // 0) >= e));
def alerting(e): select(suppressed | not) | alert_worthy(e);
def alerting: alerting($epss);
# Sorts an array of alerts: known exploited, end of life, then by EPSS.
def priority: sort_by([(if .kev then 0 else 1 end), (if .severity == "eol" then 0 else 1 end), -(.epss // 0), .image, .id]);
def key: [.image, .id] | join("|");
# Merges the findings of one vulnerability in one image into one alert, for
# example the same CVE in the packages chromium and chromium-common.
def grouped: group_by([.image, .id]) | map(.[0] + {
	severity: (max_by($rank[.severity] // 0) | .severity),
	kev: any(.[]; .kev),
	epss: (map(.epss // 0) | max),
	package: (map(.package) | unique | join(", ")),
	version: (map(.version) | unique | join(", ")),
	type: (map(.type) | unique | join(", ")),
	fix: (map(.fix | select(. != "")) | unique | join("; "))
}) | .[];
'

# Sets ALERT_ARGS, the jq arguments for the ALERTING definitions.
alert_args() {
	jq -e --arg min "$ALERT_SEVERITY" --argjson rank "$SEVERITY_RANK" '$rank | has($min)' -n >/dev/null ||
		die "SBOM_ALERT_SEVERITY must be one of: negligible, low, medium, high, critical"
	jq -e --arg e "$ALERT_EPSS" '$e | tonumber | . >= 0 and . <= 1' -n >/dev/null 2>&1 ||
		die "SBOM_ALERT_EPSS must be a number from 0 to 1"
	ALERT_ARGS=(--arg min "$ALERT_SEVERITY" --argjson rank "$SEVERITY_RANK" --argjson epss "$ALERT_EPSS")
}

cmd_scan() {
	local image file tmp n vex='{}'
	[[ -f $DATA/index.json ]] || die "$DATA/index.json is missing, run generate first"
	alert_args
	if [[ -f $VEX ]]; then
		vex=$(jq -c . "$VEX") || die "$VEX is not valid JSON"
		n=$(jq '[.statements[]? | .products[]? | ., ((.subcomponents? // []) | if type == "array" then .[] else . end) | select((."@id"? // null) | type != "string")] | length' <<<"$vex")
		((n == 0)) || echo "warning: $VEX has $n products or subcomponents without a string \"@id\", they match nothing" >&2
	fi
	tmp=$(mktemp)
	trap 'rm -f "$tmp"' RETURN

	grype db update -q
	jq -r 'to_entries[] | "\(.key)\t\(.value.file)"' "$DATA/index.json" |
		while IFS=$'\t' read -r image file; do
			echo "scanning $image" >&2
			GRYPE_DB_AUTO_UPDATE=false grype "sbom:$DATA/$file" -q -o json |
				jq -c --arg image "$image" "$EXTRACT"
		done | jq -c --argjson vex "$vex" "$VEX_APPLY" | sort -u >"$tmp"

	[[ -f $DATA/findings.jsonl ]] || : >"$DATA/findings.jsonl"
	# A finding is new if it alerts now and did not alert in the previous scan.
	# Both sides use the current settings, so a lower threshold reports the
	# findings it adds as new. The previous scan counts with half the EPSS
	# threshold, so a score that moves around the threshold alerts only once.
	jq -c -n --slurpfile old "$DATA/findings.jsonl" --slurpfile cur "$tmp" "${ALERT_ARGS[@]}" "$ALERTING"'
		([$old[] | alerting($epss / 2) | key] | INDEX(.)) as $seen
		| [$cur[] | alerting | select($seen[key] | not)] | grouped' >"$DATA/new.jsonl"
	chmod 644 "$tmp"
	mv "$tmp" "$DATA/findings.jsonl"

	write_summary >"$DATA/summary.md"
	echo "$(wc -l <"$DATA/findings.jsonl" | tr -d ' ') findings, $(wc -l <"$DATA/new.jsonl" | tr -d ' ') new alerts" >&2
}

write_summary() {
	local db_built
	db_built=$(grype db status -o json | jq -r '.built // "unknown"')
	cat <<EOF
# SBOM Scan Summary

Scanned with grype $(grype version -o json | jq -r .version), vulnerability database built $db_built. Findings alert at severity \`$ALERT_SEVERITY\` and above, at severity \`high\` from an EPSS of $ALERT_EPSS on, for entries in the CISA KEV catalog, and for end-of-life distributions. Findings that the VEX document marks as \`not_affected\` or \`fixed\` do not alert. Tables list known exploited first, then by EPSS.

## Images

Counts are distinct vulnerability IDs.

| Image | Critical | High | Medium | Low | EOL distro |
| --- | --- | --- | --- | --- | --- |
EOF
	jq -r -n --slurpfile index "$DATA/index.json" --slurpfile f "$DATA/findings.jsonl" '
		$index[0] | keys[] as $image
		| [$f[] | select(.image == $image)] as $mine
		| def n(s): [$mine[] | select(.severity == s) | .id] | unique | length;
		"| `\($image)` | \(n("critical")) | \(n("high")) | \(n("medium")) | \(n("low")) | \([$mine[] | select(.severity == "eol") | "\(.package) \(.version)"] | join("") ) |"'

	cat <<EOF

## New Alerts

EOF
	jq -c -s "${ALERT_ARGS[@]}" "$ALERTING"'priority | .[]' "$DATA/new.jsonl" | print_table /dev/stdin

	cat <<EOF

## All Alerts

EOF
	jq -c -s "${ALERT_ARGS[@]}" "$ALERTING"'[.[] | alerting] | [grouped] | priority | .[]' "$DATA/findings.jsonl" |
		print_table /dev/stdin

	cat <<EOF

## Not Affected According to VEX

Findings that would alert without the statements in the VEX document.

EOF
	jq -r -s "${ALERT_ARGS[@]}" "$ALERTING"'[.[] | select(suppressed) | alert_worthy($epss)] | [grouped] | priority
		| if . == [] then "None." else
			"| Image | ID | Severity | Packages | Status | Justification |",
			"| --- | --- | --- | --- | --- | --- |",
			(.[] | "| `\(.image)` | \(.id) | \(.severity) | \(.package) | \(.vex) | \(.vex_justification) |")
		end' "$DATA/findings.jsonl"
}

print_table() {
	local rows
	rows=$(jq -r '"| `\(.image)` | \(.id)\(if .aliases != [] then " (\(.aliases | join(", ")))" else "" end) | \(.severity) | \(if .kev then "yes" else "" end) | \((.epss // 0) * 1000 | round / 10)% | \(.package) | \(.version) | \(.fix) |"' "$1")
	if [[ -z $rows ]]; then
		echo "None."
	else
		echo "| Image | ID | Severity | KEV | EPSS | Packages | Versions | Fixed in |"
		echo "| --- | --- | --- | --- | --- | --- | --- | --- |"
		echo "$rows"
	fi
}

cmd_notify() {
	[[ -s $DATA/new.jsonl ]] || {
		echo "no new alerts"
		return 0
	}
	[[ -n ${SBOM_ALERT_WEBHOOK_URL:-} ]] || {
		echo "SBOM_ALERT_WEBHOOK_URL is not set, no notification sent" >&2
		return 0
	}
	jq -s --arg project "$PROJECT" --arg url "${SBOM_RUN_URL:-}" '{project: $project, run_url: $url, count: length, findings: .}' "$DATA/new.jsonl" |
		curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$SBOM_ALERT_WEBHOOK_URL" >/dev/null
	echo "sent $(wc -l <"$DATA/new.jsonl" | tr -d ' ') new alerts"
}

# Writes one point per scan (sbom_scan), per image (sbom_image) and per alert
# (sbom_alert), each with the tag project. All points of one run have the
# same timestamp, so a query can select the alerts of the latest scan of a
# project by its time.
cmd_influx() {
	local image file counts lines
	[[ -f $DATA/findings.jsonl ]] || die "$DATA/findings.jsonl is missing, run scan first"
	alert_args
	counts=$(jq -r 'to_entries[] | "\(.key)\t\(.value.file)"' "$DATA/index.json" |
		while IFS=$'\t' read -r image file; do
			jq -c --arg image "$image" '{($image): [.components[]? | select(.type != "file")] | length}' "$DATA/$file"
		done | jq -s 'add // {}')
	lines=$(jq -r -n --slurpfile f "$DATA/findings.jsonl" --slurpfile new "$DATA/new.jsonl" \
		--slurpfile index "$DATA/index.json" --argjson counts "$counts" --arg ts "$(date +%s)" --arg project "$PROJECT" \
		"${ALERT_ARGS[@]}" "$ALERTING"'
		def tag: tostring | gsub("(?<c>[ ,=\\\\])"; "\\\(.c)");
		def str: tostring | gsub("(?<c>[\"\\\\])"; "\\\(.c)") | "\"\(.)\"";
		([$new[] | key] | INDEX(.)) as $isnew
		| [[$f[] | alerting] | grouped] as $alerts
		| ($index[0] | keys) as $images
		| ($project | tag) as $p
		| "sbom_scan,project=\($p) images=\($images | length)i,findings=\($f | length)i,alerts=\($alerts | length)i,new_alerts=\($new | length)i,kev=\([$alerts[] | select(.kev)] | length)i,eol=\([$f[] | select(.severity == "eol")] | length)i,suppressed=\([[$f[] | select(suppressed) | alert_worthy($epss)] | grouped] | length)i \($ts)",
		($images[] as $image
			| [$f[] | select(.image == $image)] as $mine
			| [$alerts[] | select(.image == $image)] as $mine_alerts
			| def n(s): [$mine[] | select(.severity == s) | .id] | unique | length;
			"sbom_image,project=\($p),image=\($image | tag) critical=\(n("critical"))i,high=\(n("high"))i,medium=\(n("medium"))i,low=\(n("low"))i,alerts=\($mine_alerts | length)i,kev=\([$mine_alerts[] | select(.kev)] | length)i,eol=\(n("eol"))i,eol_distro=\([$mine[] | select(.severity == "eol") | "\(.package) \(.version)"] | join(", ") | str),components=\($counts[$image] // 0)i \($ts)"),
		($alerts[] | "sbom_alert,project=\($p),image=\(.image | tag),id=\(.id | tag) severity=\(.severity | str),kev=\(.kev),epss=\(.epss // 0),new=\($isnew[key] != null),packages=\(.package | str),versions=\(.version | str),fix=\(.fix | str),aliases=\(.aliases | join(", ") | str) \($ts)")')

	if [[ -z ${SBOM_INFLUX_URL:-} ]]; then
		echo "$lines"
		return 0
	fi
	[[ -n ${SBOM_INFLUX_ORG:-} && -n ${SBOM_INFLUX_TOKEN:-} ]] || die "SBOM_INFLUX_ORG and SBOM_INFLUX_TOKEN are required"
	# curl reads the header from stdin, so the token does not appear in the
	# process list.
	printf 'header = "Authorization: Token %s"\n' "$SBOM_INFLUX_TOKEN" |
		curl -fsS --config - -X POST -H 'Content-Type: text/plain; charset=utf-8' --data-binary @<(echo "$lines") \
			"${SBOM_INFLUX_URL%/}/api/v2/write?precision=s&org=$(jq -rn --arg v "$SBOM_INFLUX_ORG" '$v | @uri')&bucket=$(jq -rn --arg v "${SBOM_INFLUX_BUCKET:-sbom}" '$v | @uri')"
	echo "wrote $(wc -l <<<"$lines" | tr -d ' ') points to InfluxDB"
}

cmd_find() {
	[[ $# -eq 1 ]] || die "usage: sbom.sh find <regex>"
	[[ -f $DATA/index.json ]] || die "$DATA/index.json is missing, run generate first"
	jq -r 'to_entries[] | "\(.key)\t\(.value.file)"' "$DATA/index.json" |
		while IFS=$'\t' read -r image file; do
			jq -r --arg image "$image" --arg re "$1" \
				'.components[]? | select(.type != "file" and (.name | test($re; "i"))) | [$image, .name, .version // "", .purl // ""] | @tsv' "$DATA/$file"
		done | column -t -s $'\t'
}

case ${1:-} in
generate | scan | notify | influx | find)
	cmd=$1
	shift
	"cmd_$cmd" "$@"
	;;
*)
	usage
	exit 2
	;;
esac
