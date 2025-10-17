#!/usr/bin/env bash
set -euo pipefail

CLAIR="http://127.0.0.1:6063"
LAST="/tmp/last_clair_digest"

need(){ command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl; need jq; need column

map_img(){ [[ "$1" == */* ]] && echo "$1" || echo "library/$1"; }

scan(){
  local img tag csv
  img="$(map_img "${1:?usage: ./clair.sh scan <image> [tag] [csv_out]}")"
  tag="${2:-latest}"; csv="${3:-}"
  echo "Scanning $img:$tag ..."

  local tok ml_dig man layers dig payload
  tok="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${img}:pull" | jq -r .token)"

  ml_dig="$(curl -fsSL -H "Authorization: Bearer $tok" \
          -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
          "https://registry-1.docker.io/v2/${img}/manifests/${tag}" \
          | jq -r '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64") | .digest')"
  [[ -z "$ml_dig" || "$ml_dig" == "null" ]] && { echo "No linux/amd64 digest"; exit 1; }
  dig="$(printf %s "$ml_dig" | tr -d '\r\n' | xargs)"

  man="$(curl -fsSL -H "Authorization: Bearer $tok" \
          -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
          "https://registry-1.docker.io/v2/${img}/manifests/${dig}")"
  layers="$(printf '%s' "$man" | jq '[.layers[].digest]')"

  payload="$(jq -n --arg dig "$dig" --arg repo "$img" --arg token "$tok" --argjson layers "$layers" '
    { hash: $dig,
      layers: ($layers | map({
        hash: .,
        uri: ("https://registry-1.docker.io/v2/" + $repo + "/blobs/" + .),
        headers: { Authorization: ["Bearer " + $token] }
      }))
    }')"

  echo "Indexing in Clair..."
  curl -fsS -X POST "$CLAIR/indexer/api/v1/index_report" -H "Content-Type: application/json" -d "$payload" | jq -r .state >/dev/null

  echo "Fetching vulnerability report..."
  local rep
  rep="$(curl -fsS "$CLAIR/matcher/api/v1/vulnerability_report/$dig")"

  printf '%s\n' "$rep" | jq '
    {manifest_hash} + {
      total_vulns: (.vulnerabilities|length),
      severity_counts:
        (.vulnerabilities|to_entries|map(.value.normalized_severity)|group_by(.)|map({severity: .[0], count: length}))
    }'

  echo; echo "Top 15 (by severity):"
  printf '%s' "$rep" | jq -r '
    def sev(s): if s=="Critical" then 5 elif s=="High" then 4 elif s=="Medium" then 3 elif s=="Low" then 2 elif s=="Negligible" then 1 else 0 end;
    . as $r
    | [ $r.package_vulnerabilities|to_entries[] | .key as $pid | .value[] | $r.vulnerabilities[.]
        | {pkg:$r.packages[$pid].name, cve:.name, sev:.normalized_severity, fix:(.fixed_in_version // "")} ]
    | sort_by(-sev(.sev), .cve)[:15]
    | (["PACKAGE","CVE","SEVERITY","FIXED"]|@tsv), (.[]|[.pkg,.cve,.sev,.fix]|@tsv)
  ' | column -t -s $'\t'

  if [[ -n "$csv" ]]; then
    printf '%s' "$rep" | jq -r '
      . as $r
      | "package,cve,severity,fixed_in_version",
        ( $r.package_vulnerabilities|to_entries[]|.key as $pid|.value[]|$r.vulnerabilities[.]
          | [$r.packages[$pid].name, .name, .normalized_severity, (.fixed_in_version // "")] | @csv )' > "$csv"
    echo "Wrote $csv"
  fi

  printf '%s\n' "$dig" > "$LAST"
  echo "Saved manifest digest to $LAST"
}

del(){
  local dig="${1:---last}"
  [[ "$dig" == "--last" ]] && { [[ -f "$LAST" ]] || { echo "No $LAST"; exit 1; }; dig="$(tr -d '\r\n' < "$LAST" | xargs)"; }
  echo "DELETE index for $dig"
  curl -fsS -i -X DELETE "$CLAIR/indexer/api/v1/index_report/$dig" | sed -n '1,3p'
}

state(){ curl -fsS "$CLAIR/indexer/api/v1/index_state" | jq .; }

case "${1:-help}" in
  scan) shift; scan "$@";;
  delete) shift; del "${1:---last}";;
  state) state;;
  *) echo "Usage: $0 {scan|delete|state} ..."; exit 1;;
esac
