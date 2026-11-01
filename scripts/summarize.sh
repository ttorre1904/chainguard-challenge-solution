#!/usr/bin/env bash
# Builds evidence/ladder.csv from every evidence/<ID>.grype.json and <ID>.trivy.json
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=evidence/ladder.csv
echo "step,scanner,critical,high,medium,low,other,total,fixable,os_pkgs,go_modules,go_stdlib" > "$OUT"

# jq emits: crit,high,med,low,other,total,fixable,os,modules,stdlib
grype_row() { jq -r '
  (.matches // []) as $m
  | def n(f): [$m[] | select(f)] | length;
  [ n((.vulnerability.severity|ascii_downcase)=="critical"), n((.vulnerability.severity|ascii_downcase)=="high"),
    n((.vulnerability.severity|ascii_downcase)=="medium"),   n((.vulnerability.severity|ascii_downcase)=="low"),
    ($m|length), n(.vulnerability.fix.state=="fixed"),
    n(.artifact.type=="apk" or .artifact.type=="deb" or .artifact.type=="rpm"), n(.artifact.name=="stdlib") ]
  | [.[0],.[1],.[2],.[3], (.[4]-.[0]-.[1]-.[2]-.[3]), .[4], .[5], .[6], (.[4]-.[6]-.[7]), .[7]] | @csv' "$1"; }

trivy_row() { jq -r '
  [ .Results[]? | . as $r | (.Vulnerabilities // [])[]
    | {sev:.Severity, fixed:((.FixedVersion // "") != ""), cls:$r.Class, pkg:.PkgName} ] as $v
  | def n(f): [$v[] | select(f)] | length;
  [ n(.sev=="CRITICAL"), n(.sev=="HIGH"), n(.sev=="MEDIUM"), n(.sev=="LOW"),
    ($v|length), n(.fixed), n(.cls=="os-pkgs"), n(.pkg=="stdlib") ]
  | [.[0],.[1],.[2],.[3], (.[4]-.[0]-.[1]-.[2]-.[3]), .[4], .[5], .[6], (.[4]-.[6]-.[7]), .[7]] | @csv' "$1"; }

for f in $(ls evidence/*.grype.json 2>/dev/null | sort -V); do
  step=$(basename "$f" .grype.json)
  echo "$step,grype,$(grype_row "$f")" >> "$OUT"
  t="evidence/$step.trivy.json"; [ -f "$t" ] && echo "$step,trivy,$(trivy_row "$t")" >> "$OUT"
done
column -s, -t "$OUT"