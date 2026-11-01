#!/usr/bin/env bash
# Usage: scripts/diff-steps.sh <from-ID> <to-ID>     e.g.  scripts/diff-steps.sh B C
set -euo pipefail
cd "$(dirname "$0")/.."
A="evidence/$1.grype.json"; B="evidence/$2.grype.json"; OUT="evidence/diff-$1-$2"
for f in "$A" "$B"; do [ -f "$f" ] || { echo "missing $f (run scripts/step.sh first)"; exit 1; }; done
T=$(mktemp -d)
tsv() { jq -r '(.matches // [])[] | [.vulnerability.id, .artifact.name, .vulnerability.severity] | @tsv' "$1" | sort -u; }
tsv "$A" > "$T/from"; tsv "$B" > "$T/to"
awk -F'\t' 'NR==FNR{t[$1]=1;next} !($1 in t)' "$T/to"   "$T/from" > "$OUT.gone.tsv"
awk -F'\t' 'NR==FNR{t[$1]=1;next}  ($1 in t)' "$T/to"   "$T/from" > "$OUT.still.tsv"
awk -F'\t' 'NR==FNR{f[$1]=1;next} !($1 in f)' "$T/from" "$T/to"   > "$OUT.new.tsv"
echo "$1 -> $2  (Grype; unique CVE+package rows)"
printf '  gone:  %s\n  still: %s\n  new:   %s\n' "$(wc -l < "$OUT.gone.tsv")" "$(wc -l < "$OUT.still.tsv")" "$(wc -l < "$OUT.new.tsv")"
echo "  gone, by severity:"; cut -f3 "$OUT.gone.tsv" | sort | uniq -c | sort -rn | sed 's/^/    /'
echo "  gone, by package (top 10):"; cut -f2 "$OUT.gone.tsv" | sort | uniq -c | sort -rn | head -n 10 | sed 's/^/    /'