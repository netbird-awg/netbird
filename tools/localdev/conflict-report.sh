#!/usr/bin/env bash
set -euo pipefail

repo=${1:-.}
upstream=${2:-origin/main}
history_commits=${HISTORY_COMMITS:-200}

git -C "$repo" rev-parse --verify "$upstream" >/dev/null
merge_base=$(git -C "$repo" merge-base HEAD "$upstream")

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/netbird-conflict-report.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

local_files="$tmp_dir/local-files"
upstream_files="$tmp_dir/upstream-files"
overlap_files="$tmp_dir/overlap-files"
churn_files="$tmp_dir/churn-files"

{
  git -C "$repo" diff --name-only "$merge_base" --
  git -C "$repo" ls-files --others --exclude-standard
} | sed '/^$/d' | sort -u >"$local_files"

git -C "$repo" diff --name-only "$merge_base" "$upstream" | sort -u >"$upstream_files"
comm -12 "$local_files" "$upstream_files" >"$overlap_files"

git -C "$repo" log -n "$history_commits" --format= --name-only "$upstream" |
  sed '/^$/d' |
  sort |
  uniq -c |
  sort -nr >"$churn_files"

printf 'Repository: %s\n' "$(git -C "$repo" rev-parse --show-toplevel)"
printf 'Upstream:   %s\n' "$upstream"
printf 'Merge base: %s\n' "$merge_base"
printf 'Local paths: %s; upstream paths since base: %s\n' "$(wc -l <"$local_files" | tr -d ' ')" "$(wc -l <"$upstream_files" | tr -d ' ')"

if [[ -s "$overlap_files" ]]; then
  printf '\nDirect overlap (resolve before merge):\n'
  sed 's/^/  - /' "$overlap_files"
else
  printf '\nDirect overlap: none\n'
fi

printf '\nLocal changes in high-churn upstream paths (last %s commits):\n' "$history_commits"
found_hotspot=false
while IFS= read -r path; do
  count=$(awk -v target="$path" '$2 == target { print $1; exit }' "$churn_files")
  if [[ -n "$count" && "$count" -ge 3 ]]; then
    printf '  - %4s changes  %s\n' "$count" "$path"
    found_hotspot=true
  fi
done <"$local_files"

if [[ "$found_hotspot" == false ]]; then
  printf '  none\n'
fi
