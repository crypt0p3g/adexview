#!/usr/bin/env bash
# Run the offline audit for a snapshot and build its viewer database in ./db/PROJECT_NAME.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: enum.sh PROJECT_NAME SNAPSHOT [audit options]
Example: enum.sh PROJECTNAME ./snapshot.dat
Output: ./db/PROJECT_NAME/PROJECT_NAME.sqlite3 plus 00_summary.md and metadata.json

Options are passed to `adexview audit`, for example:
  --output-mode csv|sqlite|both   Output format (default: both)
  --csv-reports                   Also write the CSV report files
  --database PATH                 Override db/PROJECT/PROJECT.sqlite3
  --timezone ZONE                 Date timezone (default: Asia/Tokyo)
  --stale-days DAYS               Stale-account threshold (default: 90)
  --redact-sensitive-values       Replace sensitive values with fingerprints
EOF
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  usage
  exit 0
fi
if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

project_name=$1
snapshot=$2
shift 2

if [[ $project_name == */* || $project_name == .* || ! $project_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "PROJECT_NAME must be a simple safe directory name." >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
snapshot_path=$(cd -- "$(dirname -- "$snapshot")" && pwd)/$(basename -- "$snapshot")
if [[ ! -f $snapshot_path ]]; then
  echo "Snapshot not found: $snapshot_path" >&2
  exit 1
fi

output_dir="$PWD/db/$project_name"
mkdir -p -- "$output_dir"

python_bin=python3
if [[ -x "$script_dir/.venv/bin/python" ]]; then
  python_bin="$script_dir/.venv/bin/python"
fi

PYTHONPATH="$script_dir/src${PYTHONPATH:+:$PYTHONPATH}" "$python_bin" -m adexview audit \
  --snapshot "$snapshot_path" --output "$output_dir" "$@"

if [[ -f $output_dir/00_summary.md ]]; then
  echo "Summary: $output_dir/00_summary.md"
fi
if [[ -f $output_dir/$project_name.sqlite3 ]]; then
  echo "Database: $output_dir/$project_name.sqlite3"
fi
echo "Browse: $script_dir/view.sh $output_dir"
