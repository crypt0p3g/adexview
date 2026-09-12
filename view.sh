#!/usr/bin/env bash
# Start the viewer. With no arguments, serves the database library in ./db.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python_bin=python3
if [[ -x "$script_dir/.venv/bin/python" ]]; then
  python_bin="$script_dir/.venv/bin/python"
fi

if [[ $# -lt 1 ]]; then
  mkdir -p -- "$PWD/db"
  set -- --library "$PWD/db"
fi

PYTHONPATH="$script_dir/src${PYTHONPATH:+:$PYTHONPATH}" exec "$python_bin" -m adexview view "$@"
