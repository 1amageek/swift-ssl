#!/bin/sh

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <seconds> <command> [arguments ...]" >&2
    exit 2
fi

timeout_seconds="$1"
shift

case "$timeout_seconds" in
    ''|*[!0-9]*)
        echo "timeout must be an integer number of seconds" >&2
        exit 2
        ;;
esac

if [ "$timeout_seconds" -lt 1 ] || [ "$timeout_seconds" -gt 120 ]; then
    echo "timeout must be between 1 and 120 seconds" >&2
    exit 2
fi

exec python3 - "$timeout_seconds" "$@" <<'PYTHON'
import os
import signal
import subprocess
import sys

timeout = int(sys.argv[1])
command = sys.argv[2:]

process = subprocess.Popen(command, start_new_session=True)
try:
    return_code = process.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    print(f"Timed out after {timeout} seconds: {' '.join(command)}", file=sys.stderr)
    sys.exit(124)

sys.exit(return_code)
PYTHON
