#!/bin/sh

set -eu

repeats=3
timeout_seconds=30
build_timeout_seconds=120

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repeats)
            repeats="$2"
            shift 2
            ;;
        --timeout)
            timeout_seconds="$2"
            shift 2
            ;;
        --build-timeout)
            build_timeout_seconds="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "unknown option: $1" >&2
            exit 2
            ;;
    esac
done

if [ "$#" -eq 0 ]; then
    echo "a test command is required after --" >&2
    exit 2
fi

for value in "$repeats" "$timeout_seconds" "$build_timeout_seconds"; do
    case "$value" in
        ''|*[!0-9]*)
            echo "repeat and timeout values must be integers" >&2
            exit 2
            ;;
    esac
done

if [ "$repeats" -lt 1 ]; then
    echo "repeats must be positive" >&2
    exit 2
fi
if [ "$timeout_seconds" -gt 120 ] || [ "$build_timeout_seconds" -gt 120 ]; then
    echo "timeouts must not exceed 120 seconds" >&2
    exit 2
fi

artifact_root=".test-artifacts/hang-guard"
lock_directory="$artifact_root/.lock"
mkdir -p "$artifact_root"
if ! mkdir "$lock_directory" 2>/dev/null; then
    echo "another hang-guard run is active" >&2
    exit 3
fi
trap 'rmdir "$lock_directory" 2>/dev/null || true' EXIT HUP INT TERM

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_directory="$artifact_root/$timestamp"
mkdir -p "$artifact_directory"

before_helpers="$artifact_directory/helpers-before.txt"
pgrep -x swiftpm-testing-helper 2>/dev/null | sort -n > "$before_helpers" || true

run=1
while [ "$run" -le "$repeats" ]; do
    run_timeout="$timeout_seconds"
    if [ "$run" -eq 1 ]; then
        run_timeout="$build_timeout_seconds"
    fi

    log="$artifact_directory/run-$run.log"
    set +e
    scripts/swift-test-timeout.sh "$run_timeout" "$@" > "$log" 2>&1
    status="$?"
    set -e
    if [ "$status" -ne 0 ]; then
        {
            echo "command status: $status"
            echo "swift-related processes:"
            ps -axo pid,ppid,state,etime,command | rg 'swift|xcodebuild' || true
            echo "SwiftPM lock files:"
            find .build -name '*.lock' -print 2>/dev/null || true
        } > "$artifact_directory/run-$run.diag.txt"
        cat "$log"
        echo "Hang guard failed; diagnostics: $artifact_directory" >&2
        exit 1
    fi

    run_helpers="$artifact_directory/helpers-after-$run.txt"
    pgrep -x swiftpm-testing-helper 2>/dev/null | sort -n > "$run_helpers" || true
    if comm -13 "$before_helpers" "$run_helpers" | rg -q '.'; then
        {
            echo "New swiftpm-testing-helper processes remained after run $run"
            comm -13 "$before_helpers" "$run_helpers"
        } > "$artifact_directory/run-$run.diag.txt"
        cat "$log"
        echo "Hang guard detected a stale helper; diagnostics: $artifact_directory" >&2
        exit 1
    fi

    run=$((run + 1))
done

echo "OK: $repeats guarded run(s) completed without timeout or stale helper"
