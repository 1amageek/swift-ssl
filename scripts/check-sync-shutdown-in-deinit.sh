#!/bin/sh

set -eu

if [ "$#" -eq 0 ]; then
    set -- Sources Tests
fi

existing_paths=""
for candidate in "$@"; do
    if [ -e "$candidate" ]; then
        existing_paths="$existing_paths $candidate"
    fi
done

if [ -z "$existing_paths" ]; then
    echo "No source paths were available for the deinit shutdown guard" >&2
    exit 2
fi

# The bounded multiline window intentionally errs toward reporting suspicious
# synchronous waits for review. It does not attempt to parse Swift syntax.
pattern='deinit[[:space:]]*\{(?s:.{0,2400})(syncShutdownGracefully|DispatchSemaphore|\.wait[[:space:]]*\()'

# shellcheck disable=SC2086
if rg --pcre2 --multiline -n "$pattern" $existing_paths; then
    echo "Synchronous shutdown or blocking wait found near deinit" >&2
    exit 1
fi

echo "OK: no synchronous shutdown pattern found near deinit"
