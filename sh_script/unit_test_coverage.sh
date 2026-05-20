#!/bin/bash

# Navigate to repo root if run from sh_script/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="unittest-%p-%m.profraw"

find . -name "*.profraw" -not -path "./deps/*" -delete

cargo test -p policy -p migtd -p crypto -p virtio -p vsock

grcov . --binary-path ./target/debug/ -s . -t html --branch \
    --ignore-not-existing \
    --ignore "deps/*" \
    --ignore "target/*" \
    -o unit_test_coverage

unset RUSTFLAGS
unset LLVM_PROFILE_FILE
