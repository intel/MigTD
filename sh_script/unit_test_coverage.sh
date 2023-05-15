#!/bin/bash

if [[ ! $PWD =~ firmware.security.tdx.migtd.td$ ]];then
    pushd ..
fi

unittest_folders=(
    "policy"
    "migtd"
)

export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="unittest-%p-%m.profraw"

find . -name "*.profraw" | xargs rm -rf

for path in ${unittest_folders[@]}; do
    pushd $path
    cargo test
    popd
done

grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o unit_test_coverage

unset RUSTFLAGS
unset LLVM_PROFILE_FILE
