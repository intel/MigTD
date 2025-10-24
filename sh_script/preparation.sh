#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    pushd deps/spdm-rs
    bash sh_script/pre-build.sh
    popd
}

preparation
