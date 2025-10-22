#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    pushd deps/spdm-rs
    bash sh_script/pre-build.sh
    export SPDM_CONFIG=../../../config/spdm_config.json
    popd
}

preparation
