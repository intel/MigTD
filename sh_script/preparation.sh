#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    pushd deps/rustls
    git reset --hard 79b48e3d4adecc8262811ab781477ad24c09f496
    git clean -f -d
    patch -p 1 -i ../patches/rustls.diff
    popd
}

preparation
