#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    pushd deps/rustls
    git reset --hard ef76fec1459c907e7472a19fb993567ca4b288f5
    git clean -f -d
    patch -p 1 -i ../patches/rustls.diff
    popd
}

preparation
