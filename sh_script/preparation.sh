#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    pushd deps/rustls
    git reset --hard ae277befb5061bbd4c44fea1c2697f2da5b2f6fa
    git clean -f -d
    patch -p 1 -i ../patches/rustls.diff
    popd
}

preparation
