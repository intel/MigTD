#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    pushd deps/rustls
    git reset --hard 4d1b762b5328a1714862ba73ec72d5522fe0c049
    git clean -f -d
    patch -p 1 -i ../patches/rustls.diff
    popd
}

preparation
