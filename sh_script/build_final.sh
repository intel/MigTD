#!/bin/bash

set -exo pipefail

export CC_x86_64_unknown_none=clang
export AR_x86_64_unknown_none=llvm-ar
export AS=nasm

type="full"
TestBinaries="Bin"

function cleanup() {
    cargo clean

    pushd deps/td-shim
    cargo clean
    popd
}

function proccess_args() {
    while getopts ":t:a:v:d:c" option; do
        case "${option}" in
            t) type=${OPTARG};;
            a) attestation=${OPTARG};;
            d) device=${OPTARG};;
            c) cleanup;;
        esac
    done

    if [[ -n ${type} ]]; then
        case "${type}" in
            migtd|test|full) echo "";;
            *) die "Unspported type: ${type}";;
        esac
    fi

    if [[ ${type} == "test" ]]
    then
        rm -rf ${TestBinaries}
        mkdir ${TestBinaries}
    fi

    MIGTD_FEATURE="main,stack-guard"

    if [[ ${attestation} != "on" ]];
    then
        MIGTD_FEATURE+=",test_disable_ra_and_accept_all"
    fi

    case "${device}" in
        vmcall) MIGTD_FEATURE+=",vmcall-vsock";;
        serial) MIGTD_FEATURE+=",virtio-serial";;
        *) MIGTD_FEATURE+=",virtio-vsock";;
    esac
}

function check_file_exist() {
    if [[ -f $1 ]]
    then
        echo "File $1 generated successfully"
    else
        echo "File $1 generated failure"
        exit 1
    fi
}

function populate_layout() {
    pushd deps/td-shim/devtools/td-layout-config
    cargo run -- -t memory ../../../../config/shim_layout.json -o ../../td-layout/src/runtime/exec.rs
    popd
}

# Required by `td-shim-tools` but cannot be set when compiling attestation library
# TODO: Move to `xtask`
function set_cc() {
    export CC=clang
    export AR=llvm-ar
}

function unset_cc() {
    unset CC
    unset AR
}

function cp2bin() {
    cp $1 ${TestBinaries}
}

function final_test_td_payload() {
    echo "-- Build final binary with test td payload"
    cleanup

    pushd tests
    cargo build -p test-td-payload --target x86_64-unknown-none --release --features=main,tdx --no-default-features
    popd

    pushd deps/td-shim
    cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features

    set_cc
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n test-td-payload -w ../../ --target x86_64-unknown-none
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n td-shim --target x86_64-unknown-none
    
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
            target/x86_64-unknown-none/release/ResetVector.bin \
            target/x86_64-unknown-none/release/td-shim \
            -m ../../config/metadata.json \
            -p ../../target/x86_64-unknown-none/release/test-td-payload \
            -o target/x86_64-unknown-none/release/final-test.bin
    
    cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
            target/x86_64-unknown-none/release/final-test.bin \
            -f F10E684E-3ABD-20E4-5932-8F973C355E57 ../../tests/test-td-payload/src/test.json \
            CA437832-4C51-4322-B13D-A21BD0C8FFF6 ../../config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer \
            -o ../../target/release/final-test.bin
    popd
    unset_cc

    check_file_exist "./target/release/final-test.bin"
    cp2bin "./target/release/final-test.bin"
}

function final_test_migtd() {
    echo "-- Build final binary for test cases of migration TD"
    cleanup
    build_migtd
    build_tdshim_sb
    strip_info
    
    echo "-- Build final binary for test case 001 of migration TD"
    # Normal secure boot without any policy check
    sign "migtd_sb1" 1
    link "migtd_sb1" "migtd_sb1.bin"
    enroll "migtd_sb1.bin" "policy_001.json" "migtd_001.bin"

    echo "-- Build final binary for test case 002 of migration TD"
    # RTMR1 of src and dst are not equal, but RTMR1 is not in policy - SVN
    sign "migtd_sb2" 2
    link "migtd_sb2" "migtd_sb2.bin"
    enroll "migtd_sb2.bin" "policy_001.json" "migtd_002.bin"

    echo "-- Build final binary for test case 003 of migration TD"
    # RTMR1 of src and dst are not equal and RTMR1 is in policy
    sign "migtd_sb3" 13
    link "migtd_sb3" "migtd_sb3.bin"
    enroll "migtd_sb3.bin" "policy_002.json" "migtd_003.bin"

    echo "-- Build final binary for test case 004 of migration TD"
    # Secure boot and svn(13) in range(13..18) of policy
    sign "migtd_sb4" 13
    link "migtd_sb4" "migtd_sb4.bin"
    enroll "migtd_sb4.bin" "policy_004.json" "migtd_004.bin"

    echo "-- Build final binary for test case 005 of migration TD"
    # Secure boot and svn(17) in range(13..18) of policy
    sign "migtd_sb5" 17
    link "migtd_sb5" "migtd_sb5.bin"
    enroll "migtd_sb5.bin" "policy_004.json" "migtd_005.bin"

    echo "-- Build final binary for test case 006 of migration TD"
    # Secure boot and svn(18) out of range(13..18)
    sign "migtd_sb6" 18
    link "migtd_sb6" "migtd_sb6.bin"
    enroll "migtd_sb6.bin" "policy_004.json" "migtd_006.bin"

    echo "-- Build final binary for test case 010 of migration TD"
    # full policy with 
    enroll "migtd_sb1.bin" "policy_full1.json" "migtd_010.bin"
   
    echo "-- Build final binary for test case 011 of migration TD"
    # full policy with 
    enroll "migtd_sb3.bin" "policy_full2.json" "migtd_011.bin"

    echo "-- Build final binary for test case 012 of migration TD"
    # Secure boot and dst svn(2) greater than src svn(1) 
    sign "migtd_src_sb12" 1
    sign "migtd_dst_sb12" 2
    link "migtd_src_sb12" "migtd_src_sb12.bin"
    link "migtd_dst_sb12" "migtd_dst_sb12.bin"
    enroll "migtd_src_sb12.bin" "policy_006.json" "migtd_src_012.bin"
    enroll "migtd_dst_sb12.bin" "policy_006.json" "migtd_dst_012.bin"

    echo "-- Build final binary for test case 013 of migration TD"
    # Secure boot and dst svn(1) equal than src svn(1) 
    sign "migtd_src_sb13" 1
    sign "migtd_dst_sb13" 1
    link "migtd_src_sb13" "migtd_src_sb13.bin"
    link "migtd_dst_sb13" "migtd_dst_sb13.bin"
    enroll "migtd_src_sb13.bin" "policy_006.json" "migtd_src_013.bin"
    enroll "migtd_dst_sb13.bin" "policy_006.json" "migtd_dst_013.bin"

    echo "-- Build final binary for test case 014 of migration TD"
    # Secure boot and dst svn(1) smaller than src svn(2) 
    sign "migtd_src_sb14" 2
    sign "migtd_dst_sb14" 1
    link "migtd_src_sb14" "migtd_src_sb14.bin"
    link "migtd_dst_sb14" "migtd_dst_sb14.bin"
    enroll "migtd_src_sb14.bin" "policy_006.json" "migtd_src_014.bin"
    enroll "migtd_dst_sb14.bin" "policy_006.json" "migtd_dst_014.bin"

    echo "-- Build final binary for test case 015 of migration TD"
    # Test operation "array-equal", sgxtcbcomponents is no equal with reference
    enroll "migtd_sb1.bin" "policy_007.json" "migtd_015.bin"

    echo "-- Build final binary for test case 016 of migration TD"
    # Test operation "array-greater-or-equal", sgxtcbcomponents is smaller than reference
    enroll "migtd_sb1.bin" "policy_008.json" "migtd_016.bin"

    echo "-- Build final binary for test case 017 of migration TD"
    # Test polciy content is not correct, "fmspcx" shall be "fmspc"
    enroll "migtd_sb1.bin" "policy_009.json" "migtd_017.bin"

    echo "-- Build final binary for test case 018 of migration TD"
    # Test polciy file does not contain actual platforms' fmspc
    enroll "migtd_sb1.bin" "policy_010.json" "migtd_018.bin"

    cleanup
    build_migtd
    build_tdshim
    strip_info
    link "migtd" "migtd_test.bin"
    enroll "migtd_test.bin" "policy_no.json" "migtd_no.bin"

    echo "-- Build final binary for test case 007 of migration TD"
    # Different policy file and check "Digest.MigTdPolicy"
    enroll "migtd_test.bin" "policy_003.json" "migtd_007.bin"
    
    echo "-- Build final binary for test case 008 of migration TD"
    # Invalid json
    enroll "migtd_test.bin" "policy_005.json" "migtd_008.bin"
    
    echo "-- Build final binary for test case 009 of migration TD"
    # Test without vsock deveice init
    enroll "migtd_test.bin" "policy_no.json" "migtd_009.bin"
}

function final_migtd() {
    echo "-- Build final binary for migtd"
    cleanup
    build_migtd
    build_tdshim
    strip_info
    link "migtd" "migtd.bin"
    enroll "migtd.bin" "policy.json" "migtd.bin"
}

function build_migtd() {
    cargo build -p migtd --target x86_64-unknown-none --release --features=${MIGTD_FEATURE}
    check_file_exist "./target/x86_64-unknown-none/release/migtd"    
}

function build_tdshim() {
    pushd deps/td-shim
    cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features
    check_file_exist "./target/x86_64-unknown-none/release/td-shim" 
    popd 
}

function build_tdshim_sb() {
    pushd deps/td-shim
    cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx,secure-boot --no-default-features 
    check_file_exist "./target/x86_64-unknown-none/release/td-shim"
    popd 
}

function strip_info() {
    pushd deps/td-shim
    set_cc
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n migtd -w ../../ --target x86_64-unknown-none
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n td-shim --target x86_64-unknown-none   
    popd
    unset_cc
}

# para1 - output binary name
# para2 - svn number
function sign() {
   pushd deps/td-shim
   cargo run -p td-shim-tools --bin td-shim-sign-payload -- -A ECDSA_NIST_P384_SHA384 -o \
           ../../target/x86_64-unknown-none/release/$1 data/sample-keys/ecdsa-p384-private.pk8 \
           ../../target/x86_64-unknown-none/release/migtd 1 $2
   popd
   check_file_exist "./target/x86_64-unknown-none/release/$1"
}

# para 1 - linked migtd name
# para 2 - Output binary name
function link() {
    pushd deps/td-shim
    cargo run -p td-shim-tools --bin td-shim-ld --no-default-features --features=linker -- \
            target/x86_64-unknown-none/release/ResetVector.bin \
            target/x86_64-unknown-none/release/td-shim \
            -m ../../config/metadata.json \
            -p ../../target/x86_64-unknown-none/release/$1 \
            -o ../../target/release/$2
    popd
    check_file_exist "./target/release/$2"
}

# para 1 - Enrolled migtd name
# para 2 - policy file name
# para 3 - Output binary name
function enroll() {
    pushd deps/td-shim
    if [[ $1 == *sb* ]]
    then
        cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
            ../../target/release/$1 \
            -f 0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A ../../src/policy/test/$2 \
            CA437832-4C51-4322-B13D-A21BD0C8FFF6 ../../config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer \
            -H SHA384 \
            -k data/sample-keys/ecdsa-p384-public.der \
            -o ../../target/release/$3 
    else
        cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
            ../../target/release/$1 \
            -f 0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A ../../src/policy/test/$2 \
            CA437832-4C51-4322-B13D-A21BD0C8FFF6 ../../config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer \
            -o ../../target/release/$3
    fi
    
    popd
    check_file_exist "./target/release/$3"
    cp2bin "./target/release/$3"
}

./sh_script/preparation.sh

populate_layout

proccess_args $@

case "${type}" in
    migtd) final_migtd ;;
    test) final_test_td_payload && final_test_migtd ;;
    full) final_migtd && final_test_td_payload && final_test_migtd;;
    *) final_migtd && final_test_td_payload && final_test_migtd;;  
esac