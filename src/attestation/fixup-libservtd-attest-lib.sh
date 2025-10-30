#!/bin/bash

##==============================================================================
##
## Script to fix libservtd_attest.a for application linking
## Author: Mike Brasher <mikbras@microsoft.com>
##
##==============================================================================

##==============================================================================
##
## Find libservtd_attest.a (there may be more than one)
##
##==============================================================================

targets="../../deps/linux-sgx/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux/libservtd_attest.a"

##==============================================================================
##
## Find tlibc library
##
##==============================================================================

tlibc_lib=$(find ../../deps/linux-sgx -name libtlibc.a)
if [ ! -f "${tlibc_lib}" ]; then
    echo "$0: tlibc lib not found"
    exit 1;
fi

##==============================================================================
##
## Find sgxssl library
##
##==============================================================================

sgxssl_lib=$(find ../../deps/linux-sgx -name libsgx_tsgxssl_crypto.a)
if [ ! -f "${sgxssl_lib}" ]; then
    echo "$0: sgxssl lib not found"
    exit 1;
fi

##==============================================================================
##
## Remove unwanted objects from servtd_attest archive. This deletes all objects
## found in libsgx_tsgxssl_crypto.a from libservtd_attest.a. It also deletes
## most objects found in libtlibc.a from libservtd_attest.a (a few objects are
## spared, since tlibc introduces non-standard symbols, such as spinlocks and
## various non-standard string functions).
##
##==============================================================================

for i in ${targets}
do
    lib="${i%.a}_app.a"
    cp "${i}" "${lib}"
    if [ "$?" != "0" ]; then
        echo "$0: failed to copy ${i} to ${lib}"
        exit 1;
    fi
    ar d ${lib} $(ar t ${tlibc_lib} | grep -v spinlock.o | grep -v memset | grep -v memcpy )
    ar d ${lib} $(ar t ${sgxssl_lib})
    echo "Created ${lib}"
done

##==============================================================================
##
## Add object with extra code to archive. The errno and heap related objects
## were removed above so definitions are added here to compensate.
##
##==============================================================================

dir=$(mktemp -d)
src=${dir}/libservtd_attest_extras.c
obj=${dir}/libservtd_attest_extras.o

cat > ${src} <<END
#include <stddef.h>

int* __errno()
{
    extern int* __errno_location();
    return __errno_location();
}

void* heap_base;
size_t heap_size;
END

gcc -c ${src} -o ${obj}
if [ "$?" != "0" ]; then
    echo "$0: compile failed: ${src}"
    exit 1;
fi

for i in ${targets}
do
    lib="${i%.a}_app.a"
    ar r "${lib}" "${obj}"
done