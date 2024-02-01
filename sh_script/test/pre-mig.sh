#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

TYPE="local"
DEST_IP=""
PRE_BINDING="false"

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -i <dest ip>              Destination platform ip address
  -t <local|remote>         Use single or cross host live migration
  -p [true|false]           Use pre-binding or not, default value is false
  -h                        Show this help
EOM
}

process_args() {
    while getopts "i:t:p:h" option; do
        case "${option}" in
            i) DEST_IP=$OPTARG;;
            t) TYPE=$OPTARG;;
            p) PRE_BINDING=$OPTARG;;
            h) usage
               exit 0
               ;;
            *)
               echo "Invalid option '-$OPTARG'"
               usage
               exit 1
               ;;
        esac
    done

    case ${TYPE} in
        "local");;
        "remote")
            if [[ -z ${DEST_IP} ]]; then
                error "Please use -i specify DEST_IP in remote type"
            fi
            ;;
        *)
            error "Invalid ${TYPE}, must be [local|remote]"
            ;;
    esac
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    exit 1
}

pre_mig(){
    DST_COMMAND="echo qom-set /objects/tdx0/ vsockport 1235 | nc -U /tmp/qmp-sock-dst"
    SRC_COMMAND="echo qom-set /objects/tdx0/ vsockport 1234 | nc -U /tmp/qmp-sock-src"

    if [[ ${PRE_BINDING} == "true" ]]; then
        DST_COMMAND="echo qom-set /objects/tdx0/ migtd-pid $(pgrep migtd-dst) | nc -U /tmp/qmp-sock-dst && "${DST_COMMAND}
        SRC_COMMAND="echo qom-set /objects/tdx0/ migtd-pid $(pgrep migtd-src) | nc -U /tmp/qmp-sock-src && "${SRC_COMMAND}
    fi

    # Asking migtd-dst to connect to the dst socat
    if [[ ${TYPE} == "local" ]]; then
        eval ${DST_COMMAND}
    else 
       ssh root@"${DEST_IP}" -o ConnectTimeout=30 "${DST_COMMAND}"
    fi

    # Asking migtd-dst to connect to the src socat
    eval ${SRC_COMMAND}
}

process_args "$@"
pre_mig