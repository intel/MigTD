#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

QEMU_EXEC="/usr/local/bin/qemu-system-x86_64"
TD_TYPE=""
KERNEL=""
GUEST_IMG=""
OVMF="/home/env/OVMF.fd"
BOOT_TYPE="direct"
TARGET_PID=""
ROOT_PARTITION="/dev/vda3"
QUOTE_TYPE=""
GUEST_CID=3
TELNET_PORT=9088
INCOMING_PORT=6666


usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -q <qemu path>            QEMU path
  -o <OVMF image path>      OVMF image path
  -i <guest image file>     Guest image file 
  -k <kernel file>          Kernel file
  -b [direct|grub]          Boot type, default is "direct" which requires kernel binary specified via "-k"
  -p                        incoming port
  -q [tdvmcall|vsock]       Support for TD quote using tdvmcall or vsock
  -r <root partition>       root partition for direct boot, default is /dev/vda1
  -t <src|dst>              Must set userTD type, src or dst
  -h                        Show this help
EOM
}

process_args() {
    while getopts "i:k:b:o:p:q:r:t:h" option; do
        case "${option}" in
            i) GUEST_IMG=$OPTARG;;
            k) KERNEL=$OPTARG;;
            o) OVMF=$OPTARG;;
            b) BOOT_TYPE=$OPTARG;;
            p) INCOMING_PORT=$OPTARG;;
            q) QEMU_EXEC=$OPTARG;;
            a) QUOTE_TYPE=$OPTARG;;
            r) ROOT_PARTITION=$OPTARG;;
            t) TD_TYPE=$OPTARG;;
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

    if [[ -z ${TD_TYPE} ]]; then
        usage
        error "Must set TD_TYPE -t [src|dst]"
    fi

    case ${TD_TYPE} in
        "src")
            GUEST_CID=3
            TELNET_PORT=9088
            TARGET_PID=$(pgrep migtd-src)
            ;;
        "dst")
            GUEST_CID=4
            TELNET_PORT=9089
            TARGET_PID=$(pgrep migtd-dst)
            ;;
        *)
            error "Invalid ${TD_TYPE}, must be [src|dst]"
            ;;
    esac

    case ${BOOT_TYPE} in
        "direct")
            if [[ ! -f ${KERNEL} ]]; then
                usage
                error "Kernel image file ${KERNEL} not exist. Please specify via option \"-k\""
            fi
            ;;
        "grub")
            ;;
        *)
            echo "Invalid ${BOOT_TYPE}, must be [direct|grub]"
            exit 1
            ;;
    esac

    if [[ ! -f ${GUEST_IMG} ]]; then
        usage
        error "Guest image file ${GUEST_IMG} not exist. Please specify via option \"-i\""
    fi

    if [[ ! -f ${QEMU_EXEC} ]]; then
        error "Please install QEMU which supports TDX."
    fi

    if [[ ! -f ${OVMF} ]]; then
        error "Could not find OVMF, please install first"
    fi

    if [[ -n ${QUOTE_TYPE} ]]; then
        case ${QUOTE_TYPE} in
            "tdvmcall") ;;
            "vsock");;
            *)
                error "Invalid quote type \"$QUOTE_TYPE\", must be [vsock|tdvmcall]"
                ;;
        esac
    fi
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    exit 1
}

launch_TDVM() {
QEMU_CMD="${QEMU_EXEC} \
-accel kvm \
-cpu host,pmu=off,-kvm-steal-time,-shstk,tsc-freq=1000000000 \
-smp 2,threads=1,sockets=1 \
-m 8G \
-object memory-backend-memfd-private,id=ram1,size=8G \
-machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${OVMF} \
-chardev stdio,id=mux,mux=on,logfile=lm-${TD_TYPE}.log \
-drive file=$(readlink -f "${GUEST_IMG}"),if=virtio,id=virtio-disk0,format=raw \
-name process=lm-${TD_TYPE},debug-threads=on \
-no-hpet -nodefaults \
-D /run/qemu-${TD_TYPE}.log -nographic -vga none \
-monitor unix:/tmp/qmp-sock-${TD_TYPE},server,nowait \
-monitor telnet:127.0.0.1:${TELNET_PORT},server,nowait \
-device virtio-serial,romfile= \
-device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux"

    if [[ -n ${QUOTE_TYPE} ]]; then
        if [[ ${QUOTE_TYPE} == "tdvmcall" ]]; then
		    QEMU_CMD+=" -object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID},quote-generation-service=vsock:2:4050"
        else
		    QEMU_CMD+=" -object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID}"
            QEMU_CMD+=" -device vhost-vsock-pci,guest-cid=${GUEST_CID}"
        fi
    else
		QEMU_CMD+=" -object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID}"
    fi

    if [[ ${BOOT_TYPE} == "direct" ]]; then
        QEMU_CMD+=" -kernel $(readlink -f "${KERNEL}")"
        QEMU_CMD+=" -append \"root=${ROOT_PARTITION} rw console=hvc0\" "
    fi

    if [[ ${TD_TYPE} == "dst" ]]; then
        QEMU_CMD+=" -incoming tcp:0:${INCOMING_PORT}"
    fi

    eval "${QEMU_CMD}"
}

process_args "$@"
launch_TDVM