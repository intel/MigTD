#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

script_path=$(dirname "$0")
temp_dir=$(mktemp -d)
nohup_logfile="${temp_dir}/nohup.log"

guest_image="/home/env/guest.img"
kernel="/home/env/bzImage"
qemu_tdx_path="/usr/local/bin/qemu-system-x86_64"

qmp_sock_src="/tmp/qmp-sock-src"
qmp_sock_dst="/tmp/qmp-sock-dst"
tdvf_image="/home/env/OVMF.fd"

mig_src_log="migtd-src.log"
mig_dst_log="migtd-dst.log"

src_migtd=""
dst_migtd=""
payload=""

cycle=0

# Test Configuration Info
cpus=1
memory=32M
device=vsock

# Function test case list
func_tcs_list=(
    *001*
    *002*
    *004*
    *005*
    *010*
    *011*
    *012*
    *013*
)

# trap cleanup exit

# MigTD start command
migtd_qemu_cmd="${qemu_tdx_path} \
    -accel kvm \
    -M q35 \
    -cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
    -smp ${cpus},threads=1,sockets=${cpus} \
    -m ${memory} \
    -object tdx-guest,id=tdx0,quote-generation-service=vsock:1:4050,sept-ve-disable=off,debug=off \
    -object memory-backend-memfd-private,id=ram1,size=${memory} \
    -machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
    -no-hpet \
    -nographic -vga none -nic none"

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -s <Source migtd binary path> required for pre migration test.
  -d <Destination migtd binary path> required for pre migration test.
  -f <Test td payload file path> required for test td payload test.
  -p <Cloud Hypervisor/Qemu path>.
  -i <Guest image file path> by default is td-guest.raw.
  -k <Kernel binary file path> by default is vmlinuz.
  -c <CPU number> by default is 1.
  -m <Memory size> by defalt is 2G.
  -n Cycle test number.
  -t Device(transport) used for host-guest communication, by default is `vsock`.
  -h Show help info
EOM
    exit 0
}

proccess_args() {
    while getopts ":f:i:p:k:s:t:c:m:n:d:h" option; do
        case "${option}" in
            i) guest_image=${OPTARG};;
            p) qemu_tdx_path=${OPTARG};;
            k) kernel=${OPTARG};;
            f) payload=${OPTARG};;
            s) src_migtd=${OPTARG};;
            d) dst_migtd=${OPTARG};;
            c) cpus=${OPTARG};;
            m) memory=${OPTARG};;
            n) cycle=${OPTARG};; 
            t) device=${OPTARG};;
            h) usage;;
        esac
    done
    
    if [[ ${payload} == "" ]]; then
        if [[ -z ${src_migtd} ]]; then
            die "Please input correct source migtd binary path"
        fi
        [ -e ${src_migtd} ] || die "Source migtd binary path: ${src_migtd} is not exists"

        if [[ -z ${dst_migtd} ]]; then
            die "Please input correct destination migtd binary path"
        fi
        [ -e ${dst_migtd} ] || die "Destination migtd binary path: ${dst_migtd} is not exists" 
    else
        if [[ -z ${payload} ]]; then
            die "Please input correct test td payload binary path"
        fi
        [ -e ${payload} ] || die "Test td payload path: ${payload} is not exists" 
    fi

    [ -e ${qemu_tdx_path} ] || die "TDX QEMU path: ${qemu_tdx_path} is not exists"

    echo "========================================="
    echo "Source migtd binary         : ${src_migtd}"
    echo "Destination migtd binary    : ${dst_migtd}"
    echo "Test td pyalod binary       : ${payload}"
    echo "Guest Image                 : ${guest_image}"
    echo "Kernel binary               : ${kernel}"
    echo "CPUs                        : ${cpus}"
    echo "Memmory Size                : ${memory}"
    echo "Device type                 : ${device}"
    echo "========================================="
}

cleanup() {
    rm -rf ${tmp_dir}
    rm -rf ${mig_src_log} ${mig_dst_log}

    sudo dmesg --clear

    kill_qemu && kill_socat
}

kill_qemu() {
    ps aux | grep ${qemu_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
}

kill_user_td() {
    ps aux | grep lm_src | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
    ps aux | grep lm_dst | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
    sleep 3
}

kill_socat() {
    ps aux | grep socat | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

is_function_tcs() {
    result=1
    for tcs_no in ${func_tcs_list[@]}; do
        if [[ ${dst_migtd} == *${tcs_no}* ]]
        then
            result=0
            break
        fi
    done

    if [[ ${dst_migtd} == *migtd.bin* ]]
    then
        result=0
    fi

    return ${result}
}

check_result()  {
    time=0
    result=1
    while ((${time}<=$3))
    do
        sleep 1
        if [[ `grep -c "$2" "$1"` -ne 0 ]]
        then
            result=0
            break
        fi
        let "time++"
    done
    return ${result}
}

check_migration_result()  {
    time=0
    result=1
    while ((${time}<=$2))
    do
        sleep 1
        if [[ "`dmesg | tail -2 | grep "$1"`" != "" ]]
        then
            result=0
            break
        fi
        let "time++"
    done
    return ${result}
}

install_qemu_tdx() {
    echo "-- Install QEMU"
    dnf update qemu --allowerasing
}

setup_agent() {
    socat TCP4-LISTEN:9001,reuseaddr VSOCK-LISTEN:1234,fork &
    socat TCP4-CONNECT:127.0.0.1:9001,reuseaddr VSOCK-LISTEN:1235,fork &
}

launch_src_migtd() {
    local cmd="${migtd_qemu_cmd} \
                -bios ${src_migtd} \
                -name migtd-src,process=migtd-src,debug-threads=on \
                -serial mon:stdio"

    if [[ ${device} == serial ]]
    then
        cmd="${cmd} \
            -device virtio-serial-pci,id=virtio-serial0 \
            -chardev socket,host=127.0.0.1,port=1234,server=off,id=foo \
            -device virtserialport,chardev=foo,bus=virtio-serial0.0"
    elif [[ ${device} == vsock ]]
    then
        cmd="${cmd} \
            -device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=18,disable-legacy=on"
    fi

    nohup ${cmd} > ${mig_src_log} &

    sleep 1
}

launch_dst_migtd() {
    local cmd="${migtd_qemu_cmd} \
                -bios ${dst_migtd} \
                -name migtd-dst,process=migtd-dst,debug-threads=on \
                -serial mon:stdio"

    if [[ ${device} == serial ]]
    then
        cmd="${cmd} \
            -device virtio-serial-pci,id=virtio-serial0 \
            -chardev socket,host=127.0.0.1,port=1234,server=on,id=foo \
            -device virtserialport,chardev=foo,bus=virtio-serial0.0"
    elif [[ ${device} == vsock ]]
    then
        cmd="${cmd} \
            -device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=36,disable-legacy=on"
    fi

    nohup ${cmd} > ${mig_dst_log} &

    sleep 1
}

launch_src_migtd_without_device() {
    local cmd="${migtd_qemu_cmd} \
                -bios ${src_migtd} \
                -name migtd-src,process=migtd-src,debug-threads=on \
                -serial mon:stdio"

    # Connect to dst MigTD to make it run
    if [[ ${device} == serial ]]
    then
        cmd="${cmd} \
            -chardev socket,host=127.0.0.1,port=1234,server=off,id=foo"
    fi

    nohup ${cmd} > ${mig_src_log} &

    sleep 1
}

launch_src_td() {
    local MIGTD_PID=$(pgrep migtd-src) 
    nohup ${qemu_tdx_path} -accel kvm \
        -cpu host,host-phys-bits,pmu=off,-kvm-steal-time,-kvmclock,-kvm-asyncpf,-kvmclock-stable-bit,tsc-freq=1000000000 \
        -smp 1 \
        -m 2G \
        -object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${MIGTD_PID} \
        -object memory-backend-memfd-private,id=ram1,size=2G \
        -machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
        -bios ${tdvf_image} \
        -chardev stdio,id=mux,mux=on \
        -device virtio-serial,romfile= \
        -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
        -drive file=${guest_image},if=virtio,id=virtio-disk0,format=raw \
        -kernel ${kernel} \
        -append "root=/dev/vda1 rw console=hvc0" \
        -name process=lm_src,debug-threads=on \
        -no-hpet -nodefaults \
        -D qemu_src.log -nographic -vga none \
        -monitor unix:${qmp_sock_src},server,nowait &

    sleep 1
}

launch_dst_td() {
    local MIGTD_PID=$(pgrep migtd-dst) 
    nohup ${qemu_tdx_path} -accel kvm \
        -cpu host,host-phys-bits,pmu=off,-kvm-steal-time,-kvmclock,-kvm-asyncpf,-kvmclock-stable-bit,tsc-freq=1000000000 \
        -smp 1 \
        -m 2G \
        -object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${MIGTD_PID} \
        -object memory-backend-memfd-private,id=ram1,size=2G \
        -machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
        -bios ${tdvf_image} \
        -chardev stdio,id=mux,mux=on \
        -device virtio-serial,romfile= \
        -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
        -drive file=${guest_image},if=virtio,id=virtio-disk0,format=raw \
        -name process=lm_dst,debug-threads=on \
        -no-hpet -nodefaults \
        -D qemu_dst.log -nographic -vga none \
        -monitor unix:${qmp_sock_dst},server,nowait \
        -incoming tcp:0:6666 &

    sleep 1
}

send_mig_command() {
    # Asking migtd-src to connect to the src socat
    echo "qom-set /objects/tdx0/ vsockport 1234" | nc -U /tmp/qmp-sock-src

    # Asking migtd-dst to connect to the dst socat
    echo "qom-set /objects/tdx0/ vsockport 1235" | nc -U /tmp/qmp-sock-dst
}

test_migtd() {
    echo "-- start test migration td"
    local time_out=30

    if [[ ${device} == vsock ]]
    then 
        echo "-- setup agent"
        setup_agent
    fi

    echo "-- launch dst migtd"
    launch_dst_migtd

    echo "-- launch src migtd"
    if [[ ${src_migtd} == *009* ]]
    then
        launch_src_migtd_without_device 
    else
        launch_src_migtd
    fi

    echo "-- launch src td"
    launch_src_td
    echo "-- launch dst td"
    launch_dst_td
    echo "-- send migration command"
    send_mig_command

    if is_function_tcs
    then
        # TBD need to update to avoid no run scenario
        local key_str="Pre-migration is done"
    else
        # TBD need to update to avoid no run scenario
        local key_str="pre-migration failed"
    fi
    
    check_migration_result "${key_str}" ${time_out}
    if [[ $? -eq 0 ]]
    then
        kill_qemu
        echo "-- migration td test: Pass"
    else
        kill_qemu
        echo "-- migration td test: Fail" && exit 1
    fi
}

cycle_test_migtd() {
    echo "-- start test migration td"
    local time_out=30

    if [[ ${device} == vsock ]]
    then 
        echo "-- setup agent"
        setup_agent
    fi
    echo "-- launch dst migtd"
    launch_dst_migtd
    echo "-- launch src migtd"
    launch_src_migtd
    
    for ((i=1;i<${cycle};i++))
    do
        echo "#########################"
        echo "Cycling test ${i}"
        echo "#########################"
        echo "-- launch src td"
        launch_src_td

        echo "-- launch dst td"
        launch_dst_td

        echo "-- send migration command"
        send_mig_command

        local key_str="Pre-migration is done"

        check_migration_result "${key_str}" ${time_out}
        if [[ $? -eq 0 ]]
        then
            kill_user_td
            echo "-- migration td test: Pass"
        else
            kill_qemu
            echo "-- migration td test: Fail" && exit 1
        fi
        sudo dmesg --clear
    done
    echo "-- migration td cycling test: Pass"
    kill_qemu
}

launch_td_test_payload() {
    echo "-- launch td test payload"
    local time_out=20
    local key_str="0 failed"

    nohup ${qemu_tdx_path} -accel kvm \
        -M q35 \
        -name process=tdxvm \
        -smp ${cpus}\
        -object tdx-guest,id=tdx,quote-generation-service=vsock:1:4050,sept-ve-disable=off,debug=off \
        -machine q35,kernel_irqchip=split,confidential-guest-support=tdx \
        -no-hpet \
        -cpu host,host-phys-bits,-kvm-steal-time,pmu=off,-amx-tile,-amx-int8 \
        -bios ${payload} \
        -device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=37,disable-legacy=on \
        -m ${memory} -nographic -vga none -nic none \
        -serial mon:stdio > ${nohup_logfile} 2>&1 &
    
    check_result ${nohup_logfile} "${key_str}" ${time_out}

    if [[ $? -eq 0 ]]
    then
        kill_qemu
        cat ${nohup_logfile} && echo "-- launch td test payload: Pass"
    else
        kill_qemu
        cat ${nohup_logfile} && echo "-- launch td test payload: Fail" && exit 1
    fi
}

run_test() {
    echo "========================================="
    echo "               Run Test                  "
    echo "========================================="
    if [[ ${payload} == "" ]] 
    then
        if [[ ${cycle} -eq 0 ]]
        then
            test_migtd
        else
            cycle_test_migtd
        fi
    else
        launch_td_test_payload
    fi
}

main() {
    cleanup
    run_test
}

proccess_args $@
main
