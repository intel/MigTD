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

firmware=""
type="pe"

cycle=0

# Test Configuration Info
cpus=1
memory=32M

# trap cleanup exit

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -f <TD Shim Firmware file path> required.
  -p <Cloud Hypervisor/Qemu path>.
  -i <Guest image file path> by default is td-guest.raw.
  -k <Kernel binary file path> by default is vmlinuz.
  -t [pe|elf] firmware type, by default it is "pe".
  -c <CPU number> by default is 1.
  -m <Memory size> by defalt is 2G.
  -n Cycle test number.
  -h Show help info
EOM
    exit 0
}

proccess_args() {
    while getopts ":i:p:k:f:t:c:m:n:h" option; do
        case "${option}" in
            i) guest_image=${OPTARG};;
            p) qemu_tdx_path=${OPTARG};;
            k) kernel=${OPTARG};;
            f) firmware=${OPTARG};;
            t) type=${OPTARG};;
            c) cpus=${OPTARG};;
            m) memory=${OPTARG};;
            n) cycle=${OPTARG};; 
            h) usage;;
        esac
    done

    if [[ -z ${firmware} ]]; then
        die "Please input correct Migration TD Image path"
    fi

    [ -e ${firmware} ] || die "Migration TD Image path: ${firmware} is not exists"
    [ -e ${qemu_tdx_path} ] || die "TDX QEMU path: ${qemu_tdx_path} is not exists"

    if [[ -n ${type} ]]; then
        case "${type}" in
            pe|elf) echo "";;
            *) die "Unspported type: ${type}";;
        esac
    fi

    echo "========================================="
    echo "TD Shim Image     : ${firmware}"
    echo "Guest Image       : ${guest_image}"
    echo "Kernel binary     : ${kernel}"
    echo "Type              : ${type}"
    echo "CPUs              : ${cpus}"
    echo "Memmory Size      : ${memory}"
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
    nohup ${qemu_tdx_path} \
        -accel kvm \
        -M q35 \
        -cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
        -smp ${cpus},threads=1,sockets=${cpus} \
        -m ${memory} \
        -object tdx-guest,id=tdx0,quote-generation-service=vsock:1:4050,sept-ve-disable=off,debug=off \
        -object memory-backend-memfd-private,id=ram1,size=${memory} \
        -machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
        -bios $1 \
        -device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=18,disable-legacy=on \
        -name migtd-src,process=migtd-src,debug-threads=on \
        -no-hpet \
        -nographic -vga none -nic none \
        -serial mon:stdio > ${mig_src_log} &

    sleep 10
}

launch_dst_migtd() {
    nohup ${qemu_tdx_path} \
        -accel kvm \
        -M q35 \
        -cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
        -smp ${cpus},threads=1,sockets=${cpus} \
        -m ${memory} \
        -object tdx-guest,id=tdx0,quote-generation-service=vsock:1:4050,sept-ve-disable=off,debug=off \
        -object memory-backend-memfd-private,id=ram1,size=${memory} \
        -machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
        -bios $1 \
        -device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=36,disable-legacy=on \
        -name migtd-dst,process=migtd-dst,debug-threads=on \
        -no-hpet \
        -nographic -vga none -nic none \
        -serial mon:stdio > ${mig_dst_log} &

    sleep 10
}

launch_dst_migtd_without_vsock() {
    nohup ${qemu_tdx_path} \
        -accel kvm \
        -M q35 \
        -cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
        -smp ${cpus},threads=1,sockets=${cpus} \
        -m ${memory} \
        -object tdx-guest,id=tdx0,quote-generation-service=vsock:1:4050,sept-ve-disable=off,debug=off \
        -object memory-backend-memfd-private,id=ram1,size=${memory} \
        -machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
        -bios $1 \
        -name migtd-dst,process=migtd-dst,debug-threads=on \
        -no-hpet \
        -nographic -vga none -nic none \
        -serial mon:stdio > ${mig_dst_log} &

    sleep 10
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

    sleep 10
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

    sleep 10
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

    echo "-- setup agent"
    setup_agent
    echo "-- launch src migtd"
    if [[ ${firmware} == *004* ]] || [[ ${firmware} == *005* ]] || [[ ${firmware} == *006* ]] || [[ ${firmware} == *migtd.bin* ]]
    then
        launch_src_migtd ${firmware}
    elif [[ ${firmware} == *007* ]] || [[ ${firmware} == *008* ]] || [[ ${firmware} == *009* ]]
    then 
        launch_src_migtd "`dirname ${firmware}`/migtd_no.bin"
    else
        launch_src_migtd "`dirname ${firmware}`/migtd_001.bin"
    fi
    echo "-- launch dst migtd"
    if [[ ${firmware} == *009* ]]
    then
        launch_dst_migtd_without_vsock ${firmware}
    else
        launch_dst_migtd ${firmware}
    fi
    echo "-- launch src td"
    launch_src_td
    echo "-- launch dst td"
    launch_dst_td
    echo "-- send migration command"
    send_mig_command

    if [[ ${firmware} == *001* ]] || [[ ${firmware} == *002* ]] || [[ ${firmware} == *migtd.bin* ]] || [[ ${firmware} == *004* ]] || [[ ${firmware} == *005* ]]
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

    echo "-- setup agent"
    setup_agent
    echo "-- launch src migtd"
    launch_src_migtd ${firmware}

    echo "-- launch dst migtd"
    launch_dst_migtd ${firmware}
    
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
        -bios ${firmware} \
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
    if [[ ${firmware} == *final*-test* ]] 
    then
        launch_td_test_payload
    fi

    if [[ ${firmware} == *migtd* ]] && [[ ${cycle} -ne 0 ]]
    then
        cycle_test_migtd
    elif [[ ${firmware} == *migtd* ]] && [[ ${cycle} -eq 0 ]]
    then
        test_migtd
    fi
}

main() {
    cleanup
    run_test
}

proccess_args $@
main
