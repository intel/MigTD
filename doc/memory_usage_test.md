# Migration TD Multi Session Memory Consumption Test

## Preparation

Download source code & test script:

```bash
git clone https://github.com/intel/MigTD.git
git submodule update --init --recursive
./sh_script/preparation.sh
```

## Apply changes to enable stack and heap benchmark

Reference change at: <https://github.com/intel/MigTD/pull/556>

Manual pend at places at mid of the mutual attestation, where the heap/stack are consumed, to wait for transferring the other session.

Because vsock transport layer doesn't support multi-links at same time, the pending place should make both destination and source migtds pend at same time without on-going messages. The reference change pends both the responder and requester after key_exchange_rsp, waits for 20 secs to run other sessions, and continue the pre-migration.

## Build Test binary

Build vsock migtd binary with adding features with

```bash
-features test_stack_size,test_heap_size
```

and with info logging enabled,

```bash
-l info
```

Example builds

Policy V1:

```bash
cargo image --features spdm_attestation,test_stack_size,test_heap_size --policy config/policy_pre_production_fmspc.json --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer -l info
```

Policy V2:

```bash
cargo image --features spdm_attestation,test_stack_size,test_heap_size --policy-v2 --policy config/templates/policy_v2_signed.json --policy-issuer-chain config/templates/policy_issuer_chain.pem -l info
```

## Run the test

This readme uses 2 seesions as an example, and this this method supports adding more seesions.

Please refer to readme.md for more information to build and run pre-migration tests.

Example commands are based on QEMU version 8.1.90.

### Start 2 pairs of socats

```bash
socat TCP4-LISTEN:9001,reuseaddr VSOCK-LISTEN:1234,fork &
sleep 1
socat TCP4-CONNECT:127.0.0.1:9001,reuseaddr VSOCK-LISTEN:1235,fork &
sleep 1
socat TCP4-LISTEN:9001,reuseaddr VSOCK-LISTEN:1236,fork &
sleep 1
socat TCP4-CONNECT:127.0.0.1:9001,reuseaddr VSOCK-LISTEN:1237,fork &
sleep 1
```

### Start migtd dst

(example)

```bash
QEMU=/path/to/qemu-system-x86_64
MIGTD=/path/to/migtd.bin
qmp_sock_migtd_dst="/tmp/qmp-sock-migtd-dst"

$QEMU -accel kvm \
-M q35 \
-cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
-smp 1,threads=1,sockets=1 \
-m 32M \
-object '{"qom-type":"tdx-guest","id":"tdx0", "sept-ve-disable": false, "debug": false, "quote-generation-socket":{"type": "vsock", "cid":"1"port":"4050"}}' \
-machine q35,kernel_irqchip=split,hpet=off,confidential-guest-support=tdx0 \
-bios ${MIGTD} \
-device vhost-vsock-pci,guest-cid=21,disable-legacy=on \
-name migtd-dst,process=migtd-dst,debug-threads=on \
-no-hpet \
-nographic -vga none -nic none \
-serial mon:stdio
```

### Start migtd src

(example)

```bash
QEMU=/path/to/qemu-system-x86_64
MIGTD=/path/to/migtd.bin
qmp_sock_migtd_dst="/tmp/qmp-sock-migtd-src"

$QEMU -accel kvm \
-M q35 \
-cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
-smp 1,threads=1,sockets=1 \
-m 32M \
-object '{"qom-type":"tdx-guest","id":"tdx0", "sept-ve-disable": false, "debug": false, "quote-generation-socket":{"type": "vsock", "cid":"1"port":"4050"}}' \
-machine q35,kernel_irqchip=split,hpet=off,confidential-guest-support=tdx0 \
-bios ${MIGTD} \
-device vhost-vsock-pci,guest-cid=23,disable-legacy=on \
-device vhost-vsock-pci,guest-cid=24,disable-legacy=on \
-device vhost-vsock-pci,guest-cid=25,disable-legacy=on \
-name migtd-src,process=migtd-src,debug-threads=on \
-no-hpet \
-nographic -vga none -nic none \
-serial mon:stdio
```

### Start first destination td

(example)

```bash
QEMU=/path/to/qemu-system-x86_64
GUEST_KERNEL=bzImage
IMAGE=/path/to/guest-image
qmp_sock_dst="/tmp/qmp-sock-dst"
TDVF=/path/to/OVMF.fd
LOG="user-dst.log"
TARGET_PID=$(pgrep migtd-dst)

$QEMU -accel kvm \
-cpu host,host-phys-bits,pmu=off,-kvm-steal-time,-kvmclock,-kvm-asyncpf,-kvmclock-stable-bit,tsc-freq=1000000000 \
-smp 2 \
-m 8G \
-object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID} \
-machine q35,hpet=off,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${TDVF} \
-chardev stdio,id=mux,mux=on,logfile=${LOG} \
-device virtio-serial,romfile= \
-device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
-drive file=$IMAGE,if=virtio,id=virtio-disk0,format=raw \
-name process=lm_src,debug-threads=on \
-nodefaults \
-D /run/qemu_dst.log -nographic -vga none \
-monitor unix:$qmp_sock_dst,server,nowait \
-incoming tcp:0:6666
```

### Start first source td

(example)

```bash
QEMU=/path/to/qemu-system-x86_64
GUEST_KERNEL=bzImage
IMAGE=/path/to/guest-image
qmp_sock_src="/tmp/qmp-sock-src"
TDVF=/path/to/OVMF.fd
LOG="user-src.log"
TARGET_PID=$(pgrep migtd-src)

$QEMU -accel kvm \
-cpu host,host-phys-bits,pmu=off,-kvm-steal-time,-kvmclock,-kvm-asyncpf,-kvmclock-stable-bit,tsc-freq=1000000000 \
-smp 2 \
-m 8G \
-object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID} \
-machine q35,hpet=off,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${TDVF} \
-chardev stdio,id=mux,mux=on \
-device virtio-serial,romfile= \
-device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
-drive file=$IMAGE,if=virtio,id=virtio-disk0,format=raw \
-name process=lm_dst,debug-threads=on \
-nodefaults \
-nographic -vga none \
-monitor unix:$qmp_sock_src,server,nowait
```

### Start second destination td

(example)

```bash
QEMU=/path/to/qemu-system-x86_64
GUEST_KERNEL=bzImage
IMAGE=/path/to/guest-image-2
qmp_sock_dst="/tmp/qmp-sock-dst-2"
TDVF=/path/to/OVMF.fd
LOG="user-dst-2.log"
TARGET_PID=$(pgrep migtd-dst)

$QEMU -accel kvm \
-cpu host,host-phys-bits,pmu=off,-kvm-steal-time,-kvmclock,-kvm-asyncpf,-kvmclock-stable-bit,tsc-freq=1000000000 \
-smp 2 \
-m 8G \
-object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID} \
-machine q35,hpet=off,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${TDVF} \
-chardev stdio,id=mux,mux=on,logfile=${LOG} \
-device virtio-serial,romfile= \
-device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
-drive file=$IMAGE,if=virtio,id=virtio-disk0,format=raw \
-name process=lm_src,debug-threads=on \
-nodefaults \
-D /run/qemu_dst.log -nographic -vga none \
-monitor unix:$qmp_sock_dst,server,nowait \
-incoming tcp:0:6667
```

### Start second source td

(example)

```bash
QEMU=/path/to/qemu-system-x86_64
GUEST_KERNEL=bzImage
IMAGE=/path/to/guest-image-2
qmp_sock_src="/tmp/qmp-sock-src-2"
TDVF="OVMF.fd"
TDVF=/path/to/OVMF.fd
TARGET_PID=$(pgrep migtd-src)

$QEMU -accel kvm \
-cpu host,host-phys-bits,pmu=off,-kvm-steal-time,-kvmclock,-kvm-asyncpf,-kvmclock-stable-bit,tsc-freq=1000000000 \
-smp 2 \
-m 8G \
-object tdx-guest,id=tdx0,sept-ve-disable=on,debug=off,migtd-pid=${TARGET_PID} \
-machine q35,hpet=off,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${TDVF} \
-chardev stdio,id=mux,mux=on \
-device virtio-serial,romfile= \
-device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
-drive file=$IMAGE,if=virtio,id=virtio-disk0,format=raw \
-name process=lm_dst,debug-threads=on \
-nodefaults \
-nographic -vga none \
-monitor unix:$qmp_sock_src,server,nowait
```

### Connect

Sleep 5 seconds before the second connect to wait for the first pre-migration reaches pooling point to avoid vsock multi-links at same time and the possible resulting hang.

```bash
echo "qom-set /objects/tdx0/ vsockport 1234" | nc -U /tmp/qmp-sock-src
echo "qom-set /objects/tdx0/ vsockport 1235" | nc -U /tmp/qmp-sock-dst
sleep 5
echo "qom-set /objects/tdx0/ vsockport 1236" | nc -U /tmp/qmp-sock-src-2
echo "qom-set /objects/tdx0/ vsockport 1237" | nc -U /tmp/qmp-sock-dst-2
```

### Check the result

Wait all sessions complete pre-migration, and check the data logged in terminal for memory using status:

(example result)

```bash
INFO - MSK exchange completed
max stack usage: 118128
max heap usage: 190585
```

### Current SPDM attestation memory data

Current test result for spdm attestation are determined by destination migtd with policy v2 configuration.

```bash
Stack Size = 0x16_0000
Heap Size = 0x12_0000 + 0x5_0000 * session_num
```

Per session heap using mainly are about 0x2_8000 spdm context data, and 0x2_0000 remote policy data.

The proposed memory consumption equations after adding buffers for worst case are

```bash
Stack Size = 0x20_0000
Heap Size = 0x10_0000 + 0x8_0000 * session_num
```

We cannot test shared memory consumption with vsock since the shared memory are allocated in device layer for data sending and receiving whem vmcall is used, while vsock doesn't support multi links at same time. Thus, this readme provides an deductive equation to config shared memory:

```bash
Shared Memory Size = 0x4_0000 + 0x2_0000 * session_num
```

where 0x2_0000 is the max buffer size that allocated in shared memory for vmcall, current data determined by the size of v2 policy sent by vmcall-raw transport.
