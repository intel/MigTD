## QEMU-KVM Configuration

### Known issue

### Ingredients (component - version)
1. SEAMLDR - SEAMLDR_1.5.00.15 (NPW signed)
2. TDX Module - TDX_1.5.00.19
3. Host Kernel - mvp-tdx-6.2 (6.2)
4. Qemu - mvp-qemu-7.2 (7.2)
5. Guest Kernel - mvp-tdx-6.2 (6.2)
6. OS - centos stream 8
7. Attestation Library - tdx_1.5_mvp_23q1
8. DCAP - tdx_1.5_dcap_mvp_23q1

### Run Source MigTD (MigTD-s) Script
```
QEMU=/path/to/qemu-system-x86_64
MIGTD=/path/to/migtd.bin

$QEMU -accel kvm \
-M q35 \
-cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
-smp 1,threads=1,sockets=1 \
-m 32M \
-object tdx-guest,id=tdx0,sept-ve-disable=off,debug=off,quote-generation-service=vsock:1:4050 \
-object memory-backend-memfd-private,id=ram1,size=32M \
-machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${MIGTD} \
-device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=18,disable-legacy=on \
-name migtd-src,process=migtd-src,debug-threads=on \
-no-hpet \
-nographic -vga none -nic none \
-serial mon:stdio
```

### Run Destination MigTD (MigTD-d) Script
```
QEMU=/path/to/qemu-system-x86_64
MIGTD=/path/to/migtd.bin

$QEMU -accel kvm \
-M q35 \
-cpu host,host-phys-bits,-kvm-steal-time,pmu=off \
-smp 1,threads=1,sockets=1 \
-m 32M \
-object tdx-guest,id=tdx0,sept-ve-disable=off,debug=off,quote-generation-service=vsock:1:4050 \
-object memory-backend-memfd-private,id=ram1,size=32M \
-machine q35,memory-backend=ram1,confidential-guest-support=tdx0,kernel_irqchip=split \
-bios ${MIGTD} \
-device vhost-vsock-pci,id=vhost-vsock-pci1,guest-cid=36,disable-legacy=on \
-name migtd-dst,process=migtd-dst,debug-threads=on \
-no-hpet \
-nographic -vga none -nic none \
-serial mon:stdio
```

### Start SOCAT agents
```
# Start the agent listening on source platform
socat TCP4-LISTEN:9001,reuseaddr VSOCK-LISTEN:1234,fork

# Start the agent listening on destination platform
socat TCP4-CONNECT:127.0.0.1:9001,reuseaddr VSOCK-LISTEN:1235,fork
```

### Connect MigTD-s and MigTD-d and Run Pre-Migration
```
#!/bin/bash

# Asking migtd-src to connect to the src socat
echo "qom-set /objects/tdx0/ vsockport 1234" | nc -U /tmp/qmp-sock-src

# Asking migtd-dst to connect to the dst socat
echo "qom-set /objects/tdx0/ vsockport 1235" | nc -U /tmp/qmp-sock-dst
```
