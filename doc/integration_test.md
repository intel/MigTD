# Migration TD Integration Test
## Preparation
Download source code & test script:
```
git clone https://github.com/intel/MigTD.git
git submodule update --init --recursive
./sh_script/preparation.sh
```
## Setup pytest environment
Please use recommend configuration in [integration_test.py](../sh_script/test/integration_test.py).

## Config test configuration file
```
cd sh_script/test
```
Config [test configration file](../sh_script/test/conf/pyproject.toml), for example:
```
[migtd.config]
qemu="/usr/local/bin/qemu-system-x86_64"
mig_td_script = "mig-td.sh"
user_td_script = "user-td.sh"
connect_script = "connect.sh"
pre_mig_script = "pre-mig.sh"
user_td_bios_img = "/home/env/OVMF.fd"
kernel_img = "/home/env/bzImage"
guest_img = "/home/env/guest.img"
stress_test_cycles = 1
```
## Build & Test
### Build Migration TD binary - Vsock
```
cargo image
```
### Run Test
Set stress_test_cycles to 1 in configration file.
```
pushd sh_script/test
sudo pytest -k "cycle"
popd
```
### Build Migration TD Test binaries - Vsock
```
bash sh_script/build_final.sh -t test -c -a on
```
### Run Test
```
pushd sh_script/test
sudo pytest -k "not cycle"
popd
```
### Build Migration TD binary - Serial
```
cargo image --no-default-features --features remote-attestation,stack-guard,virtio-serial
```
### Run Test
Set stress_test_cycles to 1 in configration file.
```
pushd sh_script/test
sudo pytest -k "cycle" --device_type serial
popd
```
### Build Migration TD Test binaries - Serial
```
bash sh_script/build_final.sh -t test -c -a on -d serial
```
### Run Test
```
pushd sh_script/test
sudo pytest -k "not cycle" --device_type serial
popd
```
