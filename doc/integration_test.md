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
The commands below use `--no-tdinfo` for compatibility with QEMU versions that do not support TDVF Type 7.

### Build Migration TD binary - Vsock
```
cargo image --no-tdinfo --policy config/policy_pre_production_fmspc.json --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer
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
bash sh_script/build_final.sh --no-tdinfo -t test -c -a on
```
### Run Test
```
pushd sh_script/test
sudo pytest -k "not cycle"
popd
```
### Build Migration TD binary - Serial
```
cargo image --no-tdinfo --no-default-features --features stack-guard,virtio-serial --policy config/policy_pre_production_fmspc.json --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer
```
### Run Test
Set stress_test_cycles to 1 in configration file.
```
pushd sh_script/test
sudo pytest -k "cycle" --device_type serial
popd
```

## Rebinding over Virtio

Rebinding is available with Policy v1 or v2 over the legacy `Service.MigTD`
interface. Policy v1 uses quote-based RA-TLS mutual authentication. Build a
Policy v1 image with the default virtio-vsock transport:

```sh
cargo image --no-tdinfo \
  --policy config/policy_pre_production_fmspc.json \
  --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer
```

For Policy v1 with virtio-serial:

```sh
cargo image --no-tdinfo \
  --no-default-features \
  --features stack-guard,virtio-serial \
  --policy config/policy_pre_production_fmspc.json \
  --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer
```

Policy v2 with the default virtio-vsock transport:

```sh
cargo image --no-tdinfo \
  --policy-v2 \
  --policy config/templates/policy_v2_signed.json \
  --policy-issuer-chain config/templates/policy_issuer_chain.pem
```

For Policy v2 with virtio-serial:

```sh
cargo image --no-tdinfo \
  --no-default-features \
  --features stack-guard,virtio-serial \
  --policy-v2 \
  --policy config/templates/policy_v2_signed.json \
  --policy-issuer-chain config/templates/policy_issuer_chain.pem
```

The VMM must orchestrate the rebinding request. For each old/new MigTD, its
`Service.MigTD.WaitForRequest` response must set operation `2` and include the
migration-information HOB. A virtio-vsock build also requires the stream-socket
HOB. MigTD reports completion with operation `2` in
`Service.MigTD.ReportStatus`.

The old MigTD uses `migration_source = 1`; the new MigTD uses
`migration_source = 0`. Both requests identify the same target TD UUID and the
binding handle appropriate to that MigTD. The existing `mig-td.sh` script can
provide the virtio device, but the QEMU build or external controller must
implement the rebinding request and TDX-module binding sequence.

Virtio rebinding uses RA-TLS. SPDM rebinding continues to require Policy v2
with `vmcall-raw`.

### Build Migration TD Test binaries - Serial
```
bash sh_script/build_final.sh --no-tdinfo -t test -c -a on -d serial
```
### Run Test
```
pushd sh_script/test
sudo pytest -k "not cycle" --device_type serial
popd
```
