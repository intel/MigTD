### Build for Azure CVM Emulation (AzCVMEmu)

For development and testing MigTD core logic e2e flows, including RATLS with TDX Quote generation/verification and policy enforcement, you can build MigTD with emulation support as a standard Rust application. The Rust application can run within an Azure TDX CVM. Emulation implementation of the TDShim and tdcall interfaces are located under `deps/td-shim-AzCVMEmu`. MigTD Quote is emulated as TDX Quote of the Azure TDX CVM virtual FW layer. Code changes under `src` directory are kept to a minimum, mostly consisting of feature gates to select emulation layer or the real tds-shim layer, with several exceptions:

- Added `src/migtd/src/bin/migtd/cvmemu.rs` to handle emulation layer initialization and command-line processing.
- As the RTMR extension is emulated as a no-op, the eventlog integrity check against RTMR is bypassed.
- As the TDX Quote of Azure TDX CVM virtual FW constructs the REPORTDATA field of the Quote differently, the RATLS certificate public-key check against REPORTDATA is bypassed.
- The crypto crate's `TlsTimerProvider` code is changed to return a fixed `current_time` timestamp to avoid invoking RTC access (a privileged instruction), which is not supported when building MigTD as a standard Rust application.
- Added a script to patch libservtd-attest lib to link with the std runtime in AZCVMEmu build

**Note:** The `AzCVMEmu` feature only works with the `vmcall-raw` transport feature. When building with `AzCVMEmu`, the `main` and `vmcall-raw` features are enabled by default. You do not need to include them explicitly in the `--features` list.

**Emulation architecture details:** See `deps/td-shim-AzCVMEmu/README.md` for detailed documentation on the emulation layer implementation.

#### Build Options

#### Build Options

**Default build** (requires Azure TDX CVM + TPM2‑TSS):
```bash
cargo build --no-default-features --features AzCVMEmu
```
This mode uses real Azure IMDS attestation and allows testing policy rules for platform TCB level. Running on two Azure TDX CVMs with different TCB levels enables verification of policy enforcement based on TCB version requirements.

**Mock report build** (testing with mock data but full attestation flow - on any Linux machine):
```bash
cargo build --no-default-features --features AzCVMEmu,test_mock_report
```

**With IGVM attestation** (uses servtd_get_quote for quote generation):
```bash
cargo build --no-default-features --features AzCVMEmu,igvm-attest
```

**With IGVM attestation and mock report**:
```bash
cargo build --no-default-features --features AzCVMEmu,igvm-attest,test_mock_report
```

**Skip RA build** (development/testing - no TDX/Azure CVM required, bypasses attestation - on any Linux machine):
```bash
cargo build --no-default-features --features AzCVMEmu,test_disable_ra_and_accept_all
```

#### Running MigTD in AzCVMEmu Mode in Azure TDX CVM


Prerequisites:
- [Azure v6 TDX CVM](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcesv6-series?tabs=sizebasic), running Ubuntu 24.04 or 22.04 (for production builds)
- For testing with `test_disable_ra_and_accept_all` feature: any Linux system with Rust toolchain (no TDX/Azure CVM required)
- TPM2‑TSS runtime is typically required at runtime because AzCVMEmu uses `az-tdx-vtpm`, which initializes TPM via `tss-esapi` by default.
	- Ubuntu 24.04 minimal runtime packages:
		- `libtss2-esys` (e.g., `libtss2-esys-3.0.2-0t64`)
		- `libtss2-tcti-device0` (for `/dev/tpmrm0` access)
	- Optional: `tpm2-tools` (debug/inspection), other TCTIs like `libtss2-tcti-mssim0`.
	- Build-time: if build errors mention missing TSS2 headers, install `libtss2-dev`.
	- The runner script auto-sets `TSS2_TCTI=device:/dev/tpmrm0` when the device exists and may enable sudo if permissions are insufficient.
	- **Note**: When using `test_disable_ra_and_accept_all` feature, TPM2‑TSS is **not required** as mock TD reports and quotes are used instead of real TPM operations.

Ubuntu 24.04 quick install (example):

```bash
sudo apt-get update
sudo apt-get install -y libtss2-esys libtss2-tcti-device0 tpm2-tools
```


**Using the migtdemu.sh script (recommended):**

The easiest way to run MigTD in AzCVMEmu mode is using the provided `migtdemu.sh` script, which automatically builds and runs MigTD with proper environment setup:

```bash
# Display help
./migtdemu.sh --help

# Default mode (requires Azure TDX CVM + TPM)
./migtdemu.sh --role source
./migtdemu.sh --role destination

# Mock report mode (full attestation with mock data - on any Linux machine)
./migtdemu.sh --mock-report --role source
./migtdemu.sh --mock-report --both

# IGVM attestation mode (uses servtd_get_quote)
./migtdemu.sh --igvm-attest --role source
./migtdemu.sh --igvm-attest --mock-report --both

# Skip RA mode (no attestation - on any Linux machine)
./migtdemu.sh --skip-ra --role source
./migtdemu.sh --skip-ra --both

# Debug build with custom configuration
./migtdemu.sh --debug --role source --request-id 42 --dest-ip 192.168.1.100 --dest-port 8002
```

Script capabilities at a glance:
- Builds MigTD with `--no-default-features --features AzCVMEmu` in the selected mode (debug/release).
- With `--mock-report` flag: Builds with `--features "AzCVMEmu,test_mock_report"` for mock TD reports/quotes with full attestation flow (works on any Linux machine).
- With `--igvm-attest` flag: Builds with `--features "AzCVMEmu,igvm-attest"` to use servtd_get_quote for quote generation (compatible with mock-report).
- With `--skip-ra` flag: Builds with `--features "AzCVMEmu,test_disable_ra_and_accept_all"` to bypass attestation entirely (works on any Linux machine).
- Validates and sets required env vars: `MIGTD_POLICY_FILE` and `MIGTD_ROOT_CA_FILE`.
- Auto-sets `RUST_BACKTRACE` (1) and `RUST_LOG` (debug in debug builds, info in release) unless already set.
- If `/dev/tpmrm0` (or TPM2-ABRMD socket) is present and permissions are insufficient, it automatically enables sudo even if `--no-sudo` is passed (not needed with `--mock-report` or `--skip-ra`).
- Exports `TSS2_TCTI=device:/dev/tpmrm0` when the device exists, to help TPM2-TSS.
- Single-role mode: runs just source or destination.
- `--both`: starts destination in the background, waits for it to listen, then runs source in the foreground; destination logs go to `dest.out.log` and are tailed on failure.

Supported options:
- `-r, --role ROLE`                source | destination (default: source)
- `-i, --request-id ID`            migration request ID (default: 1)
- `-d, --dest-ip IP`               destination IP (default: 127.0.0.1)
- `-p, --dest-port PORT`           destination port (default: 8001)
- `--policy-file FILE`             policy file path (default: config/policy.json)
- `--root-ca-file FILE`            root CA file path (default: config/Intel_SGX_Provisioning_Certification_RootCA.cer)
- `--policy-issuer-chain-file FILE` policy issuer chain file path (required with --policy-v2)
- `--policy-v2`                    enable policy v2 support
- `--features FEATURES`            add extra cargo features (comma-separated, e.g., 'spdm_attestation')
- `--igvm-attest`                  enable IGVM attestation feature (uses servtd_get_quote)
- `--debug | --release`            build mode (default: release)
- `--mock-report`                  use mock TD reports/quotes with full attestation flow (on any Linux machine)
- `--skip-ra`                      skip remote attestation entirely (on any Linux machine)
- `--both`                         orchestrate destination then source on localhost
- `--no-sudo`                      do not use sudo unless forced by TPM permissions
- `-h, --help`                     show script help

What the script prints/shows:
- Effective configuration (role, request-id, files, dest ip:port, sudo usage).
- The exact command it will run (including env vars); useful for reproducing manual runs.
- In `--both` mode, it prints destination PID and log path `dest.out.log`.

**Example usage with migtdemu.sh:**
```bash
# Default mode (requires Azure TDX CVM + TPM)
./migtdemu.sh --role destination --request-id 42
./migtdemu.sh --role source --request-id 42 --dest-ip 127.0.0.1 --dest-port 8001
./migtdemu.sh --both --request-id 77

# Mock report mode (full attestation with mock data - on any Linux machine)
./migtdemu.sh --mock-report --role destination --request-id 42
./migtdemu.sh --mock-report --role source --request-id 42
./migtdemu.sh --mock-report --both --request-id 42

# Skip RA mode (no attestation - on any Linux machine)
./migtdemu.sh --skip-ra --role destination --request-id 42
./migtdemu.sh --skip-ra --role source --request-id 42
./migtdemu.sh --skip-ra --both --request-id 42

# Debug build examples
./migtdemu.sh --debug --role destination --request-id 123
./migtdemu.sh --debug --mock-report --both

# Policy v2 example
./migtdemu.sh --policy-v2 --policy-file ./config/AzCVMEmu/policy_v2_signed.json --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem --both

# With additional features (e.g., SPDM attestation)
./migtdemu.sh --features spdm_attestation --both
```

**Manual execution:**

If you prefer to run MigTD manually, you must first set the required environment variables:

```bash
export MIGTD_POLICY_FILE="/path/to/your/policy.json"
export MIGTD_ROOT_CA_FILE="/path/to/your/root_ca.cer"
```

Both files must exist at the specified paths. The program will exit with an error if either environment variable is missing or if the files cannot be found. vTPM access may require sudo: if TPM devices (e.g., /dev/tpmrm0) are present and permissions are insufficient, run with sudo or set `TSS2_TCTI` accordingly. The `migtdemu.sh` script auto-enables sudo when needed.

Run the application:

```bash
# Display help information
./target/release/migtd -h
```

Direct run examples (no script):
- Destination (release, with sudo expected when TPM present):
	sudo env MIGTD_POLICY_FILE=/path/to/policy.json MIGTD_ROOT_CA_FILE=/path/to/root_ca.cer RUST_LOG=info ./target/release/migtd --role destination --request-id 42
- Source (debug):
	MIGTD_POLICY_FILE=/path/to/policy.json MIGTD_ROOT_CA_FILE=/path/to/root_ca.cer RUST_LOG=debug ./target/debug/migtd --role source --request-id 42 --dest-ip 127.0.0.1 --dest-port 8001

**Built-in command-line options (from `./migtd -h`):**
- `--request-id, -r ID`: Set migration request ID (default: 1)
- `--role, -m ROLE`: Set role as 'source' or 'destination' (default: source)
- `--uuid, -u U1 U2 U3 U4`: Set target TD UUID as four integers (default: 1 2 3 4)
- `--binding, -b HANDLE`: Set binding handle as hex or decimal (default: 0x1234)
- `--dest-ip, -d IP`: Set destination IP address for connection (default: 127.0.0.1)
- `--dest-port, -t PORT`: Set destination port for connection (default: 8001)
- `--help, -h`: Show help message
