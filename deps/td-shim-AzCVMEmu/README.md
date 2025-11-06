# TDX TDCALL and TDSHIM Emulation for MigTD Development

This crate provides a drop-in replacement for the original `tdx-tdcall` crate that emulates TDX operations for MigTD development and testing in Azure TDX CVM environments or any Linux machine/VM.

## Architecture

The emulation library:
- **Re-exports all standard tdx-tdcall functions** unchanged for compatibility
- **Emulates MigTD-specific vmcalls** via TCP transport for inter-MigTD communication
- **Emulates GetQuote operations** using Azure TDX CVM virtual firmware QUOTE or a pre-captured QUOTE
- **Emulates collateral retrieval** with hardcoded DCAP collateral data
- **Maintains the exact same API** as the original tdx-tdcall
- **Uses feature flags** to enable/disable emulation

### Communication Architecture

**MigTD Inter-Communication (TCP):**
- Source and destination MigTD instances communicate via TCP sockets
- Used for `tdvmcall_migtd_send()` and `tdvmcall_migtd_receive()` operations
- Destination listens on configured port (default: 8001)
- Source connects to destination IP:port

### MigTD Quote Emulation

The emulation uses Azure TDX CVM virtual firmware REPORT/QUOTE acquired at run time or pre-captured
REPORT/QUOTE to exercise MigTD's attestation related code flow. The implementation returns the emulated
QUOTE in tdvmcall_get_quote(). Emulating MigTD REPORT/QUOTE with Azure TDX CVM virtual firmware REPORT/QUOTE
at run time requires the AzCVMEmu mode MigTD to run within an Azure TDX CVM, while emulating with pre-captured
REPORT/QUOTE can run in any Linux machine or VM. Using Azure TDX CVM virtual firmware REPORT/QUOTE acquired at
run time, the emulation mode can exercise MigTD policy engine code logic related to platform TCB level
evaluation. Running the emulated source/destination MigTD on two Azure TDX CVMs with different platform TCB
level, MigTD policy with rules about source/destination platform TCB level tcbdate can be exercised.

Azure TDX CVM does not support extending TDX RTMRs. As a result, the emulated REPORT/QUOTE's RTMRs won't
match MigTD eventlog. Another limitation is related to how REPORT.REPORTDATA field is constructed. In Azure 
TDX CVM, the interface to retrieve virtual firmware's REPORT supports caller provided data to be reflected in
REPORT.REPORTDATA field, but the implementation automatically appends virtual firmware controlled metadata to 
the caller provided data, before hashing the combined data and sets REPORT.REPORTDATA as the hashing result. 
This implementation does not match MigTD expectation of REPORT.REPORTDATA as RATLS/SPDM leaf certificate public 
key hash. Due to the limitations, in AzCVMEmu MigTD mode, RTMR value check against eventlog and REPORTDATA check
against RATLS/SPDM leaf certificate public key need to be bypassed.

### Emulated Functions

#### MigTD Communication (TCP-based)

- `tdvmcall_migtd_send()` - Sends data to remote MigTD via TCP
- `tdvmcall_migtd_receive()` - Receives data from remote MigTD via TCP
- `tdvmcall_migtd_waitforrequest()` - Waits for migration requests
- `tdvmcall_migtd_reportstatus()` - Reports migration status

#### Attestation

- `tdvmcall_get_report()` - Generate Azure TDX CVM virtual firmware REPORT or return a pre-captured REPORT
  - Uses Azure TDX CVM virtual firmware's TDREPORT interface at runtime, accepts caller-provided data (64 bytes)
    to include in the REPORT
  - With `test_mock_report` feature: Returns pre-captured mock TDREPORT for testing on any Linux machine
  - Note: Azure CVM implementation appends metadata to REPORTDATA before hashing, so REPORTDATA validation must be bypassed in AzCVMEmu mode

- `tdvmcall_get_quote()` - Generates Azure TDX CVM virtual firmware QUOTE or returns a pre-captured QUOTE
  - **Scenario 1**: Legacy TDREPORT (1024 bytes) → QUOTE
  - **Scenario 2**: QGS collateral request → Hardcoded collateral
  - **Scenario 3**: QGS quote request with TDREPORT → QUOTE with QGS wrapper
  - With `test_mock_report` feature: Returns pre-captured QUOTE for testing on any Linux machine

#### ServTD Operations

- `tdcall_servtd_rd()` - Reads emulated MSK/TDCS fields
- `tdcall_servtd_wr()` - Writes emulated MSK/TDCS fields

#### System Operations

- `tdcall_sys_rd()` - Reads emulated global SYS fields
- `tdcall_sys_wr()` - Writes emulated global SYS fields

#### RTMR (Runtime Measurement Register) Emulation

- `tdcall_extend_rtmr()` - Emulated as no-op operation
  - Azure TDX CVM does not support extending TDX RTMRs
  - Extension calls return success but don't modify RTMR values
  - RTMR values in REPORT/QUOTE reflect Azure virtual firmware state, not MigTD measurements
  - MigTD eventlog integrity check against RTMR must be bypassed in AzCVMEmu mode

#### Configuration and Firmware Volume (CFV) Emulation

The td-shim-interface provides file-based CFV emulation for policy and certificates:

- **File Reader API**: Configurable file reading interface
- **Policy Loading**: `load_policy_from_file()` - Loads migration policy from filesystem
- **Root CA Loading**: `load_root_ca_from_file()` - Loads root certificate from filesystem
- **Policy Issuer Chain**: `load_policy_issuer_chain_from_file()` - Loads policy v2 issuer chain
- **Environment Variables**: 
  - `MIGTD_POLICY_FILE` - Path to policy file
  - `MIGTD_ROOT_CA_FILE` - Path to root CA certificate
  - `MIGTD_POLICY_ISSUER_CHAIN_FILE` - Path to policy issuer chain (policy v2)

The CFV emulation replaces the firmware volume parsing with direct file system access, allowing emulation mode MigTD to load configuration from standard files instead of extracting them from the TD payload image.

#### Interrupt and Hardware Emulation

The td-payload-emu provides emulation for hardware interfaces:

**Interrupt Emulation (interrupt-emu)**:
- `register()` - Register interrupt callbacks by vector
- `trigger()` - Software-triggered interrupt dispatch
- Replaces real IDT (Interrupt Descriptor Table) with callback registry

**APIC Emulation**:
- `disable()` - No-op stub for interrupt disabling
- `enable_and_hlt()` - CPU yield instead of HLT instruction
- `one_shot_tsc_deadline_mode()` - No-op timer stub
- No real APIC hardware access in emulation mode

**Memory Emulation**:
- `SharedMemory` - Heap-allocated buffers replacing shared/private memory conversion
- No real GPA (Guest Physical Address) conversion needed
- Simplifies memory management for standard runtime

**ACPI/HOB Emulation**:
- Minimal ACPI table structures (CCEL, GenericSdtHeader)
- HOB (Hand-off Block) stubs for API compatibility
- Event log emulation with file-based storage
- No firmware parsing required

All other tdx-tdcall functions pass through to the original implementation.

## Architecture Diagram

```
MigTD Application
       ↓
tdx-tdcall (this emulation crate)
       ↓
┌──────┴──────┬───────────────┬───────────────┐
│ Migration   │  GetReport/   │  CFV          │
│ (TCP)       │  GetQuote     │  (File System)│
│             │  (Azure CVM   │               │
│             │  or mock)     │               │
↓             ↓               ↓               
Remote        Azure CVM       Config Files:
MigTD         firmware or     - policy.json
              pre-captured    - root_ca.cer
              REPORT/QUOTE    - policy_issuer_chain.pem
```

This design allows MigTD to run in Azure TDX CVM environment with:
- Inter-MigTD communication via TCP
- Emulated Quote with Azure TDX CVM virtual firmware QUOTE or pre-captured QUOTE
- Configuration loading from local file system (CFV emulation)
- No or minor modifications to core MigTD code


## Benefits

1. **Broadly available environment for core MigTD code development and testing** - Works in 
   Azure TDX CVM or any Linux machine/VM
2. **Drop-in replacement** - Same API as original tdx-tdcall
3. **Feature-gated** - Switch between real TDX baremetal environment and emulated at build time

## Usage

### Building with AzCVMEmu

To build MigTD with AzCVMEmu emulation for Azure TDX CVM:

```bash
# Build with AzCVMEmu feature (automatically uses correct dependencies)
cargo build --no-default-features --features AzCVMEmu

# Or use the build script
./migtdemu.sh --build
```

The `AzCVMEmu` feature automatically:
- Switches to td-shim-AzCVMEmu dependencies
- Enables TCP transport for MigTD communication
- Emulates MigTD Quote with Azure TDX CVM virtual FW Quote or a pre-captured Quote to
  exercise the attestation flow
- Disables real TDX hardware dependencies

### Running in Azure TDX CVM

See the main `doc/AzCVMEmu.md` for detailed instructions on:
- Setting up Azure TDX CVM environment
- Configuring network connectivity between source and destination
- Running migration tests

### Testing with migtdemu.sh

Use the provided emulation test script:

```bash
# Test both source and destination MigTD
./migtdemu.sh --both

# Test source only
./migtdemu.sh --src

# Test destination only
./migtdemu.sh --dst
```
