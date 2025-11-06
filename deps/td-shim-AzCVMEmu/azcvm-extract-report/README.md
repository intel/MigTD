# AzCVMEmu MigTD Report Extractor Tool

This tool extracts TD report information from vTPM in Azure CVM environments and outputs the data needed for ServTD collateral (TCB mapping and identity).

## Purpose

In AzCVMEmu mode, MigTD runs in Azure TDX CVMs where we get a TDX Report for **Azure CVM Underhill** (the virtual firmware layer), NOT for MigTD itself. Underhill does not use RTMRs, so all RTMR values in the Underhill report are zeros.

For MigTD policy generation, this tool:
1. Gets the Underhill TD report from vTPM using the `az-tdx-vtpm` library
2. Extracts MRTD and other base measurements from Underhill
3. Uses **hardcoded RTMR values** that represent MigTD's expected state after initialization
4. Outputs them in a JSON format suitable for policy generation

## Important: RTMR Values

**RTMRs are hardcoded to zeros** to match what's in Azure Underhill reports:
- **RTMR0**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **RTMR1**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **RTMR2**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **RTMR3**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`

## Building

From the tool directory:
```bash
cd deps/td-shim-AzCVMEmu/azcvm-extract-report
cargo build --release
```

## Usage

### Basic usage:
```bash
./target/release/azcvm-extract-report --output-json report_data.json
```

### With verbose logging:
```bash
./target/release/azcvm-extract-report --output-json report_data.json --verbose
```

### With custom report data:
```bash
# Provide 48 bytes of hex-encoded report data
./target/release/azcvm-extract-report --output-json report_data.json --report-data "0102030405..."
```

## Output Format

The tool generates a JSON file with the following structure (using camelCase field names):

```json
{
  "mrtd": "...",           // 48 bytes hex
  "rtmr0": "...",          // 48 bytes hex
  "rtmr1": "...",          // 48 bytes hex
  "rtmr2": "...",          // 48 bytes hex
  "rtmr3": "...",          // 48 bytes hex
  "xfam": "...",           // 8 bytes hex
  "attributes": "...",     // 8 bytes hex
  "mrConfigId": "...",     // 48 bytes hex
  "mrOwner": "...",        // 48 bytes hex
  "mrOwnerConfig": "...",  // 48 bytes hex
  "servtdHash": "...",     // 48 bytes hex
  "isvProdId": 0,          // u16
  "isvsvn": 1              // u16
}
```

## Integration with Policy Generation

The extracted report data is used by `build_custom_policy_from_report.sh` to:
1. Update the ServTD collateral template with real measurements
2. Generate a signed policy that includes correct MRTD values
3. Enable SVN lookup from TCB_Mapping using MRTD in AzCVMEmu mode

See `src/policy/sh_scripts/build_custom_policy_from_report.sh` for the complete workflow.

## Requirements

- Must be run in an Azure TDX CVM with vTPM access (sudo required)
- Requires `az-tdx-vtpm` crate dependencies
- Linux environment with standard tools (jq, etc.)

## Notes

- RTMRs are hardcoded to zeros (matching Azure Underhill reports)
- MRTD is the primary measurement that will be verified
- The tool accesses vTPM via the `az-tdx-vtpm` library using `tdcall_report_emulated`
