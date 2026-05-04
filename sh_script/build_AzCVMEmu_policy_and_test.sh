#!/bin/bash

# ==============================================================================
# MigTD AzCVMEmu Report-Based Policy Generation and Testing
# ==============================================================================
#
# End-to-end automation for generating custom MigTD v2 policies from live
# Azure vTPM measurements OR mock data for testing. This script supports both
# real Azure CVM environments and testing/development scenarios.
#
# Features:
#   - Extracts TD measurements from Azure vTPM (MRTD, RTMRs, XFAM, Attributes)
#   - OR generates mock measurements for testing with test_mock_report feature
#   - Updates policy templates with extracted measurements
#   - Generates certificate chain for signing
#   - Signs all components (td_identity, tcb_mapping, final policy)
#   - Creates test-ready signed policy
#   - Optionally tests the generated policy with migtdemu.sh
#   - Supports mock report mode for testing
#
# Prerequisites:
#   - For real mode: Azure TDX CVM with vTPM access, sudo privileges
#   - For mock mode: No special requirements
#   - TPM 2.0 tools installed (for real mode)
#   - jq (JSON processor) installed
#
# Usage:
#   # Real mode: extract measurements from vTPM and generate signed policy
#   ./sh_script/build_AzCVMEmu_policy_and_test.sh
#
#   # Mock mode: generate policy from predictable test data (uses test_mock_report)
#   ./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report
#
#   # Fetch fresh collaterals from Azure THIM before generating policy
#   ./sh_script/build_AzCVMEmu_policy_and_test.sh --fetch-collaterals --azure-region useast
#
#   # Skip the integration test at the end
#   ./sh_script/build_AzCVMEmu_policy_and_test.sh --skip-test
#
#   # Custom output directory
#   ./sh_script/build_AzCVMEmu_policy_and_test.sh --output-dir /path/to/output
#
#   # Show help
#   ./sh_script/build_AzCVMEmu_policy_and_test.sh --help
#
# What it does:
#   1. Optionally fetches fresh collaterals from Azure THIM (if --fetch-collaterals)
#   2. Builds required tools (azcvm-extract-report from deps/td-shim-AzCVMEmu,
#      json-signer, servtd-collateral-generator, migtd-policy-generator)
#   3. Extracts report data from Azure vTPM OR generates mock data
#   4. Updates td_identity.json template with extracted measurements
#   5. Updates tcb_mapping.json template with extracted measurements
#   6. Generates certificate chains (root CA + policy/tcb_mapping/td_identity leaves)
#   7. Signs td_identity.json with the td_identity leaf key (testing only)
#   8. Signs tcb_mapping.json with the tcb_mapping leaf key (testing only)
#   9. Generates servtd_collateral.json from signed components
#   10. Merges policy data with collaterals
#   11. Signs final policy with policy signing key
#   12. Copies certificate chain to output directory
#   13. Securely deletes private key with shred
#   14. Optionally tests with ./migtdemu.sh (with --mock-report for mock data)
#
# Outputs:
#   - config/AzCVMEmu/policy_v2_signed.json (196 KB) - Signed policy with your measurements
#   - config/AzCVMEmu/policy_issuer_chain.pem (1.5 KB) - Certificate chain for verification
#
# Expected result from testing: ✅ "Migration key exchange successful!"
#
# ==============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== MigTD Custom Policy Builder ===${NC}"
echo

print_error() {
    printf '%b\n' "${RED}Error: $1${NC}" >&2
}

print_hint_header() {
    printf '%b\n' "${YELLOW}$1${NC}" >&2
}

print_hint_lines() {
    local hint
    for hint in "$@"; do
        printf '  %s\n' "$hint" >&2
    done
}

require_cmd() {
    local cmd="$1"
    local error_message="$2"
    local hint_header="$3"
    shift 3

    if ! command -v "$cmd" >/dev/null 2>&1; then
        print_error "$error_message"
        print_hint_header "$hint_header"
        print_hint_lines "$@"
        exit 127
    fi
}

require_pkg_config_module() {
    local module="$1"
    local error_message="$2"
    local hint_header="$3"
    shift 3

    if ! pkg-config --exists "$module" >/dev/null 2>&1; then
        print_error "$error_message"
        print_hint_header "$hint_header"
        print_hint_lines "$@"
        exit 127
    fi
}

# Default paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_MATERIAL_DIR="$PROJECT_ROOT/config/AzCVMEmu"
OUTPUT_DIR="$PROJECT_ROOT/config/AzCVMEmu"
TEMP_DIR=$(mktemp -d)
TOOLS_DIR="$PROJECT_ROOT/target/release"
AZCVM_EXTRACT_REPORT_LOCAL_BIN="$PROJECT_ROOT/deps/td-shim-AzCVMEmu/azcvm-extract-report/target/release/azcvm-extract-report"
AZCVM_EXTRACT_REPORT_WORKSPACE_BIN="$TOOLS_DIR/azcvm-extract-report"
AZCVM_EXTRACT_REPORT_BIN=""

# Ensure cargo is available (try loading rustup env first).
if ! command -v cargo >/dev/null 2>&1; then
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck source=/dev/null
        . "$HOME/.cargo/env"
    fi
fi

require_cmd \
    cargo \
    "cargo not found in PATH." \
    "Install Rust toolchain and reload your shell (platform-specific):" \
    "Cross-platform (recommended): https://rustup.rs" \
    "Debian/Ubuntu: sudo apt install -y rustup" \
    "rustup default stable" \
    "source \"\$HOME/.cargo/env\"" \
    "./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report"

require_cmd \
    pkg-config \
    "pkg-config not found in PATH." \
    "Install required build dependencies (platform-specific):" \
    "Debian/Ubuntu: sudo apt install -y pkg-config libtss2-dev"

require_pkg_config_module \
    tss2-sys \
    "TPM2 system library 'tss2-sys' not found." \
    "Install required TPM2 development package (platform-specific):" \
    "Debian/Ubuntu: sudo apt install -y libtss2-dev"

require_cmd \
    nasm \
    "nasm not found in PATH." \
    "Install required assembler dependency (platform-specific):" \
    "Debian/Ubuntu: sudo apt install -y nasm"

require_cmd \
    unzip \
    "unzip not found in PATH." \
    "Install required archive extraction tool (platform-specific):" \
    "Debian/Ubuntu: sudo apt install -y unzip"

require_cmd \
    autoreconf \
    "autoreconf not found in PATH." \
    "Install required autotools dependencies (platform-specific):" \
    "Debian/Ubuntu: sudo apt install -y autoconf automake libtool"

require_cmd \
    ocamlbuild \
    "ocamlbuild not found in PATH." \
    "Install required OCaml build tools (platform-specific):" \
    "Debian/Ubuntu: sudo apt install -y ocaml ocamlbuild"

# Input Files
POLICY_DATA_RAW="$SOURCE_MATERIAL_DIR/policy_v2_raw.json"
TD_IDENTITY_TEMPLATE="$SOURCE_MATERIAL_DIR/td_identity.json"
TCB_MAPPING_TEMPLATE="$SOURCE_MATERIAL_DIR/tcb_mapping.json"
COLLATERALS_FILE="$SOURCE_MATERIAL_DIR/collateral_azure_thim.json"

# Intermediate files
REPORT_DATA_FILE="$TEMP_DIR/report_data.json"
TD_IDENTITY_UPDATED="$TEMP_DIR/td_identity_updated.json"
TCB_MAPPING_UPDATED="$TEMP_DIR/tcb_mapping_updated.json"
TD_IDENTITY_SIGNED="$TEMP_DIR/td_identity_signed.json"
TCB_MAPPING_SIGNED="$TEMP_DIR/tcb_mapping_signed.json"
SERVTD_COLLATERAL="$TEMP_DIR/servtd_collateral.json"
POLICY_DATA_MERGED="$TEMP_DIR/policy_data_merged.json"

# Output files
OUTPUT_POLICY="$OUTPUT_DIR/policy_v2_signed.json"
OUTPUT_POLICY_A="$OUTPUT_DIR/policy_v2_signed_a.json"
OUTPUT_POLICY_B="$OUTPUT_DIR/policy_v2_signed_b.json"
# Variant B with policy + tcb_mapping leaf certs both rotated
OUTPUT_POLICY_PM_B="$OUTPUT_DIR/policy_v2_signed_pm_b.json"
# Variant B with policy + tcb_mapping + td_identity leaf certs all rotated
OUTPUT_POLICY_PMI_B="$OUTPUT_DIR/policy_v2_signed_pmi_b.json"
OUTPUT_CERT_CHAIN="$OUTPUT_DIR/policy_issuer_chain.pem"
OUTPUT_CERT_CHAIN_A="$OUTPUT_DIR/policy_issuer_chain_a.pem"
OUTPUT_CERT_CHAIN_B="$OUTPUT_DIR/policy_issuer_chain_b.pem"
CERT_DIR="$TEMP_DIR/certs"
PRIVATE_KEY="$CERT_DIR/policy_signing_pkcs8.key"
PRIVATE_KEY_A="$CERT_DIR/policy_signing_a_pkcs8.key"
PRIVATE_KEY_B="$CERT_DIR/policy_signing_b_pkcs8.key"
# Independent leaf signing keys for tcb_mapping and td_identity (both variants
# under the same root CA). Used to exercise rotation of the inner cert chains
# embedded in servtd_collateral.
MAPPING_PRIVATE_KEY_A="$CERT_DIR/mapping_signing_a_pkcs8.key"
MAPPING_PRIVATE_KEY_B="$CERT_DIR/mapping_signing_b_pkcs8.key"
IDENTITY_PRIVATE_KEY_A="$CERT_DIR/identity_signing_a_pkcs8.key"
IDENTITY_PRIVATE_KEY_B="$CERT_DIR/identity_signing_b_pkcs8.key"

# Cleanup on exit
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        echo -e "${YELLOW}Cleaning up temporary files...${NC}"
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# ============================================================================
# CERTIFICATE GENERATION FUNCTIONS
# ============================================================================

# Function to get curve name from key type
get_curve_name() {
    # Only P384 is supported at this point
    echo "secp384r1"
}

# Function to get hash algorithm based on key type
get_hash_algorithm() {
    echo "sha384"
}

# Function to generate certificates
# Arguments:
#   $1 - output_dir: Directory where certificates will be generated
#   $2 - key_type: Key type (only P384 is currently supported)
#   $3 - cert_validity_days: Certificate validity in days (uses default 365 if not provided)
#   $4 - root_ca_subject: Root CA subject string (uses default "/CN=MigTD Root CA/O=Intel Corporation" if not provided)
#   $5 - leaf_subject: Leaf certificate subject string (uses default "/CN=MigTD Policy Issuer/O=Intel Corporation" if not provided)
generate_certificates() {
    local output_dir="$1"
    local key_type="$2"
    local cert_validity_days="${3:-365}"
    local root_ca_subject="${4:-/CN=MigTD Root CA/O=Intel Corporation}"
    local leaf_subject="${5:-/CN=MigTD Policy Issuer/O=Intel Corporation}"

    # Validate key type first
    if [ "$key_type" != "P384" ]; then
        echo "Error: Only P-384 keys are currently supported." >&2
        echo "P-256 and P-521 support is not yet implemented in the signing/verification code." >&2
        exit 1
    fi

    local curve_name=$(get_curve_name "$key_type")
    local hash_algo=$(get_hash_algorithm "$key_type")

    # Create output directory
    mkdir -p "$output_dir"

    echo "1. Generating root CA private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve_name -out "$output_dir/root_ca.key"

    echo "2. Generating root CA certificate..."
    openssl req -new -x509 \
        -key "$output_dir/root_ca.key" \
        -days $cert_validity_days \
        -out "$output_dir/root_ca.pem" \
        -subj "$root_ca_subject" \
        -$hash_algo

    # Generate two leaf certs (a and b) from the same root CA with the same CN
    # This exercises the peer cert chain validation / key rotation path.
    # Three leaf families are generated, all under the same root CA:
    #   - policy_signing_{a,b}    : signs the outer policy
    #   - mapping_signing_{a,b}   : signs tcb_mapping (embedded in servtd_collateral)
    #   - identity_signing_{a,b}  : signs td_identity  (embedded in servtd_collateral)
    # Variant "a" uses the same logical leaf for all three; variant "b" rotates
    # one or more of them depending on the test mode.
    for family_subject in \
        "policy_signing:/CN=MigTD Policy Issuer/O=Intel Corporation" \
        "mapping_signing:/CN=MigTD TCB Mapping Issuer/O=Intel Corporation" \
        "identity_signing:/CN=MigTD TD Identity Issuer/O=Intel Corporation"; do
        local family="${family_subject%%:*}"
        local subject="${family_subject#*:}"
        # Default to the script's leaf_subject for the policy family to preserve
        # backward-compatible certificate subjects.
        if [ "$family" = "policy_signing" ]; then
            subject="$leaf_subject"
        fi
        local family_chain_prefix
        case "$family" in
            policy_signing)   family_chain_prefix="policy_issuer_chain" ;;
            mapping_signing)  family_chain_prefix="mapping_issuer_chain" ;;
            identity_signing) family_chain_prefix="identity_issuer_chain" ;;
        esac

        for suffix in a b; do
            echo "Generating ${family}_${suffix} key + cert..."
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve_name \
                -out "$output_dir/${family}_${suffix}.key"

            openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
                -in "$output_dir/${family}_${suffix}.key" \
                -out "$output_dir/${family}_${suffix}_pkcs8.key"

            openssl req -new \
                -key "$output_dir/${family}_${suffix}.key" \
                -out "$output_dir/${family}_${suffix}.csr" \
                -subj "$subject"

            openssl x509 -req \
                -in "$output_dir/${family}_${suffix}.csr" \
                -CA "$output_dir/root_ca.pem" \
                -CAkey "$output_dir/root_ca.key" \
                -CAcreateserial \
                -out "$output_dir/${family}_${suffix}.pem" \
                -days $cert_validity_days \
                -$hash_algo \
                -extensions v3_ca \
                -extfile <(echo -e "[v3_ca]\nkeyUsage = digitalSignature")

            cat "$output_dir/${family}_${suffix}.pem" "$output_dir/root_ca.pem" \
                > "$output_dir/${family_chain_prefix}_${suffix}.pem"

            rm -f "$output_dir/${family}_${suffix}.csr"
        done
    done

    # Keep backward-compatible aliases (default to "a")
    cp "$output_dir/policy_signing_a_pkcs8.key" "$output_dir/policy_signing_pkcs8.key"
    cp "$output_dir/policy_issuer_chain_a.pem" "$output_dir/policy_issuer_chain.pem"
}

# Parse command line arguments
USE_MOCK_REPORT=false
MOCK_QUOTE_FILE=""
FETCH_COLLATERALS=false
AZURE_REGION="useast"
EXTRA_FEATURES=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            OUTPUT_DIR="$2"
            OUTPUT_POLICY="$OUTPUT_DIR/policy_v2_signed.json"
            OUTPUT_POLICY_A="$OUTPUT_DIR/policy_v2_signed_a.json"
            OUTPUT_POLICY_B="$OUTPUT_DIR/policy_v2_signed_b.json"
            OUTPUT_POLICY_PM_B="$OUTPUT_DIR/policy_v2_signed_pm_b.json"
            OUTPUT_POLICY_PMI_B="$OUTPUT_DIR/policy_v2_signed_pmi_b.json"
            OUTPUT_CERT_CHAIN="$OUTPUT_DIR/policy_issuer_chain.pem"
            OUTPUT_CERT_CHAIN_A="$OUTPUT_DIR/policy_issuer_chain_a.pem"
            OUTPUT_CERT_CHAIN_B="$OUTPUT_DIR/policy_issuer_chain_b.pem"
            shift 2
            ;;
        --skip-test)
            SKIP_TEST=true
            shift
            ;;
        --mock-report)
            USE_MOCK_REPORT=true
            shift
            ;;
        --mock-quote-file)
            MOCK_QUOTE_FILE="$2"
            shift 2
            ;;
        --fetch-collaterals)
            FETCH_COLLATERALS=true
            shift
            ;;
        --azure-region)
            AZURE_REGION="$2"
            shift 2
            ;;
        --extra-features)
            EXTRA_FEATURES="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --output-dir DIR             Output directory for generated files (default: config/AzCVMEmu)"
            echo "  --skip-test                  Skip running the MigTD test at the end"
            echo "  --mock-report                Use mock report data with test_mock_report feature"
            echo "  --mock-quote-file FILE       Path to mock quote file (--mock-report will be turned on)"
            echo "  --fetch-collaterals          Fetch fresh collaterals from Azure THIM before generating policy"
            echo "  --azure-region REGION        Azure region for THIM (useast, westus, northeurope)"
            echo "                               (default: useast, applies with --fetch-collaterals)"
            echo "  --extra-features FEATURES    Extra cargo features to add (e.g., 'igvm-attest')"
            echo "  -h, --help                   Show this help message"
            echo
            echo "Examples:"
            echo "  # Real vTPM mode (normal remote attestation):"
            echo "  $0"
            echo
            echo "  # Mock report mode (uses test_mock_report feature):"
            echo "  $0 --mock-report"
            echo
            echo "  # Mock report mode with custom quote file:"
            echo "  $0 --mock-quote-file ./config/AzCVMEmu/az_migtd_quote.blob"
            echo
            echo "  # With igvm-attest feature:"
            echo "  $0 --mock-report --extra-features igvm-attest"
            echo
            echo "  # Fetch fresh collaterals from Azure THIM and generate policy:"
            echo "  $0 --fetch-collaterals --azure-region useast"
            echo
            echo "  # Generate policy but skip test:"
            echo "  $0 --mock-report --skip-test"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            exit 1
            ;;
    esac
done

# Automatically enable mock-report mode when mock-quote-file is specified
if [[ -n "$MOCK_QUOTE_FILE" && "$USE_MOCK_REPORT" != true ]]; then
    echo -e "${YELLOW}Note: --mock-quote-file specified, automatically enabling --mock-report${NC}"
    USE_MOCK_REPORT=true
fi

echo "Configuration:"
echo "  Project root: $PROJECT_ROOT"
echo "  Source material: $SOURCE_MATERIAL_DIR"
echo "  Output directory: $OUTPUT_DIR"
echo "  Temp directory: $TEMP_DIR"
echo "  Mock report mode: $USE_MOCK_REPORT"
if [[ -n "$MOCK_QUOTE_FILE" ]]; then
    echo "  Mock quote file: $MOCK_QUOTE_FILE"
fi
echo "  Fetch collaterals: $FETCH_COLLATERALS"
if [ "$FETCH_COLLATERALS" = true ]; then
    echo "  Azure region: $AZURE_REGION"
fi
echo

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"
mkdir -p "$CERT_DIR"

# Verify input files exist
for file in "$POLICY_DATA_RAW" "$TD_IDENTITY_TEMPLATE" "$TCB_MAPPING_TEMPLATE"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: Required input file not found: $file${NC}" >&2
        exit 1
    fi
done

#
# Step 0: Fetch fresh collaterals from Azure THIM (optional)
#
if [ "$FETCH_COLLATERALS" = true ]; then
    echo -e "${BLUE}=== Step 0: Fetching Fresh Collaterals from Azure THIM ===${NC}"

    # Use temp directory for fetching, then move to final location
    TEMP_COLLATERALS_FILE="$TEMP_DIR/collateral_azure_thim.json"

    # Build migtd-collateral-generator first
    echo "Building migtd-collateral-generator..."
    cd "$PROJECT_ROOT"
    cargo build --release -p migtd-collateral-generator 2>&1 | grep -E "(Compiling|Finished|error)" || true

    if [ ! -f "$TOOLS_DIR/migtd-collateral-generator" ]; then
        echo -e "${RED}Error: Tool 'migtd-collateral-generator' not found at $TOOLS_DIR/migtd-collateral-generator${NC}" >&2
        exit 1
    fi

    # Fetch collaterals
    echo "Fetching collaterals from Azure THIM ($AZURE_REGION)..."
    if "$TOOLS_DIR/migtd-collateral-generator" --provider azure-thim --azure-region "$AZURE_REGION" -o "$TEMP_COLLATERALS_FILE"; then
        echo -e "${GREEN}✓ Collaterals fetched successfully${NC}"

        # Show summary
        NUM_PLATFORMS=$(jq '.platforms | length' "$TEMP_COLLATERALS_FILE")
        echo "  Platforms in collateral: $NUM_PLATFORMS"
        if [ "$NUM_PLATFORMS" -gt 0 ]; then
            echo "  FMSPCs:"
            jq -r '.platforms[].fmspc' "$TEMP_COLLATERALS_FILE" | sed 's/^/    - /'
        else
            echo -e "${YELLOW}  Warning: No platform TCB info found. Policy will work but without platform-specific TCB verification.${NC}"
            echo -e "${YELLOW}  Note: The tool queries Intel's FMSPC list and tries each against Azure THIM.${NC}"
        fi

        # Move to final location
        mv "$TEMP_COLLATERALS_FILE" "$COLLATERALS_FILE"
        echo -e "${GREEN}✓ Collaterals saved to: $COLLATERALS_FILE${NC}"
    else
        echo -e "${RED}Error: Failed to fetch collaterals from Azure THIM${NC}" >&2
        exit 1
    fi
    echo
else
    # Use default collaterals file
    if [ ! -f "$COLLATERALS_FILE" ]; then
        echo -e "${RED}Error: Required collaterals file not found: $COLLATERALS_FILE${NC}" >&2
        echo -e "${YELLOW}Tip: Use --fetch-collaterals to fetch fresh collaterals from Azure THIM${NC}" >&2
        exit 1
    fi
fi
#
# Step 1: Build all required tools
#
echo -e "${BLUE}=== Step 1: Building Tools ===${NC}"
cd "$PROJECT_ROOT"

echo "Building azcvm-extract-report (from deps/td-shim-AzCVMEmu)..."
if ! (cd deps/td-shim-AzCVMEmu/azcvm-extract-report && cargo build --release); then
    echo -e "${RED}Error: Failed to build azcvm-extract-report${NC}" >&2
    exit 1
fi

echo "Building json-signer..."
if ! cargo build --release -p json-signer; then
    echo -e "${RED}Error: Failed to build json-signer${NC}" >&2
    exit 1
fi

echo "Building servtd-collateral-generator..."
if ! cargo build --release -p servtd-collateral-generator; then
    echo -e "${RED}Error: Failed to build servtd-collateral-generator${NC}" >&2
    exit 1
fi

echo "Building migtd-policy-generator..."
if ! cargo build --release -p migtd-policy-generator; then
    echo -e "${RED}Error: Failed to build migtd-policy-generator${NC}" >&2
    exit 1
fi

# Verify tools exist
# azcvm-extract-report may be emitted either to the local crate target/ or the
# workspace target/ when CARGO_TARGET_DIR is set.
if [ -f "$AZCVM_EXTRACT_REPORT_LOCAL_BIN" ]; then
    AZCVM_EXTRACT_REPORT_BIN="$AZCVM_EXTRACT_REPORT_LOCAL_BIN"
elif [ -f "$AZCVM_EXTRACT_REPORT_WORKSPACE_BIN" ]; then
    AZCVM_EXTRACT_REPORT_BIN="$AZCVM_EXTRACT_REPORT_WORKSPACE_BIN"
else
    echo -e "${RED}Error: Tool 'azcvm-extract-report' not found at either:${NC}" >&2
    echo -e "${RED}  - $AZCVM_EXTRACT_REPORT_LOCAL_BIN${NC}" >&2
    echo -e "${RED}  - $AZCVM_EXTRACT_REPORT_WORKSPACE_BIN${NC}" >&2
    exit 1
fi

for tool in json-signer servtd-collateral-generator migtd-policy-generator; do
    if [ ! -f "$TOOLS_DIR/$tool" ]; then
        echo -e "${RED}Error: Tool '$tool' not found at $TOOLS_DIR/$tool${NC}" >&2
        exit 1
    fi
done

echo -e "${GREEN}✓ All tools built successfully${NC}"
echo

#
# Step 2: Extract report data from vTPM or generate mock data
#
echo -e "${BLUE}=== Step 2: Extracting Report Data ===${NC}"
cd "$TEMP_DIR"

if [ "$USE_MOCK_REPORT" = true ]; then
    echo "Using mock report data for testing..."
    echo -e "${YELLOW}Note: Will use test_mock_report feature for building${NC}"

    # Set MOCK_QUOTE_FILE environment variable if specified
    if [[ -n "$MOCK_QUOTE_FILE" ]]; then
        # Convert to absolute path if it's a relative path
        if [[ "$MOCK_QUOTE_FILE" != /* ]]; then
            MOCK_QUOTE_FILE="$PROJECT_ROOT/$MOCK_QUOTE_FILE"
        fi
        echo "Using custom mock quote file: $MOCK_QUOTE_FILE"
        export MOCK_QUOTE_FILE
    fi

    "$AZCVM_EXTRACT_REPORT_BIN" \
        --mock-report \
        --output-json "migtd_report_data.json"

    if [ ! -f "migtd_report_data.json" ]; then
        echo -e "${RED}Error: Failed to generate mock report data${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}✓ Mock report data generated${NC}"
else
    # Use sudo to access vTPM device (requires /dev/tpmrm0 access)
    echo "Note: Using sudo to access vTPM device..."
    sudo "$AZCVM_EXTRACT_REPORT_BIN"

    # Report extractor creates migtd_report_data.json in current directory
    if [ ! -f "migtd_report_data.json" ]; then
        echo -e "${RED}Error: Failed to extract report data${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}✓ Report data extracted from vTPM${NC}"
fi

mv migtd_report_data.json "$REPORT_DATA_FILE"
echo -e "${GREEN}✓ Report data saved to: $REPORT_DATA_FILE${NC}"

# Parse extracted values (using camelCase field names from JSON)
MRTD=$(jq -r '.mrtd' "$REPORT_DATA_FILE")
RTMR0=$(jq -r '.rtmr0' "$REPORT_DATA_FILE")
RTMR1=$(jq -r '.rtmr1' "$REPORT_DATA_FILE")
RTMR2=$(jq -r '.rtmr2' "$REPORT_DATA_FILE")
RTMR3=$(jq -r '.rtmr3' "$REPORT_DATA_FILE")
XFAM=$(jq -r '.xfam' "$REPORT_DATA_FILE")
ATTRIBUTES=$(jq -r '.attributes' "$REPORT_DATA_FILE")
MR_CONFIG_ID=$(jq -r '.mrConfigId // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"' "$REPORT_DATA_FILE")
MR_OWNER=$(jq -r '.mrOwner // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"' "$REPORT_DATA_FILE")
MR_OWNER_CONFIG=$(jq -r '.mrOwnerConfig // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"' "$REPORT_DATA_FILE")
ISV_PROD_ID=$(jq -r '.isvProdId // 0' "$REPORT_DATA_FILE")
ISVSVN=$(jq -r '.isvsvn // 1' "$REPORT_DATA_FILE")

echo "Extracted measurements:"
echo "  MRTD: ${MRTD:0:32}..."
echo "  RTMR0: ${RTMR0:0:32}..."
echo "  RTMR1: ${RTMR1:0:32}..."
echo "  XFAM: $XFAM"
echo "  Attributes: $ATTRIBUTES"

if [ "$USE_MOCK_REPORT" = true ]; then
    echo -e "${YELLOW}  Note: Mock data will be tested with skip-ra mode${NC}"
fi
echo

#
# Step 3: Update td_identity.json with extracted measurements
# Make sure no ending newline is added (important for signing)
#
echo -e "${BLUE}=== Step 3: Updating TD Identity Template ===${NC}"
jq -c ".xfam = \"$XFAM\" | .attributes = \"$ATTRIBUTES\" | .mrConfigId = \"$MR_CONFIG_ID\" | \
.mrOwner = \"$MR_OWNER\" | .mrOwnerConfig = \"$MR_OWNER_CONFIG\" | .mrsigner = \"$MRSIGNER\" | \
.isvProdId = $ISV_PROD_ID | .tcbLevels[0].tcb.isvsvn = $ISVSVN" \
"$TD_IDENTITY_TEMPLATE" | tr -d '\n' > "$TD_IDENTITY_UPDATED"

echo -e "${GREEN}✓ TD Identity updated: $TD_IDENTITY_UPDATED${NC}"
echo

#
# Step 4: Update tcb_mapping.json with extracted measurements
# Make sure no ending newline is added (important for signing)
#
echo -e "${BLUE}=== Step 4: Updating TCB Mapping Template ===${NC}"
jq -c ".svnMappings[0].tdMeasurements.mrtd = \"$MRTD\" | \
.svnMappings[0].tdMeasurements.rtmr0 = \"$RTMR0\" | \
.svnMappings[0].tdMeasurements.rtmr1 = \"$RTMR1\" | \
.svnMappings[0].isvsvn = $ISVSVN" \
"$TCB_MAPPING_TEMPLATE" | tr -d '\n' > "$TCB_MAPPING_UPDATED"

echo -e "${GREEN}✓ TCB Mapping updated: $TCB_MAPPING_UPDATED${NC}"
echo

#
# Step 5: Generate certificates and signing key
#
echo -e "${BLUE}=== Step 5: Generating Certificates ===${NC}"
generate_certificates "$CERT_DIR" "P384" 365

echo -e "${GREEN}✓ Certificates generated in: $CERT_DIR${NC}"
echo

#
# Steps 6-10: Sign all policy variants
#
# Each variant is built by:
#   1. Signing td_identity with an identity leaf key
#   2. Signing tcb_mapping with a mapping leaf key
#   3. Building servtd_collateral embedding the corresponding identity and
#      mapping issuer chains
#   4. Merging policy data with collaterals + servtd_collateral
#   5. Signing the merged policy with a policy leaf key
#
# All leaves chain to the same root CA so cert-chain validation succeeds.
#
# Variants emitted:
#   _a       : (identity_a, mapping_a, policy_a)               -- baseline
#   _b       : (identity_a, mapping_a, policy_b)               -- policy leaf rotated
#   _pm_b    : (identity_a, mapping_b, policy_b)               -- policy + tcb_mapping rotated
#   _pmi_b   : (identity_b, mapping_b, policy_b)               -- all 3 leaves rotated
#
build_signed_policy_variant() {
    local label="$1"
    local identity_suffix="$2"   # a or b
    local mapping_suffix="$3"    # a or b
    local policy_suffix="$4"     # a or b
    local output_policy="$5"

    local identity_key="$CERT_DIR/identity_signing_${identity_suffix}_pkcs8.key"
    local mapping_key="$CERT_DIR/mapping_signing_${mapping_suffix}_pkcs8.key"
    local policy_key="$CERT_DIR/policy_signing_${policy_suffix}_pkcs8.key"
    local identity_chain="$CERT_DIR/identity_issuer_chain_${identity_suffix}.pem"
    local mapping_chain="$CERT_DIR/mapping_issuer_chain_${mapping_suffix}.pem"

    local td_identity_signed="$TEMP_DIR/td_identity_signed_${label}.json"
    local tcb_mapping_signed="$TEMP_DIR/tcb_mapping_signed_${label}.json"
    local servtd_collateral="$TEMP_DIR/servtd_collateral_${label}.json"
    local policy_data_merged="$TEMP_DIR/policy_data_merged_${label}.json"

    echo -e "${BLUE}--- Variant ${label}: identity=${identity_suffix}, mapping=${mapping_suffix}, policy=${policy_suffix} ---${NC}"

    "$TOOLS_DIR/json-signer" \
        --sign \
        --name "tdIdentity" \
        --private-key "$identity_key" \
        --input "$TD_IDENTITY_UPDATED" \
        --output "$td_identity_signed"

    "$TOOLS_DIR/json-signer" \
        --sign \
        --name "tdTcbMapping" \
        --private-key "$mapping_key" \
        --input "$TCB_MAPPING_UPDATED" \
        --output "$tcb_mapping_signed"

    "$TOOLS_DIR/servtd-collateral-generator" \
        --identity "$td_identity_signed" \
        --identity-chain "$identity_chain" \
        --mapping "$tcb_mapping_signed" \
        --mapping-chain "$mapping_chain" \
        --output "$servtd_collateral"

    "$TOOLS_DIR/migtd-policy-generator" v2 \
        --policy-data "$POLICY_DATA_RAW" \
        --collaterals "$COLLATERALS_FILE" \
        --servtd-collateral "$servtd_collateral" \
        --output "$policy_data_merged"

    "$TOOLS_DIR/json-signer" \
        --sign \
        --name "policyData" \
        --private-key "$policy_key" \
        --input "$policy_data_merged" \
        --output "$output_policy"

    echo -e "${GREEN}✓ Policy signed (${label}): $output_policy${NC}"
}

echo -e "${BLUE}=== Step 6-10: Building Signed Policy Variants ===${NC}"
build_signed_policy_variant "a"     a a a "$OUTPUT_POLICY_A"
build_signed_policy_variant "b"     a a b "$OUTPUT_POLICY_B"
build_signed_policy_variant "pm_b"  a b b "$OUTPUT_POLICY_PM_B"
build_signed_policy_variant "pmi_b" b b b "$OUTPUT_POLICY_PMI_B"

# Also keep a default signed policy (variant a) for backward compat
cp "$OUTPUT_POLICY_A" "$OUTPUT_POLICY"

echo -e "${GREEN}✓ Default policy: $OUTPUT_POLICY${NC}"
echo

#
# Step 11: Copying Certificate Chains to output directory
#
echo -e "${BLUE}=== Step 11: Copying Certificate Chains ===${NC}"
cp "$CERT_DIR/policy_issuer_chain_a.pem" "$OUTPUT_CERT_CHAIN_A"
cp "$CERT_DIR/policy_issuer_chain_b.pem" "$OUTPUT_CERT_CHAIN_B"
cp "$OUTPUT_CERT_CHAIN_A" "$OUTPUT_CERT_CHAIN"

echo -e "${GREEN}✓ Certificate chain A: $OUTPUT_CERT_CHAIN_A${NC}"
echo -e "${GREEN}✓ Certificate chain B: $OUTPUT_CERT_CHAIN_B${NC}"
echo -e "${GREEN}✓ Default certificate chain: $OUTPUT_CERT_CHAIN${NC}"
echo

#
# Step 12: Securely delete private keys
#
echo -e "${BLUE}=== Step 12: Cleaning Up Private Keys ===${NC}"
for keyfile in \
    "$PRIVATE_KEY_A" "$PRIVATE_KEY_B" "$PRIVATE_KEY" \
    "$MAPPING_PRIVATE_KEY_A" "$MAPPING_PRIVATE_KEY_B" \
    "$IDENTITY_PRIVATE_KEY_A" "$IDENTITY_PRIVATE_KEY_B"; do
    if [ -f "$keyfile" ]; then
        shred -u "$keyfile" 2>/dev/null || rm -f "$keyfile"
    fi
done
echo -e "${GREEN}✓ Private keys securely deleted${NC}"
echo

#
# Summary
#
echo -e "${GREEN}=== Build Complete ===${NC}"
echo
echo "Generated files:"
echo "  📄 Policy (source/a):      $OUTPUT_POLICY_A"
echo "  📄 Policy (dest/b, policy leaf rotated):                  $OUTPUT_POLICY_B"
echo "  📄 Policy (dest, policy + tcb_mapping leaves rotated):    $OUTPUT_POLICY_PM_B"
echo "  📄 Policy (dest, policy + tcb_mapping + td_identity all rotated): $OUTPUT_POLICY_PMI_B"
echo "  📄 Policy (default):       $OUTPUT_POLICY"
echo "  📄 Cert chain (a):         $OUTPUT_CERT_CHAIN_A"
echo "  📄 Cert chain (b):         $OUTPUT_CERT_CHAIN_B"
echo "  📄 Cert chain (default):   $OUTPUT_CERT_CHAIN"
echo

if [ "$USE_MOCK_REPORT" = true ]; then
    echo "Policy contains MOCK measurements for testing:"
    echo "  MRTD: ${MRTD:0:64}..."
    echo "  RTMR0: ${RTMR0:0:64}..."
    echo "  RTMR1: ${RTMR1:0:64}..."
    echo -e "${YELLOW}  Note: This policy will be tested with test_mock_report feature${NC}"
else
    echo "Policy contains measurements extracted from live vTPM report:"
    echo "  MRTD: ${MRTD:0:64}..."
    echo "  RTMR0: ${RTMR0:0:64}..."
    echo "  RTMR1: ${RTMR1:0:64}..."
fi
echo

#
# Step 13: Test the policy (optional)
#
# Pass --skip-policy-generation: this script already generated the policy
# files, so migtdemu.sh must not re-run the generator (which would clobber
# the variants we want to test).
TEST_CMD="./migtdemu.sh --policy-v2 --src-policy-file $OUTPUT_POLICY_A --src-policy-issuer-chain-file $OUTPUT_CERT_CHAIN_A --dst-policy-file $OUTPUT_POLICY_B --dst-policy-issuer-chain-file $OUTPUT_CERT_CHAIN_B --skip-policy-generation --debug --both"
if [ "$USE_MOCK_REPORT" = true ]; then
    TEST_CMD="$TEST_CMD --mock-report"

    # Add mock quote file if specified
    if [[ -n "$MOCK_QUOTE_FILE" ]]; then
        TEST_CMD="$TEST_CMD --mock-quote-file $MOCK_QUOTE_FILE"
    fi
fi

# Add extra features if specified
if [[ -n "$EXTRA_FEATURES" ]]; then
    TEST_CMD="$TEST_CMD --features $EXTRA_FEATURES"
fi

if [ -z "$SKIP_TEST" ]; then
    echo -e "${BLUE}=== Step 13: Testing Policy ===${NC}"
    if [ "$USE_MOCK_REPORT" = true ]; then
        echo "Running with mock report mode: $TEST_CMD"
        echo -e "${YELLOW}Note: Using test_mock_report feature for mock TD reports/quotes${NC}"
    else
        echo "Running with real remote attestation: $TEST_CMD"
    fi
    echo

    cd "$PROJECT_ROOT"
    if $TEST_CMD; then
        echo
        echo -e "${GREEN}✓✓✓ SUCCESS: Policy validation and key exchange completed! ✓✓✓${NC}"
    else
        echo
        echo -e "${YELLOW}⚠ Test failed. Check the output above for errors.${NC}"
        echo "You can manually test with:"
        echo "  $TEST_CMD"
        exit 1
    fi
else
    echo -e "${YELLOW}Test skipped. To test manually, run:${NC}"
    echo "  $TEST_CMD"
fi

echo
echo -e "${GREEN}=== All Done! ===${NC}"

