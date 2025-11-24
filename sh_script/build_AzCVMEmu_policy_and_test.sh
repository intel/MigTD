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
#   6. Generates certificate chain (root CA + policy signing cert)
#   7. Signs td_identity.json with policy signing key (testing only)
#   8. Signs tcb_mapping.json with policy signing key (testing only)
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

# Default paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_MATERIAL_DIR="$PROJECT_ROOT/config/AzCVMEmu"
OUTPUT_DIR="$PROJECT_ROOT/config/AzCVMEmu"
TEMP_DIR=$(mktemp -d)
TOOLS_DIR="$PROJECT_ROOT/target/release"

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
OUTPUT_CERT_CHAIN="$OUTPUT_DIR/policy_issuer_chain.pem"
CERT_DIR="$TEMP_DIR/certs"
PRIVATE_KEY="$CERT_DIR/policy_signing_pkcs8.key"

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

    echo "3. Generating policy signing private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve_name -out "$output_dir/policy_signing.key"

    # Convert to PKCS8 format for json-signer
    echo "4. Converting key to PKCS8 format..."
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
        -in "$output_dir/policy_signing.key" \
        -out "$output_dir/policy_signing_pkcs8.key"

    echo "5. Generating certificate signing request..."
    openssl req -new \
        -key "$output_dir/policy_signing.key" \
        -out "$output_dir/policy_signing.csr" \
        -subj "$leaf_subject"

    echo "6. Signing leaf certificate with root CA..."
    openssl x509 -req \
        -in "$output_dir/policy_signing.csr" \
        -CA "$output_dir/root_ca.pem" \
        -CAkey "$output_dir/root_ca.key" \
        -CAcreateserial \
        -out "$output_dir/policy_signing.pem" \
        -days $cert_validity_days \
        -$hash_algo \
        -extensions v3_ca \
        -extfile <(echo -e "[v3_ca]\nkeyUsage = digitalSignature")

    # Create certificate chain (leaf + root)
    echo "7. Creating certificate chain..."
    cat "$output_dir/policy_signing.pem" "$output_dir/root_ca.pem" > "$output_dir/policy_issuer_chain.pem"

    # Clean up CSR
    rm -f "$output_dir/policy_signing.csr"
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
            OUTPUT_CERT_CHAIN="$OUTPUT_DIR/policy_issuer_chain.pem"
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
(cd deps/td-shim-AzCVMEmu/azcvm-extract-report && cargo build --release) 2>&1 | grep -E "(Compiling|Finished|error)" || true

echo "Building json-signer..."
cargo build --release -p json-signer 2>&1 | grep -E "(Compiling|Finished|error)" || true

echo "Building servtd-collateral-generator..."
cargo build --release -p servtd-collateral-generator 2>&1 | grep -E "(Compiling|Finished|error)" || true

echo "Building migtd-policy-generator..."
cargo build --release -p migtd-policy-generator 2>&1 | grep -E "(Compiling|Finished|error)" || true

# Verify tools exist
# Note: azcvm-extract-report is in a different location
if [ ! -f "$PROJECT_ROOT/deps/td-shim-AzCVMEmu/azcvm-extract-report/target/release/azcvm-extract-report" ]; then
    echo -e "${RED}Error: Tool 'azcvm-extract-report' not found${NC}" >&2
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

    "$PROJECT_ROOT/deps/td-shim-AzCVMEmu/azcvm-extract-report/target/release/azcvm-extract-report" \
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
    sudo "$PROJECT_ROOT/deps/td-shim-AzCVMEmu/azcvm-extract-report/target/release/azcvm-extract-report"

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
# Step 6: Sign td_identity.json
#
echo -e "${BLUE}=== Step 6: Signing TD Identity ===${NC}"
"$TOOLS_DIR/json-signer" \
    --sign \
    --name "tdIdentity" \
    --private-key "$PRIVATE_KEY" \
    --input "$TD_IDENTITY_UPDATED" \
    --output "$TD_IDENTITY_SIGNED"

echo -e "${GREEN}✓ TD Identity signed: $TD_IDENTITY_SIGNED${NC}"
echo

#
# Step 7: Sign tcb_mapping.json
#
echo -e "${BLUE}=== Step 7: Signing TCB Mapping ===${NC}"
"$TOOLS_DIR/json-signer" \
    --sign \
    --name "tdTcbMapping" \
    --private-key "$PRIVATE_KEY" \
    --input "$TCB_MAPPING_UPDATED" \
    --output "$TCB_MAPPING_SIGNED"

echo -e "${GREEN}✓ TCB Mapping signed: $TCB_MAPPING_SIGNED${NC}"
echo

#
# Step 8: Generate servtd_collateral.json
#
echo -e "${BLUE}=== Step 8: Generating ServTD Collateral ===${NC}"
IDENTITY_CHAIN="$CERT_DIR/policy_issuer_chain.pem"
MAPPING_CHAIN="$CERT_DIR/policy_issuer_chain.pem"

"$TOOLS_DIR/servtd-collateral-generator" \
    --identity "$TD_IDENTITY_SIGNED" \
    --identity-chain "$IDENTITY_CHAIN" \
    --mapping "$TCB_MAPPING_SIGNED" \
    --mapping-chain "$MAPPING_CHAIN" \
    --output "$SERVTD_COLLATERAL"

echo -e "${GREEN}✓ ServTD Collateral generated: $SERVTD_COLLATERAL${NC}"
echo

#
# Step 9: Merge policy data with collaterals and servtd_collateral
#
echo -e "${BLUE}=== Step 9: Merging Policy Data ===${NC}"
"$TOOLS_DIR/migtd-policy-generator" v2 \
    --policy-data "$POLICY_DATA_RAW" \
    --collaterals "$COLLATERALS_FILE" \
    --servtd-collateral "$SERVTD_COLLATERAL" \
    --output "$POLICY_DATA_MERGED"

echo -e "${GREEN}✓ Policy data merged: $POLICY_DATA_MERGED${NC}"
echo

#
# Step 10: Sign the final policy
#
echo -e "${BLUE}=== Step 10: Signing Final Policy ===${NC}"
"$TOOLS_DIR/json-signer" \
    --sign \
    --name "policyData" \
    --private-key "$PRIVATE_KEY" \
    --input "$POLICY_DATA_MERGED" \
    --output "$OUTPUT_POLICY"

echo -e "${GREEN}✓ Policy signed: $OUTPUT_POLICY${NC}"
echo

#
# Step 11: Copy certificate chain to output directory
#
echo -e "${BLUE}=== Step 11: Copying Certificate Chain ===${NC}"
cp "$CERT_DIR/policy_issuer_chain.pem" "$OUTPUT_CERT_CHAIN"

echo -e "${GREEN}✓ Certificate chain copied: $OUTPUT_CERT_CHAIN${NC}"
echo

#
# Step 12: Securely delete private key
#
echo -e "${BLUE}=== Step 12: Cleaning Up Private Key ===${NC}"
if [ -f "$PRIVATE_KEY" ]; then
    shred -u "$PRIVATE_KEY" 2>/dev/null || rm -f "$PRIVATE_KEY"
    echo -e "${GREEN}✓ Private key securely deleted${NC}"
fi
echo

#
# Summary
#
echo -e "${GREEN}=== Build Complete ===${NC}"
echo
echo "Generated files:"
echo "  📄 Policy: $OUTPUT_POLICY"
echo "  📄 Certificate chain: $OUTPUT_CERT_CHAIN"
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
TEST_CMD="./migtdemu.sh --policy-v2 --policy-file $OUTPUT_POLICY --policy-issuer-chain-file $OUTPUT_CERT_CHAIN --debug --both"
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

