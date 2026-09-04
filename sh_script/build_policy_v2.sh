#!/bin/bash
set -euo pipefail

config_temp_dir="./config/templates"
key_dir="./key"

environment="${1:-pre-production}"
tcb_mapping_file="${2:-}"
signed_identity_file="${3:-}"
servtd_crl_file="${4:-}"
case "$environment" in
  pre-production|preprod)
    collateral_file="collateral_pre_production_fmspc.json"
    ;;
  production|prod)
    collateral_file="collateral_production_fmspc.json"
    ;;
  *)
    echo "Usage: $0 <pre-production|production> <cumulative-tcb-mapping.json> <signed-identity.json> <servtd-crl.pem>" >&2
    exit 1
    ;;
esac

echo "Selected collateral environment '$environment' using $collateral_file"
if [[ -z "$tcb_mapping_file" || -z "$signed_identity_file" || -z "$servtd_crl_file" ]]; then
  echo "Usage: $0 <pre-production|production> <cumulative-tcb-mapping.json> <signed-identity.json> <servtd-crl.pem>" >&2
  exit 1
fi
if [[ ! -s "$signed_identity_file" ]] || ! jq -e \
  '(.tdIdentity | type == "object") and (.signature | type == "string" and length > 0)' \
  "$signed_identity_file" >/dev/null; then
  echo "The signed identity used to measure this release is required: $signed_identity_file" >&2
  exit 1
fi
if [[ ! -s "$servtd_crl_file" ]]; then
  echo "A nonempty signed servTD CRL is required: $servtd_crl_file" >&2
  exit 1
fi
if ! jq -e '.svnMappings | type == "array" and length > 0' "$tcb_mapping_file" >/dev/null; then
  echo "TCB mapping must contain at least one reviewed release: $tcb_mapping_file" >&2
  echo "Generate it cumulatively with migtd-hash before signing." >&2
  exit 1
fi
echo "Signing cumulative TCB mapping: $tcb_mapping_file"
measured_policy=$(jq -cS 'del(.servtdCollateral.servtdTcbMapping, .servtdCollateral.servtdTcbMappingIssuerChain)' \
  "$config_temp_dir/policy_v2.json")

# Build migtd-collateral-generator and generate collateral_pre_production_fmspc.json
# cargo build -p migtd-collateral-generator
# ./target/debug/migtd-collateral-generator \
#   -o $config_temp_dir/collateral_pre_production_fmspc.json \
#   --pre-production

# The signed identity is measured; only the TCB mapping may be re-signed here.
cargo build -p json-signer
./target/debug/json-signer --sign \
  --name tdTcbMapping \
  --private-key "$key_dir/issuer_pkcs8.key" \
  --input "$tcb_mapping_file" \
  --output "$config_temp_dir/tcb_mapping_signed.json"

# Build servtd-collateral-generator and generate servtd_collateral.json
cargo build -p servtd-collateral-generator
./target/debug/servtd-collateral-generator \
  --identity "$signed_identity_file" \
  --identity-chain "$key_dir/migtd_issuer_chain.pem" \
  --mapping "$config_temp_dir/tcb_mapping_signed.json" \
  --servtd-crl "$servtd_crl_file" \
  -o "$config_temp_dir/servtd_collateral.json"

# Build migtd-policy-generator and generate policy_v2.json
cargo build -p migtd-policy-generator
policy_output=$(mktemp "$config_temp_dir/policy_v2.XXXXXX")
trap 'rm -f -- "$policy_output"' EXIT
./target/debug/migtd-policy-generator v2 \
  --policy-data "$config_temp_dir/policy_v2.json" \
  --collaterals "$config_temp_dir/../$collateral_file" \
  --servtd-collateral "$config_temp_dir/servtd_collateral.json" \
  -o "$policy_output"

updated_measurement=$(jq -cS 'del(.servtdCollateral.servtdTcbMapping, .servtdCollateral.servtdTcbMappingIssuerChain)' "$policy_output")
if [[ "$updated_measurement" != "$measured_policy" ]]; then
  echo "Finalization would change measured policy data; prepare and measure a new release first." >&2
  exit 1
fi
mv -- "$policy_output" "$config_temp_dir/policy_v2.json"

# policyData integrity is provided by RTMR2; the policy blob has no outer
# signature. Keep the historical output filename for build compatibility.
jq -c '{policyData: .}' "$config_temp_dir/policy_v2.json" \
  > "$config_temp_dir/policy_v2_signed.json"
