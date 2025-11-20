#!/bin/bash
set -euo pipefail

config_temp_dir="./config/templates"
key_dir="./key"

environment="${1:-pre-production}"
case "$environment" in
  pre-production|preprod)
    collateral_file="collateral_pre_production_fmspc.json"
    ;;
  production|prod)
    collateral_file="collateral_production_fmspc.json"
    ;;
  *)
    echo "Usage: $0 <pre-production|production>"
    exit 1
    ;;
esac

echo "Selected collateral environment '$environment' using $collateral_file"

# Build migtd-collateral-generator and generate collateral_pre_production_fmspc.json
# cargo build -p migtd-collateral-generator
# ./target/debug/migtd-collateral-generator \
#   -o $config_temp_dir/collateral_pre_production_fmspc.json \
#   --pre-production

# Build json-signer and sign td_identity.json
cargo build -p json-signer
./target/debug/json-signer --sign \
  --name tdIdentity \
  --private-key $key_dir/issuer_pkcs8.key \
  --input $config_temp_dir/td_identity.json \
  --output $config_temp_dir/td_identity_signed.json

# Sign tcb_mapping.json
./target/debug/json-signer --sign \
  --name tdTcbMapping \
  --private-key $key_dir/issuer_pkcs8.key \
  --input $config_temp_dir/tcb_mapping.json \
  --output $config_temp_dir/tcb_mapping_signed.json

# Build servtd-collateral-generator and generate servtd_collateral.json
cargo build -p servtd-collateral-generator
./target/debug/servtd-collateral-generator \
  --identity $config_temp_dir/td_identity_signed.json \
  --identity-chain $key_dir/migtd_issuer_chain.pem \
  --mapping $config_temp_dir/tcb_mapping_signed.json \
  --mapping-chain $key_dir/migtd_issuer_chain.pem \
  -o $config_temp_dir/servtd_collateral.json

# Build migtd-policy-generator and generate policy_v2.json
cargo build -p migtd-policy-generator
./target/debug/migtd-policy-generator v2 \
  --policy-data $config_temp_dir/policy_v2.json \
  --collaterals $config_temp_dir/../$collateral_file \
  --servtd-collateral $config_temp_dir/servtd_collateral.json \
  -o $config_temp_dir/policy_v2.json

# Sign policy_v2.json
./target/debug/json-signer --sign \
  --name policyData \
  --private-key $key_dir/issuer_pkcs8.key \
  --input $config_temp_dir/policy_v2.json \
  --output $config_temp_dir/policy_v2_signed.json
