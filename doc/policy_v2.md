# MigTD Policy v2 Usage Guide

This guide describes the end-to-end flow to produce and integrate Policy v2 artifacts into the MigTD image.

## Prerequisites

- Tools:
  - MigTD collateral generator: [tools/migtd-collateral-generator/readme.md](../tools/migtd-collateral-generator/readme.md)
  - ServTD collateral generator: [tools/servtd-collateral-generator/readme.md](../tools/servtd-collateral-generator/readme.md)
  - Policy generator: [tools/migtd-policy-generator/readme.md](../tools/migtd-policy-generator/readme.md)
  - JSON signer: [tools/json-signer/readme.md](../tools/json-signer/readme.md)

## 1. Generate Platform Collaterals

Fetch platform collaterals:

```sh
cargo build -p migtd-collateral-generator
./target/debug/migtd-collateral-generator -o config/collateral_production_fmspc.json
# or pre-production:
# ./target/debug/migtd-collateral-generator -o config/collateral_pre_production_fmspc.json --pre-production
```

The output JSON feeds the policy generator.

## 2. Generate ServTD Collaterals

Sign the ServTD identity and ServTD TCB mapping JSON:

```sh
cargo build -p json-signer
# Example: sign the ServTD identity with private key (in PKCS8) and output signed JSON
./target/debug/json-signer --sign  --name tdIdentity --private-key /path/to/pkcs8 --input /path/to/td_identity.json --output td_identity_signed.json
# Example: sign the ServTD TCB mapping with private key (in PKCS8) and output signed JSON
./target/debug/json-signer --sign  --name tdTcbMapping --private-key /path/to/pkcs8 --input /path/to/tcb_mapping.json --output tcb_mapping_signed.json
```

Produce ServTD identity and TCB mapping collateral bundle:

```sh
cargo build -p servtd-collateral-generator
./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --mapping /path/to/tcb_mapping_signed.json --mapping-chain /path/to/identity_issuer_chain.pem -o servtd_collateral.json
```

Result: `servtd_collateral.json` (contains signed `td identity` and `tcb mapping`, and their issuer chains).

## 3. Generate and Sign Policy

Generate a policy v2 JSON referencing:
- Attestation collaterals (from step 1)
- Signed ServTD collateral (from step 2)
- Base Policy Data (without collaterals and ServTD collateral)

```sh
cargo build -p migtd-policy-generator
./target/debug/migtd-policy-generator v2 \
  --policy-data /path/to/policy_data.json \
  --collaterals /path/to/collateral.json \
  --servtd-collateral /path/to/servtd_collateral.json \
  -o policy_v2.json
```

Sign the policy:

```sh
cargo build -p json-signer
./target/debug/json-signer --sign  --name policyData --private-key /path/to/pkcs8 --input /path/to/policy_v2.json --output policy_v2_signed.json
```

Result: `policy_v2_signed.json` (contains `policyData` and its signature).

## 4. Build Final MigTD Image with Policy and Issuer Chain

Place artifacts where the build expects them (e.g. under `config/templates`):

```
config/templates/
  policy_v2_signed.json
  policy_issuer_chain.pem
```

Build image (with option `--policy-v2`):

```sh
cargo image --policy-v2 \
  --policy config/templates/policy_v2_signed.json \
  --policy-issuer-chain config/templates/policy_issuer_chain.pem
```

During startup:
- Policy issuer chain is measured (see measurement flow in [src/migtd/src/bin/migtd/main.rs](../src/migtd/src/bin/migtd/main.rs)).
- Policy integrity is verified with issuer chain and measured by RTMR and event log (`RawPolicyData::verify` in [src/policy/src/v2/policy.rs](../src/policy/src/v2/policy.rs)).
- Collaterals are used for quote verification and TCB evaluation.

## 5. Build Final MigTD Image with policy which contain updated TCD mapping
### Generate new key pair for policy signing
```
bash sh_script/key_gen.sh
```

### build migtd with existing policy
```
cargo clean
cargo image --policy-v2 \
 --policy config/templates/policy_v2_signed.json \
 --policy-issuer-chain key/migtd_issuer_chain.pem
```

### Build migtd-hash tool
```
pushd tools/migtd-hash
cargo build
popd
```

### Generate new measurement with updated TCB mapping
```
./target/debug/migtd-hash --manifest config/servtd_info.json \
 --image target/release/migtd.bin \
 --policy-v2 \
 --update-tcb-mapping config/templates/tcb_mapping.json
```

### Resign policy with generated keys
```
bash sh_script/build_policy_v2.sh [preprod/prod]
```
### Rebuild migtd with new policy
```
cargo image --policy-v2 \
 --policy config/templates/policy_v2_signed.json \
 --policy-issuer-chain key/migtd_issuer_chain.pem
```

## Summary Flow

1. Platform collaterals -> `collateral_*.json`
2. ServTD collateral -> sign -> `servtd_collateral_signed.json`
3. Policy generator -> `policy_v2.json` -> sign -> `policy_v2_signed.json`
4. Build image with signed policy + issuer chain -> `cargo image --policy-v2 --policy config/templates/policy_v2_signed.json --policy-issuer-chain config/templates/policy_issuer_chain.pem`
