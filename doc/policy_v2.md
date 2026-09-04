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

All v2 policies must include an intermediate-CA-signed PEM CRL with a CRL-number extension
in `servtdCollateral.servtdCrl`. If no certificates are revoked, provide a valid
signed CRL with an empty revocation list, not an empty file or an omitted field.
The CRL must be signed by the immediate, non-root issuer of each signing leaf,
not just any CA present in its chain. That intermediate must have
`BasicConstraints.cA=true` and an explicit `KeyUsage.cRLSign` permission.
Missing, malformed, or duplicate KeyUsage extensions are rejected. The policy
and identity may use separate leaves and keys, but both must have the same
issuing intermediate when sharing this CRL.

Only complete, direct, issuer-wide CRLs are supported. Delta CRLs, issuing
distribution points, indirect entries, reason-scoped or delegated certificate
distribution points, and unsupported critical extensions are rejected.
Unrecognized non-critical extensions, including Microsoft CA-version and
next-publish metadata, remain permitted. Revocation lookup applies only to
the signing leaves, never to root or intermediate serial numbers.

This profile deliberately excludes intermediate revocation and automatic
intermediate-key rollover. Root-issued CRLs and root-issued signing leaves
are not supported. Leaf-key rotation under the same intermediate is supported.
Changing measured collateral still requires a new image and TDINFO endorsement.
These restrictions apply only to `servtdCrl`, not Intel platform CRLs.

Produce the ServTD identity, TCB mapping, and CRL collateral bundle:

```sh
cargo build -p servtd-collateral-generator
./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --mapping /path/to/tcb_mapping_signed.json --servtd-crl /path/to/servtd_signers.crl.pem -o servtd_collateral.json
```

Result: `servtd_collateral.json` contains the signed ServTD identity, its issuer
chain, the signed TCB mapping, and the CRL. The TCB mapping is verified with the
policy issuer chain whose signer anchor is measured into RTMR1.

Missing, null, malformed, or unauthenticated CRLs are rejected during policy
verification, as are CRLs without a CRL-number extension. MigTD checks peer
signers against its local CRL; a peer-provided CRL cannot replace it. Existing
v2 policies without `servtdCrl` must be regenerated with a signed CRL before
use with this implementation. The CRL is part of the RTMR2-measured policy data,
so adding or updating it requires rebuilding the image and updating its
cumulative TCB mapping. Policy v1 is unchanged.

## 3. Generate Policy

Generate a policy v2 JSON referencing:
- Attestation collaterals (from step 1)
- Signed ServTD collateral (from step 2)
- Base Policy Data (without collaterals and ServTD collateral)

An optional servTD signer CRL floor belongs in a `servtd` entry in the applicable
`policy`, `forwardPolicy`, or `backwardPolicy` list:

```json
{
  "servtd": {
    "migtdIdentity": {},
    "servtdCrlNum": {
      "operation": "greater-or-equal",
      "reference": "self"
    }
  }
}
```

This constraint remains active in each evaluated servTD policy block when
rebinding skips platform checks. The example requires the peer's CRL number to
be at least the local CRL number; a missing peer or local number fails evaluation.
Both CRLs must authenticate with the same immediate-issuer name and key under
the issuer-wide profile before their numbers are compared. The peer CRL's
signature, profile, and number are checked, but its revocation entries never
override or supplement the local revocation decision.
The CRL itself remains in `servtdCollateral.servtdCrl`. `global.crl` accepts only
`pckCrlNum` and `rootCaCrlNum`; placing `servtdCrlNum` there is rejected.

Migration and rebinding always require the peer's attested TDINFO hash to resolve
to an SVN in its authenticated mapping, even when the policy only checks CRL
freshness or platform properties. Optional TD Identity controls date/status
enrichment, not whether an endorsement is required. An attached CoRIM is the sole
mapping authority: a lookup miss rejects the peer without falling back to JSON.

```sh
cargo build -p migtd-policy-generator
./target/debug/migtd-policy-generator v2 \
  --policy-data /path/to/policy_data.json \
  --collaterals /path/to/collateral.json \
  --servtd-collateral /path/to/servtd_collateral.json \
  -o policy_v2.json
```

Package the generated policy data without an outer signature:

```sh
jq -c '{policyData: .}' policy_v2.json > policy_v2_signed.json
```

RTMR2 measures canonical `policyData` with only `servtdTcbMapping` removed to
avoid the mapping/image circular dependency. The TCB mapping remains separately
signed by the RTMR1-bound policy issuer.

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
- The supplied policy issuer chain and canonical `policyData` are matched to
  their authenticated RTMR1 and RTMR2 event digests before the mapping is used.
- Collaterals are used for quote verification and TCB evaluation.

## 5. Finalize the cumulative TCB mapping

Prepare the signing keys and complete steps 1-3 **before** measuring the release.
Retain the exact signed identity as `config/templates/td_identity_signed.json`
and use `key/migtd_issuer_chain.pem` consistently for this example. Freeze the
identity, its signature and issuer chain, signer CRL, platform collaterals, policy settings,
image build options, and TDINFO manifest. Re-signing an unchanged identity can
produce a different signature, changing RTMR2 and therefore `tdinfo_hash`.

`build_policy_v2.sh` is a mapping-finalization step, not an initial policy
generator. It consumes the already-signed identity and rejects changes to
measured policy data rather than silently invalidating the recorded hash.

### Build with the prepared policy
```sh
cargo image --policy-v2 \
 --policy config/templates/policy_v2_signed.json \
 --policy-issuer-chain key/migtd_issuer_chain.pem
```

### Build migtd-hash tool
```sh
cargo build -p migtd-hash
```

### Generate new measurement with updated TCB mapping
```sh
./target/debug/migtd-hash --manifest config/servtd_info.json \
 --image target/release/migtd.bin \
 --policy-v2 \
 --output-tdinfo-hash target/release/expected_tdinfo_hash.txt \
 --mapping-isvsvn <release-svn> \
 --update-tcb-mapping config/templates/tcb_mapping.json
```

### Sign the cumulative mapping and rebuild the policy
```sh
bash sh_script/build_policy_v2.sh preprod \
 config/templates/tcb_mapping.json config/templates/td_identity_signed.json \
 /path/to/servtd_signers.crl.pem
```
### Rebuild migtd with new policy
```sh
cargo image --policy-v2 \
 --policy config/templates/policy_v2_signed.json \
 --policy-issuer-chain key/migtd_issuer_chain.pem
```

Require the rebuilt image to retain the recorded release hash. Do not publish
the image or mapping if this comparison fails:

```sh
./target/debug/migtd-hash --manifest config/servtd_info.json \
 --image target/release/migtd.bin --policy-v2 \
 --output-tdinfo-hash target/release/final_tdinfo_hash.txt
cmp --silent target/release/expected_tdinfo_hash.txt target/release/final_tdinfo_hash.txt \
 || { echo "Final image no longer matches its TDINFO endorsement" >&2; exit 1; }
```

## Summary Flow

1. Platform collaterals -> `collateral_*.json`
2. Sign the ServTD identity and cumulative TCB mapping -> generate `servtd_collateral.json`
3. Generate policy data -> package it as `policy_v2_signed.json` without an outer signature
4. Build the image with measured policy data and issuer chain
5. Record its `tdinfo_hash` and update the cumulative mapping
6. Re-sign only the mapping, preserving every measured input
7. Rebuild and require the final `tdinfo_hash` to equal the recorded value
