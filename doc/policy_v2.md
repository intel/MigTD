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

After signature verification, JSON TCB mappings must contain valid 96-character
hexadecimal `servtdInfoHash` values (48 bytes). The same hash and `servtdAttr`,
compared without regard to hexadecimal letter case, must not map to different
SVNs. Identical hash/SVN duplicates remain accepted; malformed or conflicting
entries reject the mapping with `InvalidServtdTcbMapping`.

All v2 policies must include an intermediate-CA-signed PEM CRL with a CRL-number extension
in `policyData.servtdCrl` or `policyData.servtdCollateral.servtdCrl`.
If no certificates are revoked, provide a valid
signed CRL with an empty revocation list, not an empty file or an omitted field.
The CRL must be signed by the immediate, non-root issuer of each signing leaf,
not just any CA present in its chain. That intermediate must have
`BasicConstraints.cA=true` and an explicit `KeyUsage.cRLSign` permission.
Missing, malformed, or duplicate KeyUsage extensions are rejected. Mapping
and optional identity may use separate leaves and keys, but both must have
the same issuing intermediate when sharing this CRL.

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

Produce the measured ServTD identity and CRL collateral:

```sh
cargo build -p servtd-collateral-generator
./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --servtd-crl /path/to/servtd_signers.crl.pem -o servtd_collateral.json
```

Omit both `--identity` and `--identity-chain` for SVN-only collateral; otherwise
the identity retains its issuer chain.

Result: `servtd_collateral.json` contains the CRL and any signed ServTD identity
with its issuer chain. Keep the signed TCB mapping as a separate artifact.
MigTD verifies it with the policy issuer chain and requires that chain to
resolve to the signer anchor measured into RTMR1.

Missing, null, malformed, or unauthenticated CRLs are rejected during policy
verification, as are CRLs without a CRL-number extension. MigTD checks peer
signers against its local CRL; a peer-provided CRL cannot replace it. Existing
v2 policies without `servtdCrl` must be regenerated with a signed CRL before
use with this implementation. The CRL is part of the RTMR2-measured policy data,
so adding or updating it requires rebuilding the image and updating its
cumulative TCB mapping. Policy v1 is unchanged.

### Mapping signer authority

Peer authentication verifies the JSON or CoRIM mapping signature and requires
its signing chain to resolve to the peer's attested RTMR1 signer anchor. That
anchor must match the local enrolled anchor, whether derived from a PEM chain
or supplied directly as 48 raw bytes. CoRIM direct-anchor enrollment does not
require a local PEM chain; JSON mappings still require the policy issuer PEM
to verify their signature.

The signer anchor binds the root certificate, complete leaf Subject DN,
and selected dedicated signer-purpose EKU, not the full issuer-chain bytes.
EKU supplements the identity binding; it does not replace it. The CA must
issue that identity and purpose only to authorized mapping
signers for the intended product.
Intermediate certificates must be valid CAs, but are not part of the anchor;
the CRL issuer constraints above still apply.

The authenticated source mapping resolves the initial and current release SVNs,
including releases absent from an older destination's local mapping. The
mapping signer is therefore trusted to assign SVNs correctly to complete
TDINFO hashes, including their measured policy contents; the destination's
local mapping is not an allowlist for future source releases.

### CoRIM TCB mapping (optional)

A signed CoRIM can replace the JSON `servtdTcbMapping`. It carries the same
information, `SERVTD_INFO_HASH -> isvsvn`. JSON remains the default; the policy
and the TD Identity are always JSON. Passing `--servtd-corim <file>` to
`cargo image` (with `--policy-v2`) enables the `servtd_corim` feature and
enrolls the file.

**Format** (draft-ietf-rats-corim-10, as implemented by the `corim` crate):

- The file is a `COSE_Sign1` (`#6.18`) with an attached payload. The protected
  header has `alg` ES384 (`-35`) or ESP384 (`-51`) and an RFC 9360 `x5chain`
  (DER certificates, leaf first). `nbf` and `exp` claims are rejected because
  MigTD has no trusted clock. The signature is ECDSA P-384 with SHA-384, raw
  `r || s`.
- The payload is a CoRIM (`#6.501`) holding CoMID tags (`#6.506`). Each
  authorized release adds a `reference-triple` and a
  `conditional-endorsement-series` triple in the environment
  `class = {vendor "Intel", model "TDX"}`, `instance = #6.560("migration-td")`.
  The measurement is `mval.digests[0]` = the 48-byte servTD info hash. The
  series record selects that digest and adds `mval.svn` = the exact `isvsvn`.
- A non-zero `SERVTD_ATTR` mask is carried as `mval.raw-value` (key 4) of the
  same measurement: `#6.560` of 8 bytes, little endian, in both the reference
  triple and the selection. Absent means 0. Only bits 33, 35, 36 and 37 are accepted;
  masked raw values (`#6.563`) are rejected.

**Rules**

- The `x5chain` must resolve to the RTMR[1] signer anchor (root certificate, leaf
  Subject DN and dedicated EKU; the leaf may carry other dedicated EKUs), and the
  local servTD CRL is applied to the signing leaf. See the signer anchor and
  revocation rules below.
- A CoRIM that is present is the sole mapping authority. A hash that is not in it
  rejects the peer; MigTD does not fall back to JSON.
- Every series-record hash and `SERVTD_ATTR` must also appear in a reference
  triple of the same environment, and the same hash and attribute must not map
  to two SVNs.
- The CoRIM is enrolled in the CFV and is not measured, so adding or replacing it
  does not change `tdinfo_hash`. Peers receive it with the pre-session data
  (at most 64 KiB) and authenticate it against their own enrolled anchor.
- Without JSON `servtdCollateral`, the policy still needs the numbered signer CRL
  at `policyData.servtdCrl`. See "Direct signer-anchor enrollment" for the image
  options (`--servtd-corim`, `--signer-anchor`).

The repository has no release tool that produces a CoRIM. The emulation
fixtures in `src/policy/test/policy_v2/corim/` are generated by the test-only
script `generate.py` with throwaway keys and must not be used as production
trust material.

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
    "crl": {
      "servtdCrlNum": {
        "operation": "greater-or-equal",
        "reference": "self"
      }
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
The CRL itself remains in `servtdCrl` or `servtdCollateral.servtdCrl` within
`policyData`. `global.crl` accepts only
`pckCrlNum` and `rootCaCrlNum`; the servTD floor belongs at
`servtd.crl.servtdCrlNum`.

When the new MigTD authenticates the old MigTD during rebinding, it evaluates
common `policy` servTD constraints followed by `backwardPolicy`. An absent or
empty backward block does not disable a common SVN or CRL-number floor, and
backward rules cannot relax that floor. Both blocks use the current local (new)
MigTD as their relative reference and skip `global` checks. Consequently, a
common `isvsvn >= self` rule rejects an older source even if a backward rule
would otherwise allow the upgrade. Initial-to-current source SVN ordering is
enforced separately.

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

RTMR2 measures the complete canonical `policyData`. The TCB mapping is a
separate signed artifact to avoid the mapping/image circular dependency.
Legacy policies embedding `servtdTcbMapping` or
`servtdTcbMappingIssuerChain` are rejected.

### Release SVN and policy SVN

The mapping's `isvsvn` orders complete TDINFO values, including the measured
policy and `MROWNERCONFIG`. Migration and rebinding source continuity require
the initial release SVN to be no greater than the current release SVN. The
initial hash comes from `SERVTD_EXT`; the current hash comes from the
authenticated peer quote or TDREPORT.

### Non-zero SERVTD_ATTR

`SERVTD_ATTR` is a 64-bit mask (the `SERVTD_ATTR` definition in the TD Migration
ABI reference). A set `IGNORE_*` bit makes the TDX module use 0 in place of that
field of the service TD when it calculates `SERVTD_INFO_HASH`. MigTD accepts the
bits marked "accepted" and rejects every other bit that is set, in the build
configuration, in mapping entries and CoRIMs, and in the peer's `SERVTD_EXT`:

| Bit(s) | Name | Field replaced by 0 | MigTD |
|---|---|---|---|
| 31:0 | Reserved | - | rejected |
| 32 | `IGNORE_ATTRIBUTES` | ATTRIBUTES | rejected |
| 33 | `IGNORE_XFAM` | XFAM | accepted |
| 34 | `IGNORE_MRTD` | MRTD | rejected |
| 35 | `IGNORE_MRCONFIGID` | MRCONFIGID | accepted |
| 36 | `IGNORE_MROWNER` | MROWNER | accepted |
| 37 | `IGNORE_MROWNERCONFIG` | MROWNERCONFIG | accepted |
| 38 | `IGNORE_RTMR0` | RTMR0 | rejected |
| 39 | `IGNORE_RTMR1` | RTMR1 | rejected |
| 40 | `IGNORE_RTMR2` | RTMR2 | rejected |
| 41 | `IGNORE_RTMR3` | RTMR3 | rejected |
| 42 | `IGNORE_SERVTD_HASH` | SERVTD_HASH | rejected |
| 43 | `IGNORE_MRSIGROOT` | MRSIGROOT | rejected |
| 44 | `IGNORE_MRSIGNER` | MRSIGNER | rejected |
| 45 | `IGNORE_PRODID` | PRODID | rejected |
| 46 | `IGNORE_ISVSVN` | ISVSVN | rejected |
| 47 | `IGNORE_MRCONFIGSVN` | MRCONFIGSVN | rejected |
| 48 | `IGNORE_MROWNERCONFIGSVN` | MROWNERCONFIGSVN | rejected |
| 63:49 | Reserved | - | rejected |

The mask is a property of the MigTD build. Set `servtdAttr` in
`config/servtd_attr.json`: exactly one top-level key whose value is a number or
a decimal or `0x` hex string (default `"0x0"`; whitespace is trimmed, an empty,
duplicate or malformed value fails the build). Both the MigTD build and
`migtd-hash` (unless `--servtd-attr` overrides it, in decimal or hex) read that
file with the same parser. Bind the TD with the same value. The mapping entry
then records the masked hash and the mask. Inside a mapping entry `servtdAttr`
must be a JSON number, not a string:

```json
{"tdMeasurements": {"servtdInfoHash": "<masked servTD info hash>", "servtdAttr": 137438953472}, "isvsvn": 2}
```

`servtdAttr` is omitted when it is 0. The peer's `CUR_SERVTD_ATTR` comes from its
`SERVTD_EXT`, which each side sends to the other. The verifier hashes the
verified report with that mask and looks up the exact `(hash, attr)` pair. A
signed CoRIM carries the mask as `raw-value` (key 4: 8 bytes, little
endian) next to the digest. The same `servtdInfoHash` must map to one `isvsvn`
whatever `servtdAttr` it appears with (when the masked fields are already zero,
the masked and unmasked hashes are equal); a mapping that violates this is
rejected, so the peer cannot pick the mask that gives the higher SVN.

## 4. Build Final MigTD Image with Policy, Issuer Chain, and Mapping

Place artifacts where the build expects them (e.g. under `config/templates`):

```
config/templates/
  policy_v2_signed.json
  policy_issuer_chain.pem
  tcb_mapping_signed.json
```

Build image (with option `--policy-v2`):

```sh
cargo image --policy-v2 \
  --policy config/templates/policy_v2_signed.json \
  --policy-issuer-chain config/templates/policy_issuer_chain.pem \
  --servtd-tcb-mapping config/templates/tcb_mapping_signed.json
```

During startup:
- The signer anchor is measured, not the full issuer chain. It is derived from
  PEM or supplied directly as 48 raw bytes (see the measurement flow in
  [src/migtd/src/bin/migtd/main.rs](../src/migtd/src/bin/migtd/main.rs)).
- The authenticated RTMR1 event digest must match `SHA384(signer_anchor)`.
  The RTMR2 event digest must match the hash of canonical `policyData` before
  the mapping is used.
- Collaterals are used for quote verification and TCB evaluation.

### TDINFO self-checks and policy binding

The former `verify_own_tdinfo()` startup check required `MROWNER` to equal the
SHA-384 hash of the policy issuer's leaf public key and `MROWNERCONFIG` to contain
`policySvn` as a little-endian u32 followed by 44 zero bytes. Those equalities
are intentionally no longer required for policy v2.

The full, unmasked `tdinfo_hash` includes `MROWNER` and `MROWNERCONFIG`.
Authentication requires this hash to match an authenticated JSON or CoRIM
TCB mapping, whose signer is bound to the RTMR1-measured trust anchor.
That endorsement already authorizes the exact owner-field values together
with the rest of TDINFO. Under this model, the former equality checks add
no further authorization; they only impose legacy encodings on fields
already covered by the endorsement.

Signer identity and purpose are bound by the RTMR1 anchor (root certificate,
leaf Subject DN, and dedicated EKU),
while canonical policy data, including `policySvn`, is measured in RTMR2.
Quote/TDREPORT, event-log, collateral-signature, and signer-anchor verification
establish these bindings during authentication. The authenticated full-TDINFO mapping
supplies the MigTD release `isvsvn`, which is distinct from `policySvn`.
This model applies equally to PEM and direct-anchor/CoRIM enrollment, without
requiring a rotating leaf key's fingerprint in a TD-creation field.

Changing either owner field changes the hash that must be endorsed.
The endorsement binds the actual values; it does not assert the former
owner-field equalities.

### Direct signer-anchor enrollment

The signer anchor binds the root certificate, the leaf's full Subject
Distinguished Name (the certificate's Subject), and its dedicated signer
purpose. EKU supplements the Subject DN binding; it does not replace it.

```text
tag = "MIGTD-RTMR1-ANCHOR"
R   = SHA384(DER(root certificate))
DN  = SHA384(DER(leaf Subject Distinguished Name))
A   = SHA384(tag || 0x00 || R || 0x00 || DN || 0x00 || DER(EKU OID))
```

The full Subject DN is bound byte-for-byte in DER form, without textual name
normalization. The event-log writer hashes `A` and extends RTMR1 with `SHA384(A)`.

The signing authority must keep the Subject DN DER stable and reserve that
Subject DN and selected dedicated EKU under the enrolled root for the intended
signer.

Key and intermediate-CA rotation preserve the anchor only when the root, leaf
Subject DN, and selected dedicated EKU remain unchanged. PEM enrollment
requires a single dedicated leaf EKU. CoRIM anchor-first verification can select
the matching purpose among multiple dedicated EKUs, while preserving the same
Subject DN binding. JSON peer-chain checks use the same root, Subject DN,
and dedicated EKU identity. Certificate-chain, revocation, and SVN-policy checks
remain separate and are not replaced by the anchor.

Anchor producers, enrollment tools, firmware, and offline hash calculation
use this same formula. Generate the anchor before building the image, then
endorse the image's complete TDINFO hash.

Earlier anchor profiles, including the root/EKU-only formula and the
`MIGTD-RTMR1-ANCHOR-V2` formula, produce different anchors,
RTMR1 values, and complete TDINFO hashes. Regenerate enrolled anchors
and TDINFO endorsements together when upgrading; there is no fallback
to an earlier formula.

`--signer-anchor FILE` accepts exactly 48 raw bytes, not a hexadecimal string
or a PEM chain. Checking its length is not authentication. JSON/CoRIM
verification must reproduce the enrolled value from the endorsement signer.
PEM enrollment derives the same anchor from the supplied chain.
If both `--signer-anchor` and `--policy-issuer-chain` are supplied, the anchor
is enrolled in RTMR1 and the PEM chain is enrolled separately to verify the
standalone JSON mapping. MigTD requires the chain-derived anchor to match the
directly enrolled anchor.

For the JSON path, supply the signed mapping and policy issuer chain separately:

```sh
cargo image --policy-v2 \
  --policy policy.json \
  --policy-issuer-chain policy_issuer_chain.pem \
  --servtd-tcb-mapping tcb_mapping_signed.json
```

JSON and CoRIM mappings are mutually exclusive. Both use the unmeasured
`MIGTD_SERVTD_TCB_MAPPING_FFS_GUID` slot
(`8073AC3C-7D49-4DA9-9B20-4DC1D1DB3CFB`); the build selects the mapping verifier.
New CoRIM images use this common GUID instead of the former CoRIM-only GUID,
so build them with matching updated firmware and enrollment tools.

Without JSON collateral, supply the signed CoRIM and retain the mandatory CRL
at `policyData.servtdCrl`:

```sh
cargo image --policy-v2 \
  --policy corim_policy.json \
  --signer-anchor signer-anchor.bin \
  --servtd-corim servtd_tcb_mapping.corim
```

The image builder checks these enrollment combinations and required artifact
presence before building. MigTD still authenticates signatures, signer-anchor
bindings, and the numbered CRL at runtime.

Pre-session data uses one signed-mapping TLV item (type 3) for either JSON or
CoRIM, selected by the build. This preserves the existing CoRIM wire encoding.
The format-specific verifier authenticates the mapping after framing checks.

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

Use the previous signed cumulative mapping for this first build, or a signed
provisional mapping for the first release. Its bytes do not affect RTMR2; the
current release's hash is added and the mapping re-signed below.

```sh
cargo image --policy-v2 \
 --policy config/templates/policy_v2_signed.json \
 --policy-issuer-chain key/migtd_issuer_chain.pem \
 --servtd-tcb-mapping config/templates/tcb_mapping_signed.json
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
 --output-servtd-info-hash target/release/expected_servtd_info_hash.txt \
 --mapping-isvsvn <release-svn> \
 --update-tcb-mapping config/templates/tcb_mapping.json
```

### Sign the cumulative mapping and rebuild the policy
```sh
bash sh_script/build_policy_v2.sh preprod \
 config/templates/tcb_mapping.json config/templates/td_identity_signed.json \
 /path/to/servtd_signers.crl.pem
```

The updater preserves every historical hash, rejects attempts to reassign an
existing hash or lower the SVN for a new release, and sorts entries
deterministically before signing. Release revocation uses the servTD leaf
signer CRL; individual hash mappings are never removed.
### Rebuild migtd with new policy
```sh
cargo image --policy-v2 \
 --policy config/templates/policy_v2_signed.json \
 --policy-issuer-chain key/migtd_issuer_chain.pem \
 --servtd-tcb-mapping config/templates/tcb_mapping_signed.json
```

Require the rebuilt image to retain the recorded release hash. Do not publish
the image or mapping if this comparison fails:

```sh
./target/debug/migtd-hash --manifest config/servtd_info.json \
 --image target/release/migtd.bin --policy-v2 \
 --output-servtd-info-hash target/release/final_servtd_info_hash.txt
cmp --silent target/release/expected_servtd_info_hash.txt target/release/final_servtd_info_hash.txt \
 || { echo "Final image no longer matches its TDINFO endorsement" >&2; exit 1; }
```

## Summary Flow

1. Platform collaterals -> `collateral_*.json`
2. Sign the ServTD identity and cumulative TCB mapping; keep the mapping separate from `servtd_collateral.json`
3. Generate policy data -> package it as `policy_v2_signed.json` without an outer signature
4. Build the image with measured policy data and signer anchor
5. Record its servTD info hash and update the cumulative mapping
6. Re-sign only the mapping, preserving every measured input
7. Rebuild and require the final servTD info hash to equal the recorded value
