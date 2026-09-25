# Signed CoRIM emulation fixtures

These **test-only** artifacts endorse the default mock TD report and must not
be used as production trust material. They include an ES384 COSE_Sign1 CoRIM,
its leaf-first issuer chain and independently calculated 48-byte signer anchor,
a numbered empty CRL (7), a CRL revoking the signer (8), and equivalent signed
JSON collateral with optional TD Identity.
The leaf asserts the test-only signer EKU `1.3.6.1.4.1.32473.1.1`. The version-2
anchor binds the root certificate, full Subject Distinguished Name, Subject
Alternative Name presence/value, and that DER-encoded EKU OID. Its independently
calculated formula matches the profile documented in `doc/policy_v2.md`.

Additional genuinely signed CoRIMs cover key rotation and additional EKUs with
unchanged identity, plus rejected changes to the Subject DN, SAN, SAN presence,
and signer purpose. The DN mismatch keeps the same Common Name but changes the
organization; the SAN mismatch keeps the same DNS name but changes a URI.

The chain is leaf -> intermediate -> root. Both CRLs are complete, direct,
issuer-wide CRLs signed by the immediate intermediate with `cRLSign`; they
cover only that CA's signing leaves.

The private keys are generated in memory and are never written or retained.
Certificates and CRLs use a fixed 2020-2120 validity window so fixture tests do
not depend on the current date. CoRIM CWT claims contain no time claims.

To regenerate after changing the default mock report or endorsement profile,
first generate the normal mock-report policies, then run this script in a
Python environment with `cryptography` and `cbor2` installed:

```sh
./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report --skip-test
python3 src/policy/test/policy_v2/corim/generate.py \
  --policy config/AzCVMEmu/policy_v2_signed.json
```

Regeneration replaces this directory's public fixtures together. It does not
modify the existing signer-anchor golden-vector certificates elsewhere.
Normal tests and CI use the checked-in artifacts and do not require these
Python packages.

Prepare a runtime policy using current platform collateral:

```sh
python3 sh_script/prepare_AzCVMEmu_corim_policy.py \
  --base config/AzCVMEmu/policy_v2_signed.json \
  --output target/emu-corim-policy.json
```

Add `--with-identity` to retain the signed JSON mapping and TD Identity. The
generated policies enforce SVN and CRL-number floors, and the identity variant
also requires the expected date/status, so successful emulation exercises
lookup rather than merely loading an unused CoRIM.
