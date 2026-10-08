## servtd-collateral-generator tool

This tool generates servTD collateral from a signed servTD identity, its issuer
chain, a signed TCB mapping, and a CA-signed servTD CRL.

### How to build

```
pushd tools/servtd-collateral-generator
cargo build
popd
```

### How to use

- Help 
  ```
  ./target/debug/servtd-collateral-generator -h
  ```

- Generate collateral for a production policy:
  ```
  ./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --mapping /path/to/tcb_mapping_signed.json --servtd-crl /path/to/servtd_signers.crl.pem -o servtd_collateral.json
  ```

### CRL requirements

`--servtd-crl` is required. All v2 policies must include a valid CA-signed PEM CRL
with a CRL-number extension. When nothing is revoked,
supply a signed CRL with an empty revocation list, not an empty file.

The CRL-issuing CA must be present in both the policy-signer chain, which verifies
the TCB mapping, and the identity-signer chain. Verification fails closed if either
chain lacks that CA or cannot authenticate the CRL.

MigTD uses its local policy's CRL to check peer signers. Missing or invalid CRLs
are rejected during policy verification; a peer-provided CRL is not a substitute
for the local CRL. Existing v2 policies without a CRL must be regenerated. See the
[policy v2 guide](../../doc/policy_v2.md) for configuring the `servtdCrlNum` floor.