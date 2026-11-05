## servtd-collateral-generator tool

This tool generates measured servTD collateral from a CA-signed servTD CRL.
A signed servTD identity and its issuer chain are optional. The signed TCB
mapping remains a separate, unmeasured artifact.

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
  ./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --servtd-crl /path/to/servtd_signers.crl.pem -o servtd_collateral.json
  ```

Supply the standalone mapping and policy issuer chain when building or running
MigTD. MigTD verifies that the chain resolves to the enrolled RTMR1 signer
anchor: root certificate DER, full leaf Subject DN DER, and dedicated EKU.
See the [anchor contract](../../doc/policy_v2.md#direct-signer-anchor-enrollment).

For SVN-only collateral, omit both `--identity` and `--identity-chain`. When an
identity is supplied, its separate chain remains required and is not replaced
by the mapping chain.

### CRL requirements

`--servtd-crl` is required. All v2 policies must include a valid CA-signed PEM CRL
with a CRL-number extension. When nothing is revoked,
supply a signed CRL with an empty revocation list, not an empty file.

The CRL-issuing CA must be present in the separately supplied mapping-signer
chain and, when identity is supplied, its identity-signer chain. Verification
fails closed if a signer chain lacks that CA or cannot authenticate the CRL.

MigTD uses its local policy's CRL to check peer signers. Missing or invalid CRLs
are rejected during policy verification; a peer-provided CRL is not a substitute
for the local CRL. Existing v2 policies without a CRL must be regenerated. See the
[policy v2 guide](../../doc/policy_v2.md) for configuring the
`servtd.crl.servtdCrlNum` floor.