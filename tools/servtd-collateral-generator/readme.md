## servtd-collateral-generator tool

This tool generates servTD collateral from a signed TCB mapping, its required
issuer chain, and a CA-signed servTD CRL. A signed servTD identity and its
separate issuer chain are optional.

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
  ./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --mapping /path/to/tcb_mapping_signed.json --mapping-chain /path/to/mapping_issuer_chain.pem --servtd-crl /path/to/servtd_signers.crl.pem -o servtd_collateral.json
  ```

`--mapping-chain` is required even when `--identity-chain` is supplied. The
generator always includes `servtdTcbMappingIssuerChain`; it does not choose an
implicit mapping signer. MigTD verifies that this chain resolves to the enrolled
RTMR1 signer anchor.

For SVN-only collateral, omit both `--identity` and `--identity-chain`. When an
identity is supplied, its separate chain remains required and is not replaced
by the mapping chain.

### CRL requirements

`--servtd-crl` is required. All v2 policies must include a valid CA-signed PEM CRL
with a CRL-number extension. When nothing is revoked,
supply a signed CRL with an empty revocation list, not an empty file.

The CRL-issuing CA must be present in the mapping-signer chain and, when identity
is supplied, its identity-signer chain. Verification fails closed if a supplied
signer chain lacks that CA or cannot authenticate the CRL.

MigTD uses its local policy's CRL to check peer signers. Missing or invalid CRLs
are rejected during policy verification; a peer-provided CRL is not a substitute
for the local CRL. Existing v2 policies without a CRL must be regenerated. See the
[policy v2 guide](../../doc/policy_v2.md) for configuring the `servtdCrlNum` floor.