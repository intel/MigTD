## servtd-collateral-generator tool

This tool can be used to generate the servtd collateral with provided servtd identity, servtd tcb mapping and thier issuer chains.

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

- Generate servtd collateral:
  ```
  ./target/debug/servtd-collateral-generator --identity /path/to/td_identity_signed.json --identity-chain /path/to/identity_issuer_chain.pem --mapping /path/to/tcb_mapping_signed.json --mapping-chain /path/to/identity_issuer_chain.pem -o servtd_collateral.json
  ```