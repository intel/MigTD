
## migtd-policy-verifier tool

This tool can be used to verify MigTD signed policy files and issuer certificate chains.

### How to build

```
pushd tools/migtd-policy-verifier
cargo build
popd
```

### How to use

- Help
    ```
    ./target/debug/migtd-policy-verifier -h
    ```

- Verify a signed policy and issuer chain:
    ```
    ./target/debug/migtd-policy-verifier --policy <path/to/policy_v2_signed.json> --cert-chain <path/to/policy_issuer_chain.pem>
    ```
