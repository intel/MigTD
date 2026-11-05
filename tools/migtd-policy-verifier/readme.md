
## migtd-policy-verifier tool

This tool verifies the signed servTD artifacts in policy v2: the optional identity
and the standalone JSON TCB mapping, including their issuer chains and signer
revocation. The outer policy envelope has no signature.

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

- Verify a policy, standalone signed mapping, and issuer chain:
    ```
    ./target/debug/migtd-policy-verifier --policy <path/to/policy_v2_signed.json> --cert-chain <path/to/policy_issuer_chain.pem> --servtd-tcb-mapping <path/to/tcb_mapping_signed.json>
    ```
