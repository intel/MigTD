## json-signer tool

This tool can be used to sign a JSON file or package it with a provided signature.

### How to build

```
pushd tools/json-signer
cargo build
popd
```

### How to use

- Help 
  ```
  ./target/debug/json-signer -h
  ```

- Sign a migtd policy JSON file:
  ```
  ./target/debug/json-signer --sign  --name policyData --private-key /path/to/pkcs8 --input /path/to/policy.json --output policy_signed.json
  ```

- Package a signature for a migtd policy JSON file:
  ```
  ./target/debug/json-signer --finalize --name policyData --signature /path/to/policy_sig --input /path/to/policy.json --output policy_signed.json
  ```

- Sign a tcb mapping JSON file:
  ```
  ./target/debug/json-signer --sign  --name tdTcbMapping --private-key /path/to/pkcs8 --input /path/to/tcb_mapping.json --output tcb_mapping_signed.json
  ```

- Package a signature for a tcb mapping JSON file:
  ```
  ./target/debug/json-signer --finalize --name tdTcbMapping --signature /path/to/tcb_mapping_sig --input /path/to/tcb_mapping.json --output tcb_mapping_signed.json
  ```

- Sign a servtd identity JSON file:
  ```
  ./target/debug/json-signer --sign  --name tdIdentity --private-key /path/to/pkcs8 --input /path/to/td_identity.json --output td_identity_signed.json
  ```

- Package a signature for a servtd identity JSON file:
  ```
  ./target/debug/json-signer --finalize --name tdIdentity --signature /path/to/tcb_mapping_sig --input /path/to/td_identity.json --output td_identity_signed.json
  ```