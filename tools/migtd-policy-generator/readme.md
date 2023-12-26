## migtd-policy-generator tool

This tool can be used to fetch the platform TCB and enclave information from backend server and generate the migtd policy based on the values.

### How to build

```
pushd tools/migtd-policy-generator
cargo build
popd
```

### How to use

- Help 
  ```
  ./target/debug/migtd-policy-generator -h
  ```

- Generate migtd policy for production platforms:
  ```
  ./target/debug/migtd-policy-generator -o config/policy_production_fmspc.json
  ```

- Generate migtd policy for pre-production platforms:
  ```
  ./target/debug/migtd-policy-generator -o config/policy_pre_production_fmspc.json --pre-production
  ```
