## migtd-collateral-generator tool

This tool can be used to fetch the platform TCB and enclave information from provisioning certification service (PCS) and generate the migtd collaterals.

### How to build

```
pushd tools/migtd-collateral-generator
cargo build
popd
```

### How to use

- Help 
  ```
  ./target/debug/migtd-collateral-generator -h
  ```

- Generate migtd collaterals for production platforms:
  ```
  ./target/debug/migtd-collateral-generator -o config/collateral_production_fmspc.bin
  ```

- Generate migtd collaterals for pre-production platforms:
  ```
  ./target/debug/migtd-collateral-generator -o config/collateral_pre_production_fmspc.bin --pre-production
  ```
