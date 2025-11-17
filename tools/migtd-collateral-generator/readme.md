## migtd-collateral-generator tool

This tool can be used to fetch the platform TCB and enclave information from provisioning certification service (PCS) and generate the migtd collaterals.

It supports multiple collateral service providers:
- **Intel PCS** (Production and Pre-production environments)
- **Azure THIM** (Trusted Hardware Identity Management service)

### How to build

```
pushd tools/migtd-collateral-generator
cargo build
popd
```

### How to use

#### Help
  ```
  ./target/debug/migtd-collateral-generator -h
  ```

#### Intel PCS Provider

- Generate migtd collaterals for production TDX-supported platforms:
  ```
  ./target/debug/migtd-collateral-generator -o config/collateral_production_fmspc.json
  ```

- Generate migtd collaterals for pre-production TDX-supported platforms:
  ```
  ./target/debug/migtd-collateral-generator -o config/collateral_pre_production_fmspc.json --pre-production
  ```

#### Azure THIM Provider

- Generate migtd collaterals from Azure THIM:
  ```
  ./target/debug/migtd-collateral-generator --provider azure-thim -o config/collateral_azure_thim.json
  ```

- Generate collaterals from a specific Azure region:
  ```
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region westeurope -o config/collateral_westeurope.json
  ```
