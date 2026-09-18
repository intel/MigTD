## migtd-policy-generator tool

This tool can be used to fetch the platform TCB and enclave information from backend server and generate the migtd policy based on the values. It can also package base policy data, ServTD collateral, and platform collaterals into a single JSON file.

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

- Package a v2 policy data without signature:
  ```
  ./target/debug/migtd-policy-generator v2 --policy-data /path/to/policy_data.json --collaterals config/collateral_pre_production_fmspc.json --servtd-collateral /path/to/servtd_collateral.json -o policy_data_full.json
  ```

Omitting `--servtd-collateral` removes any existing `servtdCollateral` from the
input, for use with a separately enrolled CoRIM. A numbered servTD CRL is still
required: `--servtd-crl` takes precedence over an existing top-level `servtdCrl`.
If neither is present, the CRL from the removed collateral is promoted to the top level.
Generation fails if no valid numbered CRL remains. When JSON collateral is
retained, its CRL and any top-level CRL must agree.