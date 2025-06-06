## migtd-hash tool

This tool can calculate SERVTD_INFO_HASH or SERVTD_HASH for MigTD.

### How to build

```
pushd tools/migtd-hash
cargo build
popd
```

### How to use

- Help 
  ```
  ./target/debug/migtd-hash -h
  ```

- Generate migtd SERVTD_INFO_HASH:
  ```
  ./target/debug/migtd-hash --manifest config/servtd_info.json --image <migtd.bin>
  ```

- Generate migtd SERVTD_HASH:
  ```
  ./target/debug/migtd-hash --manifest config/servtd_info.json --image <migtd.bin> --servtd-attr 0 --calc-servtd-hash
  ```
