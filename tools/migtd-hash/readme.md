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

### Note

For a `TDVF_SECTION` with `Attributes` set to `0x00000001` (indicating `PAGE.ADD + MR.EXTEND`), the measurement process is performed on a page-by-page basis for the entire section. For each individual page within that section, a `TDCALL[TDH.MEM.PAGE.ADD]` is executed, followed immediately by a `TDCALL[TDH.MR.EXTEND]`:

```
  for page in section {
    call TDCALL[TDH.MEM.PAGE.ADD]
    call TDCALL[TDH.MR.EXTEND]
  }
```

The `MRTD` calculation logic in this tool is aligned with the implementation in the Linux KVM: https://github.com/torvalds/linux/blob/v6.16/arch/x86/kvm/vmx/tdx.c#L3153-L3288.
