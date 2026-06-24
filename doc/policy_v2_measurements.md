# MigTD Policy v2 — MRTD / RTMR Measurements (`build-igvm-get-quote`)

This document summarizes exactly **what is measured into `MRTD` and `RTMR0`–`RTMR3`**
for a MigTD image produced by the `build-igvm-get-quote` target in
[`sh_script/Azure/Makefile`](../sh_script/Azure/Makefile) — i.e. build with the same features as the regular
**Azure** build (IGVM format) with **Policy v2** and real `GetQuote` attestation.

For each register it describes the measured artifact, *who* measures it
(TDX module, td-shim firmware, or the MigTD runtime), *when*, the hashing
algorithm, and reference / reproduction values.

> The equivalent **non-IGVM (TDVF `.bin`) Linux build** — `cargo image` without
> `--image-format igvm` — is covered in [§7](#7-the-linux-non-igvm-tdvf-bin-build):
> only the **MRTD derivation** differs; **RTMR0–RTMR3 are identical**.

---

## 1. The build target

```make
IGVM_FEATURES_BASE       = vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation
IGVM_FEATURES_GET_QUOTE  = $(IGVM_FEATURES_BASE),igvm-attest

build-igvm-get-quote:
        cargo image --no-default-features --features $(IGVM_FEATURES_GET_QUOTE) ... \
          --image-format igvm --output target/release/migtd.igvm --debug \
          --policy-v2 --policy config/templates/policy_v2_signed.json \
          --policy-issuer-chain config/templates/policy_issuer_chain.pem \
          --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer
```

`generate-hash-get-quote` then runs the reference tool
`migtd-hash --policy-v2 --manifest config/Azure/servtd_info.json` to reproduce the
register values offline (see §6).

### What `--policy-v2` enrolls into the image (CFV)

The build runs `td-shim-enroll` to place two raw files into the **Configuration
Firmware Volume (CFV)** (see `xtask/src/build.rs:267`):

| CFV file (FFS GUID)                                   | Content                          |
| ----------------------------------------------------- | -------------------------------- |
| `0BE92DC3-…-8EEFFD70DE5A` (`MIGTD_POLICY_FFS_GUID`)   | `policy_v2_signed.json`          |
| `3F2FB27A-…-D3EAB39F8AEB` (`MIGTD_POLICY_ISSUER_CHAIN`) | `policy_issuer_chain.pem`      |

> Note: in Policy v2 the **root CA is *not* enrolled** (the `--root-ca` argument is
> ignored — it is only used by the v1 path). The SGX root CA is delivered at runtime
> through the policy *collaterals* instead, so it is **not** measured into any RTMR.

---

## 2. Measurement model

A TDX `TDREPORT.TD_INFO` exposes one static register and four runtime registers,
all **SHA-384 (48 bytes)**:

- **`MRTD`** — build-time measurement of the initial TD memory, finalized by the
  **TDX module** at `TDH.MR.FINALIZE` (before the guest runs). It is *not*
  runtime-extendable.
- **`RTMR0`–`RTMR3`** — runtime registers extended by guest software via
  `TDG.MR.RTMR.EXTEND`. Every extension is also appended to the TDX event log
  (CCEL / `TDEL`) so a verifier can replay it.

**RTMR extend formula** (one event):

```
RTMR_new = SHA384( RTMR_old(48B) || SHA384(event_data) )
```

**Event-log `mr_index` → register** mapping used throughout MigTD
(`src/migtd/src/event_log.rs:164`):

| `mr_index` | 1     | 2     | 3     | 4     |
| ---------- | ----- | ----- | ----- | ----- |
| register   | RTMR0 | RTMR1 | RTMR2 | RTMR3 |

MigTD fills the registers in two stages:

1. **td-shim firmware** runs first and writes only an `EV_SEPARATOR` into RTMR0/RTMR1.
2. **MigTD core** (`main.rs::do_measurements`, gated by the `policy_v2` feature)
   then extends RTMR1 and RTMR2.

---

## 3. Summary

| Register | Measured content (Policy v2)                                              | Measured by        | Stage     |
| -------- | ------------------------------------------------------------------------ | ------------------ | --------- |
| `MRTD`   | Initial TD image: **td-shim BFV** + **MigTD core Payload** page contents, plus the GPAs of all added private pages. (CFV content **excluded**.) | TDX module (static) | TD build  |
| `RTMR0`  | One `EV_SEPARATOR` event (`u32` `0x0000_0000`). Nothing else.             | td-shim firmware   | Boot      |
| `RTMR1`  | `EV_SEPARATOR`, **then the policy issuer chain** (`policy_issuer_chain.pem`). | td-shim, then MigTD | Boot      |
| `RTMR2`  | **The migration policy** (`policy_v2_signed.json`). No root CA in v2.     | MigTD core         | Boot      |
| `RTMR3`  | *Nothing* — stays all-zero.                                              | —                  | —         |

---

## 4. Per-register detail

### MRTD — the MigTD firmware identity

The TDX module measures every private page the VMM adds before launch. The
reference tool reproduces this from the IGVM file
(`TdInfoStruct::build_igvmmrtd`, `deps/td-shim/td-shim-tools/src/tee_info_hash.rs:376`):

- For **each** non-shared page → `TDH.MEM.PAGE.ADD`: the page **GPA** is hashed
  (a 128-byte `"MEM.PAGE.ADD"` + GPA buffer).
- For each **measured** page (not flagged "unmeasured") → `TDH.MR.EXTEND`: the page
  **content** is hashed 256 bytes at a time.

Which sections are content-extended is driven by `config/metadata.json`
(`Attributes = 0x1` ⇒ `PAGE.ADD + MR.EXTEND`):

| Section   | Attributes | In MRTD?                                  |
| --------- | ---------- | ----------------------------------------- |
| `BFV`     | `0x1`      | ✅ GPA **and** content (td-shim firmware)  |
| `Payload` | `0x1`      | ✅ GPA **and** content (MigTD core binary) |
| `CFV`     | `0x0`      | ⚠️ GPA only — **content not extended**     |
| `TempMem` | `0x0`      | GPA only (pre-added zero pages)            |
| `PermMem` | `0x2`      | ❌ not measured (PAGE.AUG — accepted dynamically after launch) |

**Consequence:** `MRTD` is the identity of the td-shim firmware + the MigTD core
code and its fixed memory layout. Because the CFV **content** is excluded, changing
the policy or issuer chain does **not** change `MRTD`.

### RTMR0 — firmware separator only

td-shim calls `create_seperator()`, which extends **RTMR0 and RTMR1** with the
digest of the 4-byte value `0x0000_0000`
(`deps/td-shim/cc-measurement/src/log.rs:58`). For MigTD nothing else reaches RTMR0:

- The TD-HOB is logged into RTMR0 *only if* td-shim consumes one
  (`main.rs:131`). MigTD uses a pre-allocated `PermMem` region and consumes no
  TD-HOB, so this is skipped.
- The payload binary is *not* re-measured into an RTMR (`payload_extend_rtmr` is
  false — the payload is already covered by `MRTD`).

`RTMR0` is therefore a **constant** for every MigTD build:

```
RTMR0 = SHA384( 0x00*48 || SHA384(0x00000000) )
      = 518923B0F955D08DA077C96AABA522B9DECEDE61C599CEA6C41889CFBEA4AE4D50529D96FE4D1AFDAFB65E7F95BF23C4
```

(verified against `config/templates/tcb_mapping.json`).

### RTMR1 — separator + policy issuer chain

After the firmware separator, the MigTD core measures the **policy issuer chain**
read from the CFV (`get_policy_issuer_chain_and_measure`, `src/migtd/src/bin/migtd/main.rs:312`)
into `mr_index = 2` (RTMR1), tagged `POLICY_ISSUER_CHAIN`:

```
RTMR1 = SHA384( RTMR0_separator(48B) || SHA384(policy_issuer_chain.pem) )
```

This step exists **only** under the `policy_v2` feature.

### RTMR2 — migration policy

The MigTD core measures the **migration policy** read from the CFV
(`get_policy_and_measure`, `src/migtd/src/bin/migtd/main.rs:262`) into
`mr_index = 3` (RTMR2), tagged `POLICY`. RTMR2 starts from zero (no separator):

```
RTMR2 = SHA384( 0x00*48 || SHA384(policy_v2_signed.json) )
```

> The bytes **extended** are the full signed policy file. The event-log *payload*
> for this entry is just the policy SVN/version string, but the RTMR digest is over
> the whole policy.
> In Policy v1 the root CA would also be extended into RTMR2; in v2 it is not.

### RTMR3 — unused

No MigTD measurement targets `mr_index = 4`. `RTMR3` remains all-zero
(`00…00`) in the normal Policy v2 flow.
(The `test_disable_ra_and_accept_all` debug feature is **not** part of this target.)

---

## 5. Reference values for this target

`RTMR0` is constant. `RTMR1`/`RTMR2` depend on the exact bytes of the enrolled
files, so they are shown here as reproduced from the current
`config/templates/*` artifacts (regenerate whenever the policy or issuer chain
changes):

| Register | Value                                                                                              |
| -------- | -------------------------------------------------------------------------------------------------- |
| `RTMR0`  | `518923B0F955D08DA077C96AABA522B9DECEDE61C599CEA6C41889CFBEA4AE4D50529D96FE4D1AFDAFB65E7F95BF23C4` |
| `RTMR1`  | `279EB652F7D7B7D15EA1E593B29EEEB20C6AFD33BE432C66A7B237107A00F5276919AEF490A8DC000886552F79748B0F` |
| `RTMR2`  | `07AF01E95CEFCDC4885A5DC5C5BB1CBE05913FD9486BCD1141C195C3C399939D5127F9E0D5F2F0E09D62B571B562EC36` |
| `RTMR3`  | `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` |
| `MRTD`   | build-specific (measures the firmware image; e.g. `E2C7DA7C…` in the committed template).          |

> ⚠️ The `rtmr0`/`rtmr1` placeholders committed in `config/templates/tcb_mapping.json`
> are both `518923B0…`. That is only the firmware-separator stage; the live
> `RTMR1` of a Policy v2 TD additionally includes the issuer chain (as shown above)
> and is what `TdTcbMapping::get_engine_svn_by_report` compares against the TDREPORT
> (`src/policy/src/v2/servtd_collateral.rs:192`). Regenerate the mapping with
> `migtd-hash --policy-v2` before signing a deployable policy.

The non-register `TD_INFO` fields (`ATTRIBUTES`, `XFAM`, `MRCONFIGID`, `MROWNER`,
`MROWNERCONFIG`) come from the manifest `config/Azure/servtd_info.json`, not from
the measured registers.

---

## 6. Reproducing the values

```sh
# Build the image (writes target/release/migtd.igvm)
make -C sh_script/Azure build-igvm-get-quote

# Print MRTD + RTMR0..3 from the image and CFV
cargo run -p migtd-hash -- \
  --image target/release/migtd.igvm \
  --manifest config/Azure/servtd_info.json \
  --policy-v2 --verbose
```

The tool's `build_td_info` (`tools/migtd-hash/src/lib.rs:37`) implements exactly the
flow above: `build_igvmmrtd` (MRTD), `build_rtmr_with_seperator(0)` (RTMR0/RTMR1
seed), then `rtmr1()` (+ issuer chain) and `rtmr2()` (policy) for Policy v2.

---

## 7. The Linux non-IGVM (TDVF `.bin`) build

The standard Linux / KVM build produces a **TDVF flat image** `target/release/migtd.bin`
instead of an IGVM file — `cargo image` defaults to `--image-format tdvf`
(`xtask/src/build.rs:19,439`):

```sh
# Non-IGVM build (default format = tdvf) -> target/release/migtd.bin
cargo image --policy-v2 \
  --policy config/templates/policy_v2_signed.json \
  --policy-issuer-chain config/templates/policy_issuer_chain.pem

# Reproduce MRTD + RTMR0..3 (the .bin extension auto-selects the TDVF path)
cargo hash --image target/release/migtd.bin --policy-v2
```

(`cargo image` / `cargo hash` are aliases for `xtask image` / `xtask hash`;
`hash` supports the same `--policy-v2` flag — `xtask/src/servtd_info_hash.rs:50`.)

### What changes vs the IGVM build

| Register      | TDVF `.bin` build                                                                                                   | Same value as IGVM?                    |
| ------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `MRTD`        | Derived by `TdInfoStruct::build_mrtd` — walks the OVMF GUID table / TDVF metadata in the 16 MB image and replays `TDH.MEM.PAGE.ADD` / `TDH.MR.EXTEND` per `config/metadata.json` | **Derivation differs** — see below     |
| `RTMR0`       | separator only                                                                                                      | ✅ identical (`518923B0…`)              |
| `RTMR1`       | separator + policy issuer chain                                                                                      | ✅ identical (same `policy_issuer_chain.pem`) |
| `RTMR2`       | policy                                                                                                               | ✅ identical (same `policy_v2_signed.json`)   |
| `RTMR3`       | all-zero                                                                                                             | ✅ identical                            |

- **RTMR0–RTMR3 are unchanged.** The firmware separator, the runtime
  `do_measurements` flow, and the CFV content (policy + issuer chain, enrolled
  identically by `td-shim-enroll`) are all image-format-independent. In the `.bin`
  the CFV is simply the first `TD_SHIM_CONFIG_SIZE` bytes, which the reference tool
  reads directly instead of de-duplicating IGVM pages
  (`tools/migtd-hash/src/lib.rs:66`). So the §5 values for RTMR0–RTMR3 apply
  verbatim to the non-IGVM build.
- **MRTD is the only difference — and it is structural, not content.** For a given
  feature set the BFV (td-shim) and Payload (MigTD core) are the *same compiled
  binaries* in both formats; only `td-shim-ld -i <format>` (`xtask/src/build.rs:246`)
  packages them differently. `MRTD` is a single SHA-384 over an **ordered** stream of
  per-page `TDH.MEM.PAGE.ADD` / `TDH.MR.EXTEND` records (each carries the page GPA,
  and for extended pages the 256-byte content). The two formats feed that stream in a
  **different order**:
  - TDVF `build_mrtd` replays `config/metadata.json` sections in order:
    **BFV → Payload → CFV → TempMem**.
  - IGVM `build_igvmmrtd` replays the linker's `PageData` directives, emitted as
    **CFV → mailbox → temp-stack → temp-heap → Payload → BFV**
    (`deps/td-shim/td-shim-tools/src/linker.rs:429`, `build_igvm`).

  BFV is measured *first* under TDVF but *last* under IGVM, so even with byte-identical
  firmware/payload content and identical GPAs the two digests differ. `build_td_info`
  selects the algorithm from the file extension (`tools/migtd-hash/src/lib.rs:56`).
  Always derive `MRTD` from the exact image you deploy.

> There is no `build-igvm-get-quote` equivalent for `.bin` in `sh_script/Azure/Makefile`
> (that Makefile is IGVM-only). Use `cargo image --policy-v2 …` as shown above, or
> the general build helpers under `sh_script/` (e.g. `build_final.sh`).

---

## 8. Design note: why the MigTD core is in MRTD, not RTMR1

A common assumption (true for *generic* td-shim / TDVF images) is: **MRTD measures
only the firmware, then the firmware loads the payload and extends it into RTMR1.**
**This is *not* how MigTD is configured** — for MigTD the core (Payload) is part of
`MRTD`, and td-shim does **not** extend any RTMR with it.

### What MigTD does

`config/metadata.json` marks **both** firmware and core sections with the `MR.EXTEND`
attribute `0x1`, so the **VMM / TDX module** measures both into `MRTD` via
`TDH.MEM.PAGE.ADD` + `TDH.MR.EXTEND` during TD build — *before* td-shim runs and
finalizes at `TDH.MR.FINALIZE`. (MRTD is produced by the host/TDX module, not by
td-shim; td-shim is itself one of the measured payloads, and so is the migtd core.)

| Section                | `Attributes` | Lands in |
| ---------------------- | ------------ | -------- |
| `BFV` (td-shim)        | `0x1`        | `MRTD`   |
| `Payload` (MigTD core) | `0x1`        | `MRTD`   |

### Why td-shim does not extend RTMR1 with the payload

td-shim *supports* the "measure payload into RTMR1" behaviour —
`log_payload_binary()` extends the payload blob into `mr_index = 2` → **RTMR1**
(`deps/td-shim/td-shim/src/event_log.rs:76`; `mr_index 2 → RTMR1` via
`deps/td-shim/td-shim/src/bin/td-shim/td/tdx.rs:53`). But it is **gated** on the
payload *not* already being in MRTD (`deps/td-shim/td-shim/src/bin/td-shim/shim_info.rs:91`):

```rust
// payload_extend_rtmr is true ONLY when the Payload section is not measured into MRTD
if section.r#type == TDX_METADATA_SECTION_TYPE_PAYLOAD && section.attributes == 0 {
    payload_extend_rtmr = true;
}
```

MigTD's Payload attribute is `0x1` (not `0`), so `payload_extend_rtmr()` is **false**
and the RTMR1 extension is **skipped** — preventing the core from being measured
twice (`src/migtd/src/bin/migtd/main.rs` boot flow calls `log_payload_binary` only
under this flag).

### Rationale

1. **MigTD ships as one fixed image.** Firmware + core are bundled into a single
   `migtd.bin` / `migtd.igvm`, fully known at build time and placed in guest memory
   by the VMM before launch. Measuring the whole image into `MRTD` yields one
   **static identity** for the complete MigTD.
2. **The RTMR1-payload model is for *separately-loaded* payloads.** The generic
   td-shim path exists when the payload is a distinct, variable artifact loaded at
   boot (e.g. a Linux kernel) and therefore absent from the launch image — it *must*
   then be measured dynamically into an RTMR. MigTD has no such separation.
3. **It matches ServTD binding.** A user TD binds to MigTD by its measurement
   (`SERVTD_HASH` derived from `TD_INFO`); a static `MRTD` that already pins the exact
   core is the natural, immutable anchor, independent of runtime ordering.
4. **No double-counting.** The attribute gate guarantees the core is measured into
   exactly one register (`MRTD`), never both.

**Net:** for MigTD, `MRTD` = td-shim (BFV) **+** migtd core (Payload); `RTMR1` =
firmware separator (+ policy issuer chain at runtime under Policy v2). The core is
**never** in `RTMR1`.

---

## 9. Experimental evidence: MRTD covers the MigTD core

To confirm that the MigTD core (the `Payload` section) really is part of `MRTD` — and
that it is *not* in any RTMR — each image was built **twice** with a single
optimization-proof change to the core, and the registers were compared. The
experiment was run for **both** image formats: the standard KVM TDVF `.bin` build and
the regular Azure IGVM Policy v2 build (`build-igvm-get-quote`).

**Environment** (both experiments)

- Commit: `intel/main` @ `e29440454028ea5eab6180e21f521cb9d32e5db6` (clean tree; `HEAD == intel/main`)
- Toolchain: Rust `1.88.0`

**The change** — identical for both — in the MigTD core,
`src/migtd/src/bin/migtd/main.rs`:

```diff
 fn basic_info() {
+    core::hint::black_box(0xA5A5_5A5A_DEAD_BEEFu64); // temporary marker, reverted after
     info!("MigTD Version - {}\n", MIGTD_VERSION);
 }
```

`core::hint::black_box` forces the constant into the compiled payload, so the core
binary differs by a few bytes while nothing else (firmware, CFV, layout) changes.
**A** = baseline (clean), **B** = with the change, **C** = change reverted.

### 9.1 Standard KVM build (TDVF `.bin`)

- Build: `cargo image` → `target/release/migtd.bin`
- Measure: `cargo run -p migtd-hash -- --image target/release/migtd.bin --manifest config/servtd_info.json --output-td-info <out>.json`

| Build | MRTD                                                                                               |
| ----- | -------------------------------------------------------------------------------------------------- |
| **A** | `560703c6259a4efebf5dc13de6220e0ab2b2b85a838a441a38b0bc6971908d0211a4d0a0398fa440c7310cc5803f37d8` |
| **B** | `71956de175eca87f8b958a8ac283ea8bc45bbd638ecfe0d51818ad8989261912ad2f4eec3aac6974a48ebea14683beaf` |
| **C** | `560703c6259a4efebf5dc13de6220e0ab2b2b85a838a441a38b0bc6971908d0211a4d0a0398fa440c7310cc5803f37d8` |

RTMRs — **identical** across A, B, C (this default build is the **v1** image, so
`rtmr1` is the separator only and `rtmr2` carries policy + root CA):

```
rtmr0 = 518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4
rtmr1 = 518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4
rtmr2 = 00738709463174735612b421f112c600a153ad659d54c1ffdfe58967904996a1ef1ed7d130acbee7ea861b70c15454f3
rtmr3 = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

### 9.2 Regular Azure build (IGVM, Policy v2) — `build-igvm-get-quote`

- Build: `make -C sh_script/Azure build-igvm-get-quote` → `target/release/migtd.igvm`
- Measure: `cargo run -p migtd-hash -- --image target/release/migtd.igvm --manifest config/Azure/servtd_info.json --policy-v2 --output-td-info <out>.json`

| Build | MRTD                                                                                               |
| ----- | -------------------------------------------------------------------------------------------------- |
| **A** | `582f87da119c826a56af55891450f8e26627114929b137d66b60d951f0b0297fca81421d3818f720852257e790ed5a76` |
| **B** | `c359d539c5e758f6a28b973bc11d2014bc327103a808c699917c2fafe7dc9cd994c1cac7d25a602ec30817a1915bc4b1` |
| **C** | `582f87da119c826a56af55891450f8e26627114929b137d66b60d951f0b0297fca81421d3818f720852257e790ed5a76` |

RTMRs — **identical** across A, B, C. This is the **Policy v2** image, so `rtmr1`
carries the issuer chain and `rtmr2` the policy — and these match the reference values
computed in §5:

```
rtmr0 = 518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4
rtmr1 = 279eb652f7d7b7d15ea1e593b29eeeb20c6afd33be432c66a7b237107a00f5276919aef490a8dc000886552f79748b0f
rtmr2 = 07af01e95cefcdc4885a5dc5c5bb1cbe05913fd9486bcd1141c195c3c399939d5127f9e0d5f2f0e09d62b571b562ec36
rtmr3 = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

### Conclusion (both builds)

- **A ≠ B** — a one-line change to the MigTD core changes `MRTD` ⇒ **`MRTD` covers the
  MigTD core (Payload)**, not just the td-shim firmware. Holds for the TDVF *and* the
  Azure IGVM Policy v2 image.
- **RTMR0–3 unchanged between A and B** ⇒ the core is **not** measured into any RTMR —
  the firmware does not extend the payload into RTMR1 (confirming §8).
- **A == C** — reverting restores the exact baseline `MRTD`, confirming the build is
  deterministic and the difference was caused solely by the core change.
- The two formats yield **different** `MRTD` baselines (§7); note the `.bin` build here
  is release+v1 and the IGVM build is debug+v2, so their absolute `MRTD` values are not
  directly comparable — each experiment is self-contained (same format, A vs B).

---

## 10. Source references

| Concern                       | Location                                                       |
| ----------------------------- | -------------------------------------------------------------- |
| Build target / CFV enrollment | `sh_script/Azure/Makefile`, `xtask/src/build.rs:267`           |
| MRTD (IGVM) computation       | `deps/td-shim/td-shim-tools/src/tee_info_hash.rs:376`          |
| MRTD (TDVF `.bin`) computation | `deps/td-shim/td-shim-tools/src/tee_info_hash.rs:196`         |
| IGVM page emission order      | `deps/td-shim/td-shim-tools/src/linker.rs:429` (`build_igvm`)  |
| RTMR0/RTMR1 separator         | `deps/td-shim/cc-measurement/src/log.rs:58`                    |
| Reference RTMR1/RTMR2 build   | `tools/migtd-hash/src/lib.rs:123` (`rtmr1`/`rtmr2`)            |
| MRTD format selection         | `tools/migtd-hash/src/lib.rs:56` (`build_td_info`)             |
| Runtime measurement flow      | `src/migtd/src/bin/migtd/main.rs:184` (`do_measurements`, v2)  |
| Core in MRTD (Payload attr)   | `config/metadata.json` (`Payload` `Attributes 0x1`)           |
| Payload→RTMR1 gate            | `deps/td-shim/td-shim/src/bin/td-shim/shim_info.rs:91` (`payload_extend_rtmr`) |
| Payload→RTMR1 extension       | `deps/td-shim/td-shim/src/event_log.rs:76` (`log_payload_binary`) |
| `mr_index` → RTMR mapping      | `src/migtd/src/event_log.rs:164` (`extend_rtmr`)              |
| TCB-mapping comparison        | `src/policy/src/v2/servtd_collateral.rs:192`                   |
