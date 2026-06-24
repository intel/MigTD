TCB Mapping Design for One-Hash Endorsement
===================================================
# Current TCB Mapping inside Policy V2


**Current TCBMapping without full measurement of MigTD and policy in svnMappings**

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Signed Policy Blob                           │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ policyData                                                    │  │
│  │  ├── policy (migration rules)                                 │  │
│  │  ├── collaterals (platform TCB info)                          │  │
│  │  └── servtdCollateral                                         │  │
│  │       ├── servtdIdentity {tdIdentity, signature}              │  │
│  │       └── servtdTcbMapping                                    │  │
│  │            └── svnMappings[]:                                 │  │
│  │                 {[MRTD, RTMR0, RTMR1], isvsvn}                │  │
│  │                  ─────────────────────                        │  │
│  │                  RTMR2, RTMR3 excluded to avoid circularity   │  │
│  └─────────────────────┬─────────────────────────────────────────┘  │
│                        │                                            │
│  signature             │                                            │
└────────────────────────┼────────────────────────────────────────────┘
                         │ entire blob measured into
                         ▼
              ┌─────────────────────┐
              │       RTMR2         │  ← depends on svnMappings content
              └─────────────────────┘    (inside the measured blob)

   Result: svnMappings cannot include RTMR2 without creating a
   circular dependency, so RTMR2 is excluded — leaving the TCB
   mapping unable to fully bind MigTD identity to policy content.
```

Policy v2 bundles `{policy, collaterals, servtdCollateral (signed TCB mapping + signed identity)}` into one signed blob that is measured into RTMR2. This creates a **circular dependency**: binding RTMR2 into `svnMappings` requires RTMR2 to be known before the TCB mapping is generated, yet RTMR2 is computed over policy content that already contains that TCB mapping.

To avoid the cycle, today's `svnMappings` exclude RTMR2 and key only on `[MRTD, RTMR0, RTMR1]`. The signed TCB mapping therefore binds the MigTD code measurement and policy-signer anchor but **not** the policy content measured into RTMR2. This results in two problems described below.


# Problem 1: source MigTD cannot map the init hash to an SVN locally

The source MigTD cannot map `init_servtd_info_hash` (= `SHA384(TDINFO)`) to an SVN directly, so it must accept the full init TDINFO from the untrusted VMM on every request and re-derive the registers after verifying the init TDINFO.

**Init MigTD (rebinding/migration) TCB evaluation - current svnMappings require init TDINFO from VMM:**

```
   VMM / Host OS                          Current MigTD (source)
  ┌─────────────────────┐               ┌──────────────────────────────────┐
  │                     │               │                                  │
  │  TDX Module provides│               │  Needs to determine TCB level    │
  │  init_servtd_info_  │               │  of init MigTD bound to target   │
  │  hash to MigTD      │               │                                  │
  │  (from servtd_ext)  │               │  svnMappings only has:           │
  │  But svnMappings    │               │    {[MRTD, RTMR0, RTMR1], isvsvn}│
  │  uses [MRTD,RTMR0,  │               │                                  │
  │  RTMR1] not full    │               │  Cannot derive [MRTD, RTMR0,     │
  │  tdinfo_hash        │               │  RTMR1] from init_servtd_info_   │
  │                     │               │  hash alone!                     │
  │                     │               │                                  │
  │  ┌───────────────┐  │   per-request │                                  │
  │  │ init TDINFO   │──┼──────────────►│  Verify:                         │
  │  │ (full struct) │  │   VMM carries │   SHA384(TDINFO) ==              │
  │  └───────────────┘  │   untrusted   │   init_servtd_info_hash? ✓       │
  │                     │   input       │                                  │
  │                     │               │  Extract [MRTD, RTMR0, RTMR1]    │
  │                     │               │  from verified TDINFO            │
  │                     │               │          │                       │
  │                     │               │          ▼                       │
  │                     │               │  Look up svnMappings →  isvsvn   │
  └─────────────────────┘               └──────────────────────────────────┘

   Problem: VMM must supply full init TDINFO struct on every migration
   request. MigTD verifies it against init_servtd_info_hash, then
   extracts individual registers to look up SVN. This adds:
   - VMM implementation complexity (carry and supply TDINFO per request)
   - Larger untrusted input surface per migration handshake
```

# Problem 2: attestation service cannot match the info hash to svnMappings

The tenant TD attestation service holds only `init/cur_servtd_info_hash` (hashes over *all* registers) and cannot match them against the subset-keyed `svnMappings`, forcing reliance on separate hash-based endorsements.


**Tenant TD attestation — current svnMappings not useful:**

```
  TD Quote (authenticated by QE signature)
  ┌──────────────────────────────────────────────────────────┐
  │  tdinfo                                                  │
  │   ├── MRTD, RTMR0, RTMR1, RTMR2, RTMR3, ...              │
  │   └── Servtd_hash = SHA384(SERVTD_EXT_STRUCT) ───────┐   │
  └──────────────────────────────────────────────────────┼───┘
                                                         │
   SERVTD_EXT_STRUCT (carried alongside quote)           │
  ┌──────────────────────────────────────────────────┐   │
  │  init_servtd_info_hash  (48 bytes)               │◄──┘ authenticated
  │  init_servtd_attr                                │      by Servtd_hash
  │  cur_servtd_info_hash   (48 bytes)               │
  │  cur_servtd_attr                                 │
  └──────────────┬──────────────────┬────────────────┘
                 │                  │
                 ▼                  ▼
   init_servtd_info_hash      cur_servtd_info_hash
   = SHA384(init TDINFO)      = SHA384(cur TDINFO)
                 │                  │
                 ▼                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    Attestation Service                       │
  │                                                              │
  │  Has: init_servtd_info_hash, cur_servtd_info_hash            │
  │       (single hashes of full TDINFO including ALL registers) │
  │                                                              │
  │  svnMappings provides:                                       │
  │    {[MRTD, RTMR0, RTMR1], isvsvn}                            │
  │     ─────────────────────────────                            │
  │     Incomplete! Missing RTMR2, RTMR3.                        │
  │                                                              │
  │  ✗ Cannot match init/cur_servtd_info_hash against            │
  │    svnMappings — the hash covers ALL registers but           │
  │    svnMappings only lists a subset.                          │
  │                                                              │
  │  ✗ Cannot reconstruct tdinfo_hash from partial registers     │
  │    without knowing RTMR2 (which svnMappings excludes).       │
  │                                                              │
  │  → Must rely on separate endorsements (CoRIM) that           │
  │    directly map tdinfo_hash → SVN, bypassing svnMappings.    │
  └──────────────────────────────────────────────────────────────┘
```

*Note:* `SERVTD_EXT_STRUCT` is constructed by the TDX module at runtime using the tenant's TDCS and is not directly included in the TD report. Its hash, `SHA384(SERVTD_EXT_STRUCT)`, is included as `tdinfo.Servtd_hash`. The structure is read by the host OS and supplied to the Quoting service (QTD/QE), which verifies it against the hash and includes it in the TD Quote. MigTD can also read it from the bound target tenant TD's TDCS and use the hash to verify the tdinfo from VMM.

```rust
struct ServtdExt {
    init_servtd_info_hash: [u8; 48],
    init_servtd_attr: [u8; 8],
    reserved: [u8; 8],
    init_cpusvn: [u8; 16],
    init_tee_tcb_svn: [u8; 16],
    init_tee_model: [u8; 12],
    reserved1: [u8; 4],
    cur_servtd_info_hash: [u8; 48],
    cur_servtd_attr: [u8; 8],
    reserved2: [u8; 104],
}
```

# Proposal


Break policy content into independent measured components so RTMR2 no longer depends on TCB mapping content:

**Measurement register layout** (RTMR extends):

| Register | Before | Proposed |
|----------|--------|----------|
| **RTMR1** | Policy issuer cert chain | TCBMapping issuer cert chain |
| **RTMR2** | Signed policy blob (contains policy rules + collaterals + signed TCB mapping + signed identity) | **Single canonical-bytes extend** of `policyData` with `servtdCollateral.servtdTcbMapping` removed. By construction this binds every other top-level `policyData` field — `version`, `id`, `policySvn`, `policy`, `forwardPolicy`, `backwardPolicy`, `collaterals`, and the rest of `servtdCollateral` (including the issuer-signed `{tdIdentity, signature}` and both issuer chains). See "RTMR2 single redacted extend" below. |

**IGVM CFV file layout** (configuration firmware volume slots loaded at boot):

| CFV slot | Before | Proposed | Measured into |
|----------|--------|----------|---------------|
| `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID` | Policy issuer cert chain | TCBMapping issuer cert chain | **RTMR1** |
| `MIGTD_POLICY_FFS_GUID` | Signed policy with collaterals | Signed policy with collaterals, updated `svnMappings` semantics | **RTMR2** |

With this split:
- RTMR2 = measurement of canonical `policyData` with `servtdCollateral.servtdTcbMapping` redacted — every other field is automatically bound by being inside the canonical object. The redaction is the only escape hatch and permits `servtdTcbMapping` to be re-signed after the IGVM is shipped, preserving circularity-freedom.
- TCB mapping can bind `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)` for attr=0) to SVN without circularity. (See "Schema note" at the end.)
- RTMR1 = measurement of TCB Mapping issuer cert chain instead of policy issuer chain.
- Policy is still signed to keep current file format not changed, but signing is not required as TCBMapping now includes and authenticates the policy measurement.

**New design — full tdinfo hash in svnMappings but unmeasured, removing circular dependency:**

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Signed Policy Blob                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ policyData                                                       │  │
│  │  ├── policy, version, id, policySvn, collaterals, ...            │  │
│  │  └── servtdCollateral                                            │  │
│  │       ├── servtdIdentity {tdIdentity, signature}  ──┐            │  │
│  │       ├── servtdIdentityIssuerChain                 │ measured   │  │
│  │       ├── servtdTcbMappingIssuerChain               │            │  │
│  │       └── servtdTcbMapping ◄────── NOT measured ──┐ │            │  │
│  │            └── svnMappings[]:                     │ │            │  │
│  │                 {tdinfo_hash, isvsvn}             │ │            │  │
│  └───────────────────────────────────────────────────┼─┼────────────┘  │
│  signature  ─────────────────────────────────────────┼─┤               │
└──────────────────────────────────────────────────────┼─┼───────────────┘
                                                       │ │
              RTMR2 = SHA384(canonical(policyData      │ │
                      minus servtdTcbMapping))  ◄──────┘ │
                         │                               │
              ┌──────────┼──────────────────┐            │
              │          ▼                  │            │
              │ tdinfo_hash = SHA384(TDINFO)│            │
              │   MRTD, RTMR0, RTMR1, RTMR2 │            │
              └──────────┬──────────────────┘            │
                         │                               │
                         ▼                               │
              svnMappings[].tdinfo_hash ─────────────────┘
                                          populated AFTER
                                          measurement
                                          (no circularity)

```


# Benefits

- **Breaks the circular dependency** — `tdinfo_hash` is computable from build inputs before the TCB mapping is signed.
- **Problem 1 solved with simpler rebind/migration** — MigTD maps `servtd_ext.init_servtd_info_hash` to an SVN locally; the VMM no longer supplies init TDINFO per request.
- **Problem 2 solved with TCB Mapping reused for attestation** — the service matches `init/cur_servtd_info_hash` directly against `svnMappings`, needing no out-of-band endorsements.

# Design details

## RTMR2 single redacted extend

RTMR2 is extended **once** with the canonical bytes of `policyData` with
`servtdCollateral.servtdTcbMapping` removed. Every other `policyData` field
— including `version`, `id`, `policySvn`, `policy`, `forwardPolicy`,
`backwardPolicy`, `collaterals`, and the rest of `servtdCollateral`
(`majorVersion`, `minorVersion`, the issuer-signed
`{tdIdentity, signature}` object, `servtdIdentityIssuerChain`,
`servtdTcbMappingIssuerChain`) — is bound into RTMR2 by virtue of being
inside the canonical object bytes. The redaction is the only escape hatch
and is what makes `servtdTcbMapping` updateable after the IGVM is shipped.

This single extend folds together two security properties:
detecting drift between the bytes that were signed and the bytes loaded
into the running MigTD (covered by canonicalizing the whole `policyData`
sub-tree), and — whenever `servtdIdentity` is used for policy — defeating
its playback / TCB-downgrade attacks (covered by including
`servtdCollateral.servtdIdentity` in that sub-tree; see below).

**`servtdIdentity` — measured for free, retained for compatibility:**

- `servtdIdentity.tcbLevels` is an optional enrichment layer on top of the `tdinfo_hash → SVN` mapping: it translates a resolved SVN into a `tcbStatus` / `tcbDate`, enabling richer recovery policy (status labels, date thresholds, per-SVN revocation) that pure SVN ordering cannot express. The core identity and anti-downgrade guarantee comes from the TCB mapping and holds with or without it.
- **Initial implementation:** retain `servtdIdentity` unchanged so existing `tcbDate` / `tcbStatus` policies keep working; it is measured into RTMR2 for free by the redacted-`policyData` extend — no extra code, tag, or event-log entry.
- **Must be measured whenever used:** unmeasured, an attacker could boot a peer with an obsolete-but-still-signed `servtdIdentity` and present revoked SVNs as `UpToDate` (playback / downgrade). Measured, a different `servtdIdentity` yields a different `tdinfo_hash` that falls outside the authority's `svnMappings`, so migration fails closed.

**Why include the signature too:**

- Hash scope = **full canonical `policyData` minus `servtdTcbMapping`**, which includes the `{tdIdentity, signature}` object verbatim (canonical bytes, sorted keys, no whitespace).
- Including the signature means that **any** authority re-signing event (even of byte-identical content) changes RTMR2. This is intentional: operators must re-release the MigTD image whenever the issuer re-issues `servtdIdentity`, and `svnMappings[]` for the new image must be re-computed by the authority. This eliminates ambiguity over "which issuance is bound here".

**Why `servtdTcbMapping` is the only redacted field:**

- Measuring it would defeat the entire purpose of the proposal: `servtdTcbMapping` carries `svnMappings[].tdinfo_hash` (which is what `tdinfo_hash` itself derives from), and so binding it back into RTMR2 would re-introduce the circular dependency.
- The redaction is also what enables the authority to re-issue `servtdTcbMapping` (adding/removing `svnMappings[]` entries, bumping `nextUpdate`, etc.) without forcing a new IGVM release. Operators just swap the signed TCB mapping artifact alongside the existing IGVM.

**Why measure by construction:**

- The single redacted-`policyData` extend automatically binds every top-level `policyData` field, including any added in the future, without requiring an explicit whitelist update.
- Both issuer chains are covered for free: `servtdIdentityIssuerChain` and `servtdTcbMappingIssuerChain`. An attacker who could substitute either chain could weaponise it to validate an arbitrary identity or mapping; this scheme rules that out by construction.
- Optional blocks (`forwardPolicy` / `backwardPolicy`) are covered the same way — no separate extend, no separate tag, no separate event-log entry.

**Alternatives considered**

| Scheme | Result | Why chosen / rejected |
|--------|--------|-----------------------|
| **Single canonical extend over `policyData` with `servtdTcbMapping` redacted** *(chosen)* | One RTMR2 extend, one tag, one event-log entry. | Breaks the circular dependency by redacting exactly the field that contains `tdinfo_hash`; binds every other field by construction. |
| **Per-field extends** | N RTMR2 extends, each with own tag and event-log entry. | Requires discipline to add a new extend for every new `policyData` field — easy to forget, silently leaving fields unmeasured. Rejected. |
| **Single extend over raw (non-canonical) bytes** | One extend, no canonicalization. | Brittle: any whitespace or key-order difference between policy generator, CFV, and offline hash tool produces a different digest. Rejected. |
| **Single canonical extend over full `policyData` (no redaction)** | One extend covering `servtdTcbMapping` too. | Re-introduces the circular dependency. Rejected. |

## Build flow

The release artifact is produced in two stages: a build stage that compiles the MigTD binary into a *base IGVM* with a dummy CFV, and a release stage that signs the policy artifacts and enrolls the production bytes into the base IGVM's CFV via `td-shim-enroll` (a byte-level FFS slot replacement — no Rust rebuild).

1. **Build stage — base IGVM.** Compile MigTD and embed a dummy CFV containing the same canonical `policyData` content the final policy will carry, so the single redacted-`policyData` RTMR2 extend matches the final image byte-for-byte. The production signing chain is also enrolled into the `MIGTD_POLICY_ISSUER_CHAIN` CFV slot so RTMR1 already matches the final IGVM. The embedded `servtdIdentity` is signed by an ephemeral build-time key (the build environment has no access to production signing). This yields the base IGVM and a *preview* `tdinfo_hash`.

2. **Release stage — pre-final IGVM (CFV swap).** Re-sign `servtdIdentity` under production signing. Assemble a *pre-final* `policyData` with an empty `servtdTcbMapping` sentinel (the redacted RTMR2 extend ignores this field). Run `td-shim-enroll` to overwrite the CFV slots. Measure the re-enrolled binary to obtain the production `tdinfo_hash`.

3. **Release stage — TCB mapping.** Create `svnMappings: [{tdinfo_hash, isvsvn}]` using the production `tdinfo_hash`, then sign the TCB mapping.

4. **Release stage — final IGVM.** Assemble the final signed policy (now including the signed TCB mapping) and re-run `td-shim-enroll`. Verify its `tdinfo_hash` equals the pre-final value — a CI gate enforcing the "`tcbMapping` is not measured" invariant.

5. **Endorsements.** Compute endorsed `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)`) from the final image. This hash captures policy content (via the single RTMR2 extend).

## Init_servTD verification - how problem 1 solved

With `svnMappings` keyed on the full `tdinfo_hash`, the source MigTD maps `servtd_ext.init_servtd_info_hash` to an SVN entirely from its locally-measured TCB mapping — the VMM no longer supplies the init TDINFO struct per request.

**Init MigTD (rebinding/migration) TCB evaluation — proposed svnMappings need no TDINFO from VMM:**

```
   VMM / Host OS                            Proposed MigTD (source)
  ┌─────────────────────┐               ┌──────────────────────────────────┐
  │                     │               │                                  │
  │  TDX Module provides│               │  Needs to determine TCB level    │
  │  init_servtd_info_  │               │  of init MigTD bound to target   │
  │  hash to MigTD      │               │                                  │
  │  (from servtd_ext)  │               │  svnMappings now keyed on full   │
  │                     │   no per-     │  tdinfo_hash:                    │
  │                     │   request     │    {tdinfo_hash, isvsvn}         │
  │  (no init TDINFO    │   TDINFO      │                                  │
  │   struct needed)    │──────────────►│  Direct lookup:                  │
  │                     │               │   init_servtd_info_hash ==       │
  │                     │               │   svnMappings[].tdinfo_hash?  ✓  │
  │                     │               │          │                       │
  │                     │               │          ▼                       │
  │                     │               │  → isvsvn                        │
  │                     │               │  (no VMM input, no register      │
  │                     │               │   re-derivation)                 │
  └─────────────────────┘               └──────────────────────────────────┘

   Result: MigTD maps init_servtd_info_hash → SVN from its locally-measured
   TCB mapping. The VMM supplies nothing per request, removing the
   untrusted-input surface and VMM implementation complexity.
```


## Attestation verification - how problem 2 solved

The attestation service receives the Tenant TD Quote, which includes for each bound MigTD:

* `init_migtd_hash` ← `servtd_ext.init_servtd_info_hash` — the hash of the MigTD originally bound to the tenant TD.
* `cur_migtd_hash` ← `servtd_ext.cur_servtd_info_hash` — the hash of the currently bound MigTD.

Both values are authenticated by `tdinfo.Servtd_hash` (the `SHA384(SERVTD_EXT_STRUCT)` carried in the quote).

The service consults two signed endorsement artifacts:

1. **Authorization endorsement** (`servtd_info_hash → SVN`) — translates `init_migtd_hash` and `cur_migtd_hash` into `init_migtd_svn` and `cur_migtd_svn`. Cumulative across releases — must include historical entries so past `init_migtd_hash` values still resolve.

2. **Trust / baseline endorsement** — declares the minimum acceptable MigTD SVN. The service evaluates **both** initial and current bound MigTDs against this baseline (`init_migtd_svn >= min_migtd_svn` and `cur_migtd_svn >= min_migtd_svn`). A failure on either fails the attestation — catching both "originally bound to a now-revoked MigTD" and "currently bound to an out-of-date MigTD" cases.

**Proposed tenant TD attestation — self-contained reverse lookup:**

```
  TD Quote (authenticated by QE signature)
  ┌──────────────────────────────────────────────────────────┐
  │  tdinfo                                                  │
  │   └── Servtd_hash = SHA384(SERVTD_EXT_STRUCT) ───────┐   │
  └──────────────────────────────────────────────────────┼───┘
                                                         │
   SERVTD_EXT_STRUCT (carried alongside quote)           │
  ┌──────────────────────────────────────────────────┐   │
  │  init_servtd_info_hash  ─────────────────────┐   │◄──┘ authenticated
  │  cur_servtd_info_hash   ──────────────────┐  │   │      by Servtd_hash
  └───────────────────────────────────────────┼──┼───┘
                                              │  │
                                              ▼  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │                     Attestation Service                           │
  │                                                                   │
  │  Step 1: Authorization endorsement (svnMappings in TCB mapping)   │
  │  ┌─────────────────────────────────────────────────────────────┐  │
  │  │  svnMappings[]:                                             │  │
  │  │    {tdinfo_hash: "abc123...", isvsvn: 3}                    │  │
  │  │    {tdinfo_hash: "def456...", isvsvn: 2}  ← historical      │  │
  │  │    {tdinfo_hash: "ghi789...", isvsvn: 1}  ← historical      │  │
  │  │                                                             │  │
  │  │  ✓ Direct lookup:                                           │  │
  │  │    init_servtd_info_hash == tdinfo_hash? → init_migtd_svn   │  │
  │  │    cur_servtd_info_hash  == tdinfo_hash? → cur_migtd_svn    │  │
  │  └─────────────────────────────────────────────────────────────┘  │
  │                          │                                        │
  │                          ▼                                        │
  │  Step 2: Trust baseline endorsement                               │
  │  ┌─────────────────────────────────────────────────────────────┐  │
  │  │  min_migtd_svn = 2                                          │  │
  │  │                                                             │  │
  │  │  init_migtd_svn >= min_migtd_svn?  (e.g. 3 >= 2 ✓)         │  │
  │  │  cur_migtd_svn  >= min_migtd_svn?  (e.g. 3 >= 2 ✓)         │  │
  │  │                                                             │  │
  │  │  Both pass → attestation succeeds                           │  │
  │  │  Either fails → attestation denied                          │  │
  │  └─────────────────────────────────────────────────────────────┘  │
  └───────────────────────────────────────────────────────────────────┘

   Key improvement: svnMappings now uses tdinfo_hash (= SHA384(full TDINFO))
   as the lookup key. The attestation service matches init/cur_servtd_info_hash
   directly against svnMappings — no out-of-band endorsements needed.
```

This design enables self-contained reverse lookup: the attestation service can derive MigTD identity and trustworthiness entirely from the `tdinfo_hash` → SVN mapping and the trust baseline, without requiring additional out-of-band endorsements.

# Future considerations

These items are out of scope for the circular-dependency fix above but are enabled by it.

## Mig-NRX support

In NRX arch, `SERVTD_EXT.{INIT,CUR}_INFO_HASH` will measure the policy only, so we just need to align the `tdinfo_hash` in svnMappings by redefining it as the hash of the policy only.

## Dropping `servtdIdentity` (pure-SVN policy)

If migration policy is expressed purely as SVN comparisons, `servtdIdentity` can be dropped: the peer's SVN is derived solely from the TCB mapping (`tdinfo_hash → SVN`), independent of `servtdIdentity`. Trade-off: loses the `tcbStatus` / `tcbDate` axes and non-monotonic per-SVN revocation (mark SVN N `Revoked` while keeping N−1), and requires SVN monotonicity ("higher SVN ≥ as trustworthy"); build-specific revocation still works by removing that build's `tdinfo_hash` entry from the mapping.

## Dropping the outer policy signature

Once RTMR2 binds the canonical `policyData` content directly (this proposal), the outer policy-blob signature is redundant for integrity: the hardware-rooted RTMR2 measurement already authenticates the exact bytes loaded into MigTD. A future revision can drop policy signing entirely, removing the policy-signing key and its rotation burden. The issuer signatures on `servtdTcbMapping` and `servtdIdentity` still remain — those artifacts are redacted/updateable and are verified by their own issuer chains, not by RTMR2.

## RTMR1 signer anchor for key rotation

Today RTMR1 measures the full issuer cert chain, so any leaf re-issuance (e.g. routine key rotation) changes RTMR1 — and therefore `tdinfo_hash` — forcing a new `svnMappings` entry and IGVM release per rotation. A future change can measure a stable *signer anchor* instead of the raw chain bytes — e.g. RTMR1 = `SHA384(root-CA identity || leaf subject)` rather than the DER chain — so rotating the leaf key while keeping the same root and subject leaves RTMR1 (and `tdinfo_hash`) unchanged, decoupling key rotation from measurement churn.

# Schema note — flat `tdinfo_hash` vs measurement registers (MRs)

Throughout this document `svnMappings[]` entries are written in the flattened form `{tdinfo_hash, isvsvn}` for readability. In the actual CoRIM/`policyData` schema the measurement is nested under `tdMeasurements` (e.g. `svnMappings[].tdMeasurements.tdinfo_hash`, see `src/policy/src/v2/servtd_collateral.rs`), and `tdMeasurements` is the place that can also carry the individual measurement registers / MRs (`MRTD`, `RTMR0`–`RTMR3`). This proposal keys the mapping on the single composite `tdinfo_hash` (= `SHA384(TDINFO)`, which already folds in all MRs) rather than the per-register subset used today; the implementation should populate `tdMeasurements.tdinfo_hash` accordingly.

# MRTD / RTMR measurements -current implementation

| Register | Measured content (Policy v2)                                              | Measured by        | Stage     |
| -------- | ------------------------------------------------------------------------ | ------------------ | --------- |
| `MRTD`   | Initial TD image: **td-shim BFV** + **MigTD core Payload** page contents, plus the GPAs of all added private pages. (CFV content **excluded**.) | TDX module (static) | TD build  |
| `RTMR0`  | One `EV_SEPARATOR` event (`u32` `0x0000_0000`). Nothing else.             | td-shim firmware   | Boot      |
| `RTMR1`  | `EV_SEPARATOR`, **then the policy issuer chain** (`policy_issuer_chain.pem`). | td-shim, then MigTD | Boot      |
| `RTMR2`  | **The migration policy** (`policy_v2_signed.json`). No root CA in v2.     | MigTD core         | Boot      |
| `RTMR3`  | *Nothing* — stays all-zero.                                              | —                  | —         |

See [policy_v2_measurements.md](./policy_v2_measurements.md) for details.