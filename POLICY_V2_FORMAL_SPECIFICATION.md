# MigTD Policy v2 Formal Specification

**Document Version:** 1.0  
**Date:** January 2026  
**Status:** Draft  
**Scope:** Complete formal specification of MigTD Policy v2 syntax, semantics, enforcement rules, and limitations

---

## 1. Introduction

This document provides a comprehensive formal specification for the MigTD Policy v2 system. MigTD Policy v2 is a declarative JSON-based policy framework for managing and enforcing Trusted Computing Base (TCB) evaluation rules during CVM migration in Intel's MigTD system.

### 1.1 Purpose

The policy system enables:
- Attestation collateral management (X.509 certificates, CRL data)
- TCB state tracking and validation
- Platform-specific configuration constraints
- Forward and backward platform/MigTD compatibility checks
- ServTD identity and measurement tracking

### 1.2 Key Concepts

- **Policy Data**: The core policy JSON containing evaluation rules
- **Collaterals**: Intel platform attestation collaterals (TCB info, CRL, certificates)
- **ServTD Collateral**: MigTD attestation collaterals
- **Policy Evaluation Info**: Runtime data extracted from quotes/reports for policy evaluation
- **Policy SVN**: Monotonically increasing policy version number

---

## 2. JSON Structure and Syntax

### 2.1 Top-Level Policy Document Structure

```json
{
  "policyData": { /* PolicyData object */ },
  "signature": "hex_string"
}
```

**Field Definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policyData` | Object | Yes | The raw policy data (JSON string converted to object) |
| `signature` | String | Yes | Hex-encoded signature of policyData, verified against policy issuer chain |

### 2.2 PolicyData Object Structure

```json
{
  "id": "uuid_string",
  "version": "2.0",
  "policySvn": 1,
  "policy": [/* PolicyTypes array */],
  "forwardPolicy": [/* PolicyTypes array */],
  "backwardPolicy": [/* PolicyTypes array */],
  "collaterals": { /* Collaterals object */ },
  "servtdCollateral": { /* ServtdCollateral object */ }
}
```

**Field Definitions:**

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `id` | String | Yes | Non-empty UUID | Unique identifier for this policy instance |
| `version` | String | Yes | Must be "2.0" | Policy format version (validation enforced) |
| `policySvn` | Integer | Yes | $ \geq 0 $ | Policy Security Version Number; must be >= remote policy SVN for acceptance |
| `policy` | Array | No | Array of PolicyTypes | Common policy rules applied to all migration scenarios |
| `forwardPolicy` | Array | No | Array of PolicyTypes | Policy rules for forward evaluation (source evaluates destination) |
| `backwardPolicy` | Array | No | Array of PolicyTypes | Policy rules for backward evaluation (destination evaluates source) |
| `collaterals` | Object | Yes | Valid Collaterals | Intel platform attestation collaterals |
| `servtdCollateral` | Object | Yes | Valid ServtdCollateral | MigTD attestation collaterals |

### 2.3 PolicyTypes Union

```json
{
  "global": { /* GlobalPolicy */ }
}
```
OR
```json
{
  "servtd": { /* ServtdPolicy */ }
}
```

**Variants:**
- `global`: Contains platform and TCB evaluation rules
- `servtd`: Contains ServTD identity evaluation rules (MigTD-specific constraints)

### 2.4 GlobalPolicy Object

```json
{
  "tcb": { /* TcbPolicy */ },
  "platform": { /* PlatformPolicy */ },
  "crl": { /* CrlPolicy */ }
}
```

All fields optional; if present, corresponding evaluation occurs.

#### 2.4.1 TcbPolicy Object

```json
{
  "tcbDate": { /* PolicyProperty */ },
  "tcbStatusAccepted": { /* PolicyProperty */ },
  "tcbEvaluationDataNumber": { /* PolicyProperty */ }
}
```

**Field Semantics:**

| Field | Type | Meaning |
|-------|------|---------|
| `tcbDate` | PolicyProperty | ISO-8601 date of TCB level; evaluated as lexicographic string comparison |
| `tcbStatusAccepted` | PolicyProperty | Status of the TCB level (e.g., "UpToDate", "OutOfDate") |
| `tcbEvaluationDataNumber` | PolicyProperty | Monotonically increasing sequence number changed when Intel updates TCB evaluation data (TCB Info, QE Identity, QVE Identity, TD QE Identity, QTD Identity). Updated synchronously across all SGX/TDX CPU flavors (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE/TD QE/QTD Identity. Allows determination of when one TCB Info/Identity supersedes another. |

#### 2.4.2 PlatformPolicy Object

```json
{
  "fmspc": { /* PolicyProperty */ }
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `fmspc` | PolicyProperty | Intel CPU Family-Model-Stepping-Platform-Custom Identifier (6 bytes, hex-encoded) |

#### 2.4.3 CrlPolicy Object

```json
{
  "pckCrlNum": { /* PolicyProperty */ },
  "rootCaCrlNum": { /* PolicyProperty */ }
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `pckCrlNum` | PolicyProperty | PCK certificate revocation list serial number |
| `rootCaCrlNum` | PolicyProperty | Root CA CRL serial number |

### 2.5 ServtdPolicy Object

```json
{
  "migtdIdentity": {
    "isvsvn": { /* PolicyProperty */ },
    "tcbDate": { /* PolicyProperty */ },
    "tcbStatusAccepted": { /* PolicyProperty */ }
  }
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `isvsvn` | PolicyProperty | MigTD ISV Security Version Number |
| `tcbDate` | PolicyProperty | MigTD TCB issue date |
| `tcbStatusAccepted` | PolicyProperty | MigTD TCB status (restricted to UpToDate/OutOfDate/Revoked) |

### 2.6 PolicyProperty Object

```json
{
  "operation": "operation_string",
  "reference": reference_value
}
```

**Field Definitions:**

| Field | Type | Meaning |
|-------|------|---------|
| `operation` | String | Comparison operator or list operation |
| `reference` | Number\|String\|Array | Value(s) to compare against |

#### 2.6.1 Operations and Reference Types

**For Integer Values (TCB Evaluation Number, ISV SVN, CRL Numbers):**

| Operation | Reference Type | Semantics |
|-----------|---|-----------|
| `equal` | Integer | value == reference |
| `greater-or-equal` | Integer | value >= reference |
| `equal` | String ("self"\|"init") | value == relative_reference |
| `greater-or-equal` | String ("self"\|"init") | value >= relative_reference |
| `in-range` | String "N..M" | value >= N AND value <= M |
| `subset` | Integer Array | value ∈ reference |

**For String Values (Dates, FMSPC, Identifiers):**

| Operation | Reference Type | Semantics |
|-----------|---|-----------|
| `equal` | String | Exact string equality |
| `greater-or-equal` | String | Lexicographic comparison (ISO-8601 dates are sortable) |
| `equal` | String ("self"\|"init") | Compare with relative_reference |
| `greater-or-equal` | String ("self"\|"init") | Lexicographic comparison with relative_reference |
| `allow-list` | String Array | value ∈ reference array |
| `deny-list` | String Array | value ∉ reference array |

**For TCB Status Values:**

| Operation | Reference Type | Semantics |
|-----------|---|-----------|
| `equal` | String (TcbStatus value) | status == reference |
| `greater-or-equal` | String (TcbStatus value) | status >= reference (rank-based) |
| `allow-list` | String Array | status ∈ allowed statuses |
| `deny-list` | String Array | status ∉ denied statuses |

**For ServTD TCB Status Values:**

| Operation | Reference Type | Semantics |
|-----------|---|-----------|
| `allow-list` | String Array | ServtdTcbStatus ∈ reference (always allow-list) |

---

## 3. Data Types and Constraints

### 3.1 TCB Status Enumeration

**For Global (Platform) TCB:**

```
UpToDate
SWHardeningNeeded
ConfigurationNeeded
ConfigurationAndSWHardeningNeeded
OutOfDate
OutOfDateConfigurationNeeded
Revoked
```

**Hardcoded Rank Ordering:**

```
Rank 2: UpToDate == SWHardeningNeeded == OutOfDate (most acceptable)
Rank 1: ConfigurationNeeded == ConfigurationAndSWHardeningNeeded == OutOfDateConfigurationNeeded
Rank 0: Revoked (least acceptable)
```

**Acceptance Rules (hardcoded):**
- Always accept: UpToDate, SWHardeningNeeded, OutOfDate
- Always deny: Revoked
- Conditional: ConfigurationNeeded, ConfigurationAndSWHardeningNeeded, OutOfDateConfigurationNeeded (policy-defined)

**For ServTD (MigTD) TCB:**

```
UpToDate
OutOfDate
Revoked
```

**Hardcoded Rank Ordering:**

```
Rank 2: UpToDate == OutOfDate (most acceptable)
Rank 0: Revoked (least acceptable)
```

**Acceptance Rules (hardcoded):**
- Always accept: UpToDate, OutOfDate
- Always deny: Revoked

### 3.2 Date/Time Format

**ISO-8601 Format (strict):** `YYYY-MM-DDTHH:MM:SSZ`

**Examples:**
- `2022-11-09T00:00:00Z`
- `2025-01-14T12:30:45Z`

**Comparison:** Lexicographic string comparison is semantically correct for ISO-8601 date strings.

### 3.3 Hexadecimal Encoding

**Format:** Uppercase hexadecimal strings without `0x` prefix

**Examples:**
- FMSPC (Family-Model-Stepping-Platform-Custom): `20C06F000000` (6 bytes = 12 hex characters)
- Measurements: `D3E5E4...` (48+ bytes for SHA-384)

### 3.4 Collaterals Structure (Intel Platform Attestation)

```json
{
  "majorVersion": 1,
  "minorVersion": 0,
  "teeType": 129,
  "rootCa": "pem_string",
  "pckCrlIssuerChain": "pem_string",
  "rootCaCrl": "pem_crl_string",
  "pckCrl": "pem_crl_string",
  "platforms": [
    {
      "fmspc": "hex_string",
      "tcbInfoIssuerChain": "pem_string",
      "tcbInfo": "json_string_with_signature"
    }
  ],
  "qeIdentityIssuerChain": "pem_string",
  "qeIdentity": "json_string_with_signature"
}
```

### 3.5 ServTD Collateral Structure (MigTD Attestation)

```json
{
  "servtdIdentity": {
    "tdIdentity": "json_with_signature",
    "servtdIdentityIssuerChain": "pem_string"
  },
  "servtdTcbMapping": {
    "tdTcbMapping": "json_with_signature",
    "servtdTcbMappingIssuerChain": "pem_string"
  }
}
```

---

## 4. Policy Evaluation Semantics

### 4.1 Evaluation Context

**PolicyEvaluationInfo** - Runtime data extracted from attestation quote/report:

```rust
{
  tcb_date: Option<String>,                    // ISO-8601 date from TCB info
  tcb_status: Option<String>,                  // "UpToDate", "OutOfDate", etc.
  tcb_evaluation_number: Option<u32>,          // TCB revision number
  fmspc: Option<[u8; 6]>,                      // Platform identifier
  migtd_isvsvn: Option<u16>,                   // MigTD SVN from identity
  migtd_tcb_status: Option<String>,            // MigTD status
  migtd_tcb_date: Option<String>,              // MigTD TCB date
  pck_crl_num: Option<u32>,                    // CRL version
  root_ca_crl_num: Option<u32>,                // Root CRL version
}
```

### 4.2 Evaluation Flow

**Three policy evaluation paths:**

1. **Common Policy (`policy` block):** Applied in both destination and source side evaluations
2. **Forward Evaluation (`forwardPolicy` block):** Applied when source evaluates destination platform before accepting migration
3. **Backward Evaluation (`backwardPolicy` block):** Applied when destination evaluates source platform before accepting the migrated VM

**Important: Local Policy Resources for Remote Authentication**

For both forward and backward evaluation, the local policy provides two distinct resources for authenticating remote peers:

1. **Local Policy Issuer Certificate Chain:** Used to verify the remote peer's policy signature
2. **Local Policy Collaterals:** Passed to Intel QVL (Quote Verification Library) to:
   - Verify the remote peer's attestation quote
   - Extract platform TCB evaluation info (tcbDate, tcbStatus, tcbEvaluationDataNumber) from QVL supplemental data
3. **Local ServTD Identity/TCB Mapping Issuer Chains:** Used to verify remote peer's ServTD identity and TCB mapping signatures

**Note on ServTD TCB Extraction:** Unlike platform TCB info (which is extracted via QVL using local collaterals), ServTD TCB info (migtd_tcb_date, migtd_tcb_status, migtd_isvsvn) is extracted from the **remote peer's policy** ServTD TCB mapping and identity data after signature verification using local issuer chains.


**Evaluation Logic:**

```
FOR EACH policy block in [policy, forward_policy, backward_policy]:
  FOR EACH policy_type in policy_block:
    IF policy_type is GlobalPolicy:
      evaluate_global_policy(policy_type, evaluation_info, reference_info)
    ELSE IF policy_type is ServtdPolicy:
      evaluate_servtd_policy(policy_type, evaluation_info, reference_info)
    IF ANY evaluation fails:
      RETURN error
  RETURN success
```

### 4.3 Evaluation Context References

**"self" and "init" References:**

- `"self"`: Refers to data from the evaluating endpoint (reference endpoint in policy context)
- `"init"`: Refers to data from the evaluating endpoint (reference endpoint in policy context)
- Must use in context of relative_reference parameter

**Forward Evaluation (source evaluates destination):**
- Current evaluation info: Remote/destination endpoint data
- Relative reference ("self"/"init"): Local/source endpoint data (reference endpoint)

**Backward Evaluation (destination evaluates source):**
- Current evaluation info: Remote/source endpoint data
- Relative reference ("self"/"init"): Local/destination endpoint data (reference endpoint)

### 4.4 SVN Compatibility Check

**Hard-coded enforcement (before policy evaluation):**

```
IF remote_policy.policySvn < local_policy.policySvn:
  RETURN PolicyError::SvnMismatch
```

*Code Reference: [policy.rs lines 343-345](../src/policy/src/v2/policy.rs#L343-L345)*

This ensures policies only update to newer or equal SVNs, never downgrade.

---

## 5. Hardcoded Enforcement Rules

### 5.1 TCB Status Semantics (Immutable)

**Platform TCB Status Hierarchy:**

```
ALWAYS_ALLOW = {
  UpToDate,
  SWHardeningNeeded,
  OutOfDate
}

ALWAYS_DENY = {
  Revoked
}

CONDITIONAL_STATUS = {
  ConfigurationNeeded,
  ConfigurationAndSWHardeningNeeded,
  OutOfDateConfigurationNeeded
}
```

*Code Reference: [policy.rs lines 736-751](../src/policy/src/v2/policy.rs#L736-L751)*

**Logic:**
1. If status ∈ ALWAYS_DENY → deny (return false)
2. If status ∈ ALWAYS_ALLOW → allow (return true)
3. If status ∈ CONDITIONAL_STATUS → check policy rule

**Rationale:**
- UpToDate: Always acceptable (current TCB)
- SWHardeningNeeded: Always acceptable (known state, mitigation available)
- OutOfDate: Always acceptable (timestamp untrusted, assume acceptable)
- Revoked: Never acceptable (security issue)
- Configuration*: Requires policy decision (may require platform changes)

### 5.2 ServTD TCB Status Semantics (Immutable)

```
ALWAYS_ALLOW = {
  UpToDate,
  OutOfDate
}

ALWAYS_DENY = {
  Revoked
}
```

*Code Reference: [policy.rs lines 798-820](../src/policy/src/v2/policy.rs#L798-L820)*

**Logic:**
- If status ∈ ALWAYS_DENY → deny
- If status ∈ ALWAYS_ALLOW → allow
- All other statuses → deny

### 5.3 Policy Validation Rules

**Version Validation:**

```
IF version != "2.0":
  RETURN InvalidPolicy
IF id.is_empty():
  RETURN InvalidPolicy
```

**Collateral Validation:**

```
IF collaterals.teeType != 129 (TDX):
  RETURN InvalidPolicy
IF collaterals.platforms.is_empty():
  RETURN InvalidPolicy
FOR platform in collaterals.platforms:
  IF platform.fmspc.is_empty():
    RETURN InvalidPolicy
```

**ServTD Collateral Validation:**

```
IF servtdCollateral is invalid:
  RETURN InvalidServtdCollateral
```

### 5.4 Signature Verification

**All signatures must be verified against issuer chains:**

1. **Policy Data Signature:**
   - Verify policyData with policy_issuer_chain
   - Certificate chain must be valid
   - Signature must match exactly

2. **ServTD Identity Signature:**
   - Verify tdIdentity with servtdIdentityIssuerChain
   - Certificate chain must be valid

3. **ServTD TCB Mapping Signature:**
   - Verify tdTcbMapping with servtdTcbMappingIssuerChain
   - Certificate chain must be valid

**Failure Mode:**
- ANY signature verification failure → PolicyError::SignatureVerificationFailed

### 5.5 Policy Integrity Verification

**Event Log Verification:**

```
IF check_policy_integrity(policy_bytes, event_log_map):
  sha384(policy_bytes) must match event_log.MigTdPolicy digest
  IF mismatch:
    RETURN PolicyError::PolicyHashMismatch
```

---

## 6. Operational Constraints and Limitations

### 6.1 Array Constraint Limitations

**Current Limitations:**

| Constraint | Limit | Impact |
|-----------|-------|--------|
| Policy blocks per file | Unlimited (practical: ~100) | Large policies may be slow to evaluate |
| Policy properties per block | Unlimited | Evaluation time scales linearly |
| Allow-list entries | Unlimited | FMSPC lists can have 50+ entries |
| Deny-list entries | Unlimited | Rare in practice |
| TCB status values | 7 platform + 3 servtd | Fixed, immutable |

### 6.2 Numeric Type Constraints

**ISV SVN (u16):**
- Range: 0 - 65535
- No negative values

**TCB Evaluation Number (u32):**
- Range: 0 - 4,294,967,295
- Monotonically increasing

**CRL Numbers (u32):**
- Range: 0 - 4,294,967,295
- Must be >= configured minimum

**FMSPC (48-bit Intel CPU Family-Model-Stepping-Platform-Custom):**
- Fixed 6 bytes (12 hex characters)
- No variable length

### 6.3 String Encoding Limitations

**Date Strings:**
- Must be ISO-8601 format
- Timezone must be 'Z' (UTC)
- Seconds precision only (no milliseconds)

**Hex Strings:**
- Must be uppercase or lowercase consistent
- No `0x` prefix allowed
- Even number of characters

**UUIDs:**
- Must be valid RFC 4122 format
- Non-empty requirement

### 6.4 Certificate Chain Limitations

**Issuer Chain Requirements:**

```
Maximum depth: Theoretically unlimited (practical: ~5)
Must include:
  - Root CA (self-signed)
  - Intermediate CAs (optional)
  - Leaf certificate (signing certificate)
  
Each certificate must:
  - Be valid (not expired)
  - Have proper key usage
  - Chain to trusted root
```

### 6.5 Integer Range Constraint in "in-range" Operation

**Format:** `"MIN..MAX"` (two dots, no spaces)

**Constraints:**
- Both MIN and MAX must be valid u32 integers
- MIN must be <= MAX (not enforced, results in always-false evaluation)
- Cannot use negative numbers
- Must parse as decimal integers

**Example:** `"0..1000000"` (inclusive range)

### 6.6 Special Reference Values

**Reserved Keywords:**
- `"self"`: Cannot be used as literal string value
- `"init"`: Cannot be used as literal string value
- Must use in context of relative_reference parameter

### 6.7 ConfigurationNeeded Status Expansion

**Implicit Status Expansion (hardcoded):**

When `allow-list` contains `"ConfigurationNeeded"`:

```
Expand to: {
  ConfigurationNeeded,
  ConfigurationAndSWHardeningNeeded,
  OutOfDateConfigurationNeeded
}
```

*Code Reference: [policy.rs lines 774-779](../src/policy/src/v2/policy.rs#L774-L779)*

**Reason:** These three statuses are semantically equivalent (rank-equal) due to immutable comparison logic. Policy author specifies one; all are implicitly included.

**Important Note:** The `allow-list` for `tcbStatusAccepted` is only meaningful when `"ConfigurationNeeded"` is specified in the list. For all other TCB status values (UpToDate, SWHardeningNeeded, OutOfDate, Revoked), the `allow-list` has no effect because these statuses are already handled by the hardcoded ALWAYS_ALLOW/ALWAYS_DENY rules (lines 731-748).

**Critical Limitation:** If `"ConfigurationAndSWHardeningNeeded"` or `"OutOfDateConfigurationNeeded"` are specified directly in the allow-list without `"ConfigurationNeeded"`, they will be **silently ignored**. These statuses are only honored when `"ConfigurationNeeded"` is specified. Direct specification of these variants has no effect.

---

## 7. Error Handling

### 7.1 Error Types

**PolicyError Enumeration:**

```
InvalidParameter              // Generic validation failure
InvalidPolicy                 // Malformed policy structure
InvalidEventLog               // Event log parsing error
PolicyHashMismatch            // Policy integrity check failed
SignatureVerificationFailed   // Certificate or signature invalid
InvalidQuote                  // Quote format error
TcbEvaluation                 // TCB evaluation failed
SvnMismatch                   // SVN incompatibility
CrlEvaluation                 // CRL validation failed
UnqualifiedMigTdInfo          // MigTD identity validation failed
InvalidReference              // Policy reference not valid for operation
InvalidOperation              // Operation not defined for reference type
HashCalculation               // Hash computation failed
InvalidServtdCollateral       // ServTD collateral invalid
```

### 7.2 Evaluation Failure Semantics

**Policy Evaluation Failures:**

```
IF ANY field required for evaluation is missing:
  RETURN error (not silent failure)

IF ANY comparison fails:
  RETURN error (false indicates policy violation, not missing data)

IF ANY operation is invalid:
  RETURN error (never proceed with evaluation)
```

**No Partial Success:**
- All-or-nothing evaluation semantics
- Single failure causes entire policy to fail

---

## 8. Measurement Tracking and Mapping

### 8.1 MigTD Identity Measurements

**Structure in ServTD Collateral:**

```json
{
  "mrSigner": "hex_string_96",     // MR SIGNER (MigTD identity)
  "isvProdId": 65535,                // ISV Product ID
  "svnMappings": [
    {
      "tdMeasurements": {
        "mrTd": "hex_string_96",     // MR TD measurement
        "rtmr0": "hex_string_96",    // Runtime TMR 0
        "rtmr1": "hex_string_96",    // Runtime TMR 1
        "rtmr2": "hex_string_96",    // Runtime TMR 2
        "rtmr3": "hex_string_96"     // Runtime TMR 3
      },
      "isvsvn": 1                    // SVN for this measurement set
    }
  ]
}
```

### 8.2 Measurement Lookup Algorithm

```
FUNCTION get_engine_svn_by_report(report: Report) -> Option<u16>:
  measurements = extract_measurements_from_report(report)
  measurements = to_ascii_uppercase(measurements)
  
  FOR mapping in svn_mappings:
    IF compare_measurements(mapping.measurements, measurements):
      RETURN Some(mapping.isvsvn)
  
  RETURN None

FUNCTION compare_measurements(policy_meas, report_meas) -> bool:
  RETURN (
    policy_meas.mrTd.uppercase() == report_meas.mrTd.uppercase() AND
    policy_meas.rtmr0.uppercase() == report_meas.rtmr0.uppercase() AND
    policy_meas.rtmr1.uppercase() == report_meas.rtmr1.uppercase() AND
    policy_meas.rtmr2.uppercase() == report_meas.rtmr2.uppercase() AND
    policy_meas.rtmr3.uppercase() == report_meas.rtmr3.uppercase()
  )
```

**Measurement Matching:** Exact string match (case-insensitive) for all 5 measurements

---

## 9. Forward and Backward Evaluation Semantics

### 9.1 Forward Evaluation (Source Evaluates Destination)

**Scenario:** Source host evaluates destination platform before accepting the VM migration

**Authentication Flow:**
1. Source receives destination's quote, event log, and policy
2. Source uses **local policy issuer cert chain** to verify destination's policy signature
3. Source passes **local policy collaterals** to QVL to verify destination's quote and extract **platform** TCB evaluation info
4. Source uses **local ServTD issuer chains** to verify destination's ServTD identity/TCB mapping signatures
5. Source extracts **ServTD** TCB evaluation info (migtd_tcb_date, migtd_tcb_status) from **destination's policy** ServTD TCB mapping data

**Evaluation Context:**
- Current data: Remote/destination endpoint
- Reference data: Local/source endpoint (initial state)
- Reference keyword "self" resolves to: source endpoint data
- Reference keyword "init" resolves to: source endpoint data

**Purpose:** Source evaluates destination platform before accepting the VM migration to ensure destination meets minimum requirements

### 9.2 Backward Evaluation (Destination Evaluates Source)

**Scenario:** Destination evaluates source platform before accepting a VM that came from source

**Authentication Flow:**
1. Destination receives source's quote, event log, and policy
2. Destination uses **local policy issuer cert chain** to verify source's policy signature
3. Destination passes **local policy collaterals** to QVL to verify source's quote and extract **platform** TCB evaluation info
4. Destination uses **local ServTD issuer chains** to verify source's ServTD identity/TCB mapping signatures
5. Destination extracts **ServTD** TCB evaluation info (migtd_tcb_date, migtd_tcb_status) from **source's policy** ServTD TCB mapping data

**Evaluation Context:**
- Current data: Remote/source endpoint
- Reference data: Local/destination endpoint (current state)
- Reference keyword "self" resolves to: destination endpoint data
- Reference keyword "init" resolves to: destination endpoint data

**Purpose:** Destination evaluates source platform constraints before accepting the migrated VM from that source (platform compatibility check)

---

## 10. Example Policies

### 10.1 Strict Policy (Minimal Acceptable TCB)

```json
{
  "policy": [
    {
      "global": {
        "tcb": {
          "tcbDate": {
            "operation": "greater-or-equal",
            "reference": "2022-11-09T00:00:00Z"
          },
          "tcbStatusAccepted": {
            "operation": "allow-list",
            "reference": ["UpToDate"]
          },
          "tcbEvaluationDataNumber": {
            "operation": "greater-or-equal",
            "reference": 5
          }
        }
      }
    }
  ]
}
```

**Effect:** Only allow UpToDate TCB with evaluation number >= 5 from 2022-11-09 onward

### 10.2 Flexible Policy (Allow Configuration Needed)

```json
{
  "policy": [
    {
      "global": {
        "tcb": {
          "tcbStatusAccepted": {
            "operation": "allow-list",
            "reference": [
              "UpToDate",
              "SWHardeningNeeded",
              "ConfigurationNeeded"
            ]
          }
        }
      }
    }
  ]
}
```

**Effect:** Allow UpToDate, SWHardeningNeeded, and all ConfigurationNeeded variants

### 10.3 SVN Dependent Policy

```json
{
  "servtd": {
    "migtdIdentity": {
      "isvsvn": {
        "operation": "greater-or-equal",
        "reference": "self"
      }
    }
  }
}
```

**Effect:** MigTD SVN must be >= remote MigTD SVN (no downgrade)

---

## 11. Extensibility and Future Considerations

### 11.1 Currently Unsupported

- Bitfield operations on ISV SVN
- Complex boolean logic (AND/OR across fields)
- Time-based policies (expiration checks)
- Certificate pinning
- Revocation checking (CRL-based)
- Dynamic policy updates (inline)

### 11.2 Design Limitations

1. **No Conditional Logic:** Policies cannot express "IF A THEN B" constraints
2. **All-or-Nothing Evaluation:** No partial success or warning states
3. **Static Collaterals:** Cannot refresh during policy lifetime
4. **Single Measurement Set:** Only one SVN mapping per FMSPC+date combination supported
5. **No Audit Trail:** Policy evaluation does not log detailed decision reasoning

---

## 12. Normative Definitions

**MUST:** Absolute requirement; violation causes policy failure

**SHOULD:** Recommended; violation may cause unexpected behavior

**MAY:** Optional; implementation specific

**HARDCODED:** Cannot be overridden by policy author

**CONDITIONAL:** Determined by policy author via allow-list/deny-list

---

## 13. References

- Intel TDX Specification
- MigTD Architecture Document (doc/AzCVMEmu.md)
- Policy v2 Usage Guide (doc/policy_v2.md)
- Source Implementation (src/policy/src/v2/)
- Test Cases (src/policy/test/policy_v2/)

---

## 14. Change History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-14 | Initial formal specification |

---

## Appendix A: Complete ABNF Grammar (Informative)

```
policy-document = "{" "policyData" ":" policy-data "," "signature" ":" hex-string "}"

policy-data = "{" 
  "id" ":" uuid ","
  "version" ":" "2.0" ","
  "policySvn" ":" integer ","
  ["policy" ":" policy-array ","]
  ["forwardPolicy" ":" policy-array ","]
  ["backwardPolicy" ":" policy-array ","]
  "collaterals" ":" collaterals ","
  "servtdCollateral" ":" servtd-collateral
"}"

policy-array = "[" (global-policy | servtd-policy) *("," (global-policy | servtd-policy)) "]"

global-policy = "{" "global" ":" "{" [tcb-policy] [platform-policy] [crl-policy] "}" "}"
servtd-policy = "{" "servtd" ":" "{" migtd-identity-policy "}" "}"

policy-property = "{" "operation" ":" operation-string "," "reference" ":" reference-value "}"

operation-string = "equal" | "greater-or-equal" | "in-range" | "subset" | "allow-list" | "deny-list"

reference-value = integer | string | integer-array | string-array

tcb-status = "UpToDate" | "SWHardeningNeeded" | "ConfigurationNeeded" | 
             "ConfigurationAndSWHardeningNeeded" | "OutOfDate" | 
             "OutOfDateConfigurationNeeded" | "Revoked"

servtd-status = "UpToDate" | "OutOfDate" | "Revoked"

iso-8601-date = 4DIGIT "-" 2DIGIT "-" 2DIGIT "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT "Z"

fmspc = 12(HEXDIG)  ; Intel CPU Family-Model-Stepping-Platform-Custom (6 bytes in hex)

uuid = 8HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 12HEXDIG
```

---

## Appendix B: TCB Status Comparison Truth Table

| Status A | Status B | A > B | A == B | A < B |
|----------|----------|-------|--------|-------|
| UpToDate | UpToDate | F | T | F |
| UpToDate | OutOfDate | F | T | F |
| UpToDate | SWHardeningNeeded | F | T | F |
| UpToDate | ConfigurationNeeded | T | F | F |
| UpToDate | Revoked | T | F | F |
| ConfigurationNeeded | SWHardeningNeeded | F | F | T |
| ConfigurationNeeded | ConfigurationAndSWHardeningNeeded | F | T | F |
| SWHardeningNeeded | ConfigurationNeeded | T | F | F |
| Revoked | Any | F | F | T |

---

**End of Document**
