# Migration TD Security Test
## Static Code Scan
| Tool         |
| ------------ |
| cargo-clippy |
| Prusti       |
| MIRAI        |

Refer to https://github.com/confidential-containers/td-shim/blob/main/doc/static_analyzer.md.

## Vulnerable Crate Scan
| Tool       |
| ---------- |
| cargo-deny |

Refer to https://github.com/confidential-containers/td-shim/blob/main/doc/cargo-deny.md.

## Fuzzing Test
| Evaluation Area              | Detailed Test Description                                 | Test Case Url                                                                       |
| ---------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Virtio Devices               | Use AFL to fuzz VirtioPci and VirtioVsock devices.        | [vritio](../src/devices/virtio/fuzz/) & [virtio-vsock](../src/devices/virtio/fuzz/) |
| Migration Policy             | Use AFL & Libfuzzer to fuzz policy related area.          | [policy](../src/policy/fuzz/)                                                       |
| X509 Certificate             | Use AFL & Libfuzzer to fuzz x509 parser.                  | [x509](../src/crypto/fuzz/)                                                         |
| GHCI - VmcallServiceResponse | Use AFL & Libfuzzer to fuzz service response data parser. | [service response](../src/migtd/fuzz/)                                              |

Refer to https://github.com/confidential-containers/td-shim/blob/main/doc/fuzzing.md.

## Secure Code Review
| Evaluation Area              | Detailed Test Description                                                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Virtio Devices               | Virtio devices are external input for MigTD, so it should have sanity check before using it. Data should be copied to privated memory before it been accessed |
| GHCI - VmcallServiceResponse | VMCALL result is from VMM is not trusted, so it should be copied to privated memory before it been accessed and should have sanity check before using it .    |
| Migration Policy             | Migration policy is external input for MigTD, so it should be measured and have sanity check before using it.                                                 |
| X509 Certificate             | Parse and validate untrusted certificate chains before use. Policy-v2 mapping signers must match the measured signer anchor; the complete chain is not measured. |

For the [signer-anchor contract](policy_v2.md#direct-signer-anchor-enrollment),
cover unchanged anchors and successful authentication after leaf-key or unbound
certificate metadata changes. Changes to root certificate DER, full Subject DN
DER, or dedicated EKU must not retain the same authority. Reject anchors with
missing or extra identity components. Chain signatures, issuer-CA constraints,
and authoritative CRL checks remain mandatory.