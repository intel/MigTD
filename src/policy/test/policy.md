# Test Policy File Usage List
| File Name                            | Usage                                                                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| [policy.json](./policy.json)         | Default policy file                                                                                           |
| [policy_no.json](./policy_no.json)   | No "Digest.MigTdPolicy" and "Digest.MigTdCore"                                                                |
| [policy_001.json](./policy_001.json) | Test RTMR1 different with policy_no.json, no "Digest.MigTdPolicy" in "EventLog" and no "RTMR1" in "TDINFO"    |
| [policy_002.json](./policy_002.json) | Test RTMR1 different with policy_no.json, no "Digest.MigTdPolicy" in "EventLog", contain "RTMR1"  in "TDINFO" |
| [policy_003.json](./policy_003.json) | Test "Digest.MigTdPolicy" with different policy files                                                         |
| [policy_004.json](./policy_004.json) | Test secure boot, check svn whether in 13...                                                                  |
| [policy_005.json](./policy_005.json) | Invalid json                                                                                                  |
| [policy_006.json](./policy_006.json) | Test operator 'greater or equal' with Digest.MigTdCoreSvn                                                     |