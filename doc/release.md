# MigTD Release Flow

## Release version semantics

1. Always use `v<major>.<minor>.<patch>`.
2. Please refer to https://semver.org/.

## Release content

1. github branch `v<major>.<minor>`.
2. A release directory, including below content.
   * Release build image, without debug message.
   * Release build MigTD:TEE_INFO_HASH
   * Debug build image, with debug message to virtual serial port.
   * Debug build MigTD:TEE_INFO_HASH
   * Release notes, including
     * major tested features
     * critical bug fixes and known issues.
     * configuration, the version of
       * EMR SOC
       * IFWI, MCHECK
       * TDX-module
       * Host Hypervisor: KVM, QEMU
       * Guest OS: Linux kernel, initrd
       * Attestation: Attestation library, DCAP
     * launch script
       * Source migtd launch parameter
       * Destination migtd launch parameter
   * cargo.lock file to lock the rust crate dependency version.

## Release Step:

1. Unit test on latest main branch.
2. Create tag `v<major>.<minor>.<patch>-rc`.
3. Release test on the Release Candidate. (by validation engineer)
4. Fix issues if found.
5. Create branch `v<major>.<minor>`.
6. Upload the release content to branch `v<major>.<minor>`.

## Release Test Feature:

1. Migration Flow
2. Attestation flow
