// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use crypto::{hash::digest_sha384, SHA384_DIGEST_SIZE};
use tdx_tdcall::tdx::{tdcall_servtd_rd, tdcall_vm_write};

use crate::migration::MigrationResult;

/// SERVTD_EXT_STRUCT fields in target TD’s TDCS
pub const TDCS_FIELD_SERVTD_INIT_SERVTD_INFO_HASH: u64 = 0x191000030000020E;
pub const TDCS_FIELD_SERVTD_INIT_ATTR: u64 = 0x191000030000020D;
pub const TDCS_FIELD_INIT_CPUSVN: u64 = 0x1110000300000060;
pub const TDCS_FIELD_INIT_TEE_TCB_SVN: u64 = 0x1110000300000062;
pub const TDCS_FIELD_INIT_TEE_MODEL: u64 = 0x1110000200000064;
/// SERVTD_EXT_STRUCT fields in Service TDs Binding Table Entry in target TD’s TDCS
pub const TDCS_FIELD_SERVTD_INFO_HASH: u64 = 0x1910000300000207;
pub const TDCS_FIELD_SERVTD_ATTR: u64 = 0x1910000300000202;

/// Hash of SERVTD_EXT that the new Service TD 0 (i.e., rebound Service TD or MigTD on the
/// destination platform) believes is the SERVTD_EXT for this TD.
pub const TDCS_FIELD_SERVTD_ACCEPT_SERVTD_EXT_HASH: u64 = 0x1910000300000214;
const TDCS_FIELD_WRITE_MASK: u64 = u64::MAX;

/// Hardcoded expected SERVTD_ATTR value.
///
/// Per MigTD Design Guide: "SERVTD_ATTR is written by untrusted VMM. In order
/// to ensure VMM writes a right value, the MigTD MUST verify
/// TDG.SERVTD.RD(CURR_SERVTD_ATTR) matching a hardcoded value in the MigTD
/// reflecting the intended SERVTD_ATTR."
///
/// Bits 15:0  = SERVTD_TYPE (0 = MigTD)
/// Bits 40:32 = IGNORE flags for SERVTD_HASH computation
pub const EXPECTED_SERVTD_ATTR: u64 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServtdExt {
    pub init_servtd_info_hash: [u8; 48],
    pub init_attr: [u8; 8],
    reserved: [u8; 8],
    pub init_cpusvn: [u8; 16],
    pub init_tee_tcb_svn: [u8; 16],
    pub init_tee_model: [u8; 12],
    reserved1: [u8; 4],
    pub cur_servtd_info_hash: [u8; 48],
    pub cur_servtd_attr: [u8; 8],
    reserved2: [u8; 104],
}

impl ServtdExt {
    pub fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<ServtdExt>() {
            return None;
        }

        let mut uninit = MaybeUninit::<ServtdExt>::uninit();
        // SAFETY: `MaybeUninit<T>` has same memory layout with T.
        Some(unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                uninit.as_mut_ptr() as *mut u8,
                core::mem::size_of::<ServtdExt>(),
            );
            uninit.assume_init()
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }

    pub fn calculate_approved_servtd_ext_hash(mut self) -> Result<Vec<u8>, MigrationResult> {
        self.cur_servtd_attr.fill(0);
        self.cur_servtd_info_hash.fill(0);
        digest_sha384(self.as_bytes()).map_err(|_| MigrationResult::InvalidParameter)
    }
}

#[repr(C)]
pub struct TeeModel {
    custom: u16,
    platform_id: u16,
    fm: u32,
    reservtd: [u8; 8],
}

pub fn read_servtd_ext(
    binding_handle: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdExt, MigrationResult> {
    let read_field =
        |field_base: u64, elem_size: usize, buf: &mut [u8]| -> Result<(), MigrationResult> {
            for (idx, chunk) in buf.chunks_mut(elem_size).enumerate() {
                let result =
                    tdcall_servtd_rd(binding_handle, field_base + idx as u64, target_td_uuid)?;
                let bytes = result.content.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }

            Ok(())
        };

    let mut init_servtd_info_hash = [0u8; 48];
    let mut init_attr = [0u8; 8];
    let mut init_cpusvn = [0u8; 16];
    let mut init_tee_tcb_svn = [0u8; 16];
    let mut init_tee_model = [0u8; 12];
    let mut cur_servtd_info_hash = [0u8; 48];
    let mut cur_servtd_attr = [0u8; 8];

    read_field(
        TDCS_FIELD_SERVTD_INIT_SERVTD_INFO_HASH,
        8,
        &mut init_servtd_info_hash,
    )?;
    read_field(TDCS_FIELD_SERVTD_INIT_ATTR, 8, &mut init_attr)?;
    read_field(TDCS_FIELD_INIT_CPUSVN, 8, &mut init_cpusvn)?;
    read_field(TDCS_FIELD_INIT_TEE_TCB_SVN, 8, &mut init_tee_tcb_svn)?;
    read_field(TDCS_FIELD_INIT_TEE_MODEL, 4, &mut init_tee_model)?;
    read_field(TDCS_FIELD_SERVTD_INFO_HASH, 8, &mut cur_servtd_info_hash)?;
    read_field(TDCS_FIELD_SERVTD_ATTR, 8, &mut cur_servtd_attr)?;

    // Verify CURR_SERVTD_ATTR matches the hardcoded expected value.
    let actual_attr = u64::from_le_bytes(cur_servtd_attr);
    if actual_attr != EXPECTED_SERVTD_ATTR {
        log::error!(
            "SERVTD_ATTR mismatch vs hardcoded: expected {EXPECTED_SERVTD_ATTR:#x}, got {actual_attr:#x}"
        );
        return Err(MigrationResult::InvalidParameter);
    }

    Ok(ServtdExt {
        init_servtd_info_hash,
        init_attr,
        init_cpusvn,
        init_tee_tcb_svn,
        init_tee_model,
        reserved1: [0u8; 4],
        cur_servtd_info_hash,
        cur_servtd_attr,
        reserved: [0u8; 8],
        reserved2: [0u8; 104],
    })
}

/// Verify that CURR_SERVTD_ATTR of the target TD (VMM input) matches the
/// hardcoded expected value (MigTD internal).
///
/// Per GHCI 1.5: Both source and destination MigTDs must verify this before
/// any TDG.SERVTD.WR operations (mig_dec_key, mig_version).
pub fn verify_servtd_attr(
    binding_handle: u64,
    target_td_uuid: &[u64],
) -> Result<(), MigrationResult> {
    let result = tdcall_servtd_rd(binding_handle, TDCS_FIELD_SERVTD_ATTR, target_td_uuid)?;
    let actual_attr = result.content;
    if actual_attr != EXPECTED_SERVTD_ATTR {
        log::error!(
            "SERVTD_ATTR mismatch: VMM wrote {actual_attr:#x}, MigTD expects {EXPECTED_SERVTD_ATTR:#x}"
        );
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(())
}

/// Extract the SERVTD_EXT carried in the leaf certificate of an RA-TLS peer.
///
/// Must only be called on an established session, i.e. after the peer certificate
/// (including its SERVTD_EXT extension) has been authenticated during the handshake.
#[cfg(all(feature = "main", not(feature = "spdm_attestation")))]
pub fn get_servtd_ext_from_cert(certs: &Option<Vec<&[u8]>>) -> Result<ServtdExt, MigrationResult> {
    use crate::ratls::{find_extension, EXTNID_MIGTD_SERVTD_EXT};
    use crypto::x509::{Certificate, Decode};

    if let Some(cert_chain) = certs {
        if cert_chain.is_empty() {
            return Err(MigrationResult::SecureSessionError);
        }

        let cert = Certificate::from_der(cert_chain[0])
            .map_err(|_| MigrationResult::SecureSessionError)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(MigrationResult::SecureSessionError)?;

        let servtd_ext = find_extension(extensions, &EXTNID_MIGTD_SERVTD_EXT)
            .ok_or(MigrationResult::SecureSessionError)?;

        ServtdExt::read_from_bytes(servtd_ext).ok_or(MigrationResult::InvalidParameter)
    } else {
        Err(MigrationResult::SecureSessionError)
    }
}

pub fn write_approved_servtd_ext_hash(servtd_ext_hash: &[u8]) -> Result<(), MigrationResult> {
    if servtd_ext_hash.len() != SHA384_DIGEST_SIZE {
        return Err(MigrationResult::InvalidParameter);
    }

    for (idx, chunk) in servtd_ext_hash.chunks_exact(size_of::<u64>()).enumerate() {
        let elem = u64::from_le_bytes(chunk.try_into().unwrap());
        tdcall_vm_write(
            TDCS_FIELD_SERVTD_ACCEPT_SERVTD_EXT_HASH + idx as u64,
            elem,
            TDCS_FIELD_WRITE_MASK,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::ServtdExt;

    #[test]
    fn test_structure_sizes() {
        assert_eq!(size_of::<ServtdExt>(), 272)
    }

    #[cfg(all(feature = "main", not(feature = "spdm_attestation")))]
    mod cert {
        use super::super::get_servtd_ext_from_cert;
        use super::ServtdExt;
        use crate::migration::MigrationResult;
        use crate::ratls::{EXTNID_MIGTD_SERVTD_EXT, ID_EC_SIG_OID};
        use alloc::vec::Vec;
        use crypto::x509::{AlgorithmIdentifier, CertificateBuilder, Encode, Extension};

        fn build_cert(servtd_ext: Option<&[u8]>) -> Vec<u8> {
            let alg = || AlgorithmIdentifier {
                algorithm: ID_EC_SIG_OID,
                parameters: None,
            };
            let mut builder = CertificateBuilder::new(alg(), alg(), &[0u8; 4]).unwrap();
            if let Some(ext) = servtd_ext {
                builder = builder
                    .add_extension(
                        Extension::new(EXTNID_MIGTD_SERVTD_EXT, Some(false), Some(ext)).unwrap(),
                    )
                    .unwrap();
            }
            builder.build().to_der().unwrap()
        }

        #[test]
        fn extracts_servtd_ext_from_leaf_cert() {
            let ext: Vec<u8> = (0..size_of::<ServtdExt>()).map(|i| i as u8).collect();
            let cert = build_cert(Some(&ext));
            let other = build_cert(None);

            let parsed = get_servtd_ext_from_cert(&Some(vec![&cert[..], &other[..]])).unwrap();
            assert_eq!(parsed.as_bytes(), &ext[..]);
        }

        #[test]
        fn rejects_missing_or_empty_chain() {
            assert_eq!(
                get_servtd_ext_from_cert(&None).err(),
                Some(MigrationResult::SecureSessionError)
            );
            assert_eq!(
                get_servtd_ext_from_cert(&Some(Vec::new())).err(),
                Some(MigrationResult::SecureSessionError)
            );
        }

        #[test]
        fn rejects_malformed_cert() {
            assert_eq!(
                get_servtd_ext_from_cert(&Some(vec![&[0xde, 0xad, 0xbe, 0xef][..]])).err(),
                Some(MigrationResult::SecureSessionError)
            );
        }

        #[test]
        fn rejects_cert_without_servtd_ext() {
            let cert = build_cert(None);
            assert_eq!(
                get_servtd_ext_from_cert(&Some(vec![&cert[..]])).err(),
                Some(MigrationResult::SecureSessionError)
            );
        }

        #[test]
        fn rejects_truncated_servtd_ext() {
            let cert = build_cert(Some(&[0u8; 16]));
            assert_eq!(
                get_servtd_ext_from_cert(&Some(vec![&cert[..]])).err(),
                Some(MigrationResult::InvalidParameter)
            );
        }
    }
}
