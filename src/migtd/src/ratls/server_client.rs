// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use async_io::{AsyncRead, AsyncWrite};
use crypto::{
    ecdsa::EcdsaPk,
    hash::digest_sha384,
    tls::{SecureChannel, TlsConfig},
    x509::{
        AlgorithmIdentifier, AnyRef, BitStringRef, Certificate, CertificateBuilder, Decode, Encode,
        ExtendedKeyUsage, Extension, Extensions, Tag,
    },
    Error as CryptoError,
};
use tdx_tdcall::tdreport::TdxReport;

use super::*;
use crate::event_log::get_event_log;
#[cfg(feature = "policy_v2")]
use crate::{config::get_policy, migration::servtd_ext::ServtdExt};
use verify::*;

type Result<T> = core::result::Result<T, RatlsError>;

#[cfg(not(feature = "policy_v2"))]
pub fn server<T: AsyncRead + AsyncWrite + Unpin>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().map_err(|e| {
        log::error!("server EcdsaPk::new() failed with error {:?}\n", e);
        e
    })?;
    let (certs, quote) = create_certificate_for_server(&signing_key).map_err(|e| {
        log::error!("server gen_cert() failed with error {:?}\n", e);
        e
    })?;
    let certs = vec![certs];

    // Server verifies certificate of client
    let config = TlsConfig::new(certs, signing_key, verify_client_cert, quote).map_err(|e| {
        log::error!("server TlsConfig::new() failed with error {:?}\n", e);
        e
    })?;

    config.tls_server(stream).map_err(|e| {
        log::error!("server tls_server() failed with error {:?}\n", e);
        e.into()
    })
}

#[cfg(feature = "policy_v2")]
pub fn server<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    remote_policy: Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().map_err(|e| {
        log::error!(
            "server policy_v2 EcdsaPk::new() failed with error {:?}\n",
            e
        );
        e
    })?;
    let (certs, _quote) = create_certificate_for_server(&signing_key).map_err(|e| {
        log::error!("server policy_v2 gen_cert() failed with error {:?}\n", e);
        e
    })?;
    let certs = vec![certs];

    // Server verifies certificate of client
    let config = TlsConfig::new(
        certs,
        signing_key,
        move |cert, quote| verify_client_cert(cert, quote),
        remote_policy,
    )
    .map_err(|e| {
        log::error!(
            "server policy_v2 TlsConfig::new() failed with error {:?}\n",
            e
        );
        e
    })?;
    config.tls_server(stream).map_err(|e| {
        log::error!("server policy_v2 tls_server() failed with error {:?}\n", e);
        e.into()
    })
}

#[cfg(not(feature = "policy_v2"))]
pub fn client<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    #[cfg(feature = "vmcall-raw")] data: &mut Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().map_err(|e| {
        log::error!("client EcdsaPk::new() failed with error {:?}\n", e);
        e
    })?;
    let (certs, quote) = create_certificate_for_client(&signing_key).map_err(|e| {
        log::error!("client gen_cert() failed with error {:?}\n", e);
        e
    })?;
    let certs = vec![certs];

    // Client verifies certificate of server
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, quote).map_err(|e| {
        log::error!("client TlsConfig::new() failed with error {:?}\n", e);
        e
    })?;
    config.tls_client(stream).map_err(|e| {
        #[cfg(feature = "vmcall-raw")]
        data.extend_from_slice(
            &format!(
                "Error: server_client client(): Failure in tls_client() error: {:?}\n",
                e
            )
            .into_bytes(),
        );
        log::error!(
            "server_client client(): Failure in tls_client() error: {:?}\n",
            e
        );
        e.into()
    })
}

#[cfg(feature = "policy_v2")]
pub fn client<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    remote_policy: Vec<u8>,
    #[cfg(feature = "vmcall-raw")] data: &mut Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().map_err(|e| {
        log::error!(
            "client policy_v2 EcdsaPk::new() failed with error {:?}\n",
            e
        );
        e
    })?;
    let (certs, _quote) = create_certificate_for_client(&signing_key).map_err(|e| {
        log::error!("client policy_v2 gen_cert() failed with error {:?}\n", e);
        e
    })?;
    let certs = vec![certs];

    // Client verifies certificate of server
    let config =
        TlsConfig::new(certs, signing_key, verify_server_cert, remote_policy).map_err(|e| {
            log::error!(
                "client policy_v2 TlsConfig::new() failed with error {:?}\n",
                e
            );
            e
        })?;
    config.tls_client(stream).map_err(|e| {
        #[cfg(feature = "vmcall-raw")]
        data.extend_from_slice(
            &format!(
                "Error: client policy_v2 client(): Failure in tls_client() error: {:?}\n",
                e
            )
            .into_bytes(),
        );
        log::error!("client policy_v2 tls_client() failed with error {:?}\n", e);
        e.into()
    })
}

// TLS server for rebinding new
#[cfg(feature = "policy_v2")]
pub fn server_rebinding<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    remote_policy: Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().map_err(|e| {
        log::error!(
            "server rebinding EcdsaPk::new() failed with error {:?}\n",
            e
        );
        e
    })?;
    let certs = create_certificate_for_rebinding_new(&signing_key).map_err(|e| {
        log::error!("server rebinding gen_cert() failed with error {:?}\n", e);
        e
    })?;
    let certs = vec![certs];

    let config = TlsConfig::new(certs, signing_key, verify_rebinding_old_cert, remote_policy)
        .map_err(|e| {
            log::error!(
                "server rebinding TlsConfig::new() failed with error {:?}\n",
                e
            );
            e
        })?;
    config.tls_server(stream).map_err(|e| {
        log::error!("server rebinding tls_server() failed with error {:?}\n", e);
        e.into()
    })
}

// TLS client for rebinding old
#[cfg(feature = "policy_v2")]
pub fn client_rebinding<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    remote_policy: Vec<u8>,
    init_policy_hash: &[u8],
    init_td_report: &[u8],
    init_event_log: &[u8],
    servtd_ext: &ServtdExt,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().map_err(|e| {
        log::error!(
            "server rebinding EcdsaPk::new() failed with error {:?}\n",
            e
        );
        e
    })?;
    let certs = create_certificate_for_rebinding_old(
        &signing_key,
        init_policy_hash,
        init_td_report,
        init_event_log,
        servtd_ext,
    )
    .map_err(|e| {
        log::error!("server rebinding gen_cert() failed with error {:?}\n", e);
        e
    })?;
    let certs = vec![certs];

    let config = TlsConfig::new(certs, signing_key, verify_rebinding_new_cert, remote_policy)
        .map_err(|e| {
            log::error!(
                "server rebinding TlsConfig::new() failed with error {:?}\n",
                e
            );
            e
        })?;
    config.tls_server(stream).map_err(|e| {
        log::error!("server rebinding tls_server() failed with error {:?}\n", e);
        e.into()
    })
}

fn gen_quote(public_key: &[u8]) -> Result<Vec<u8>> {
    let td_report = gen_tdreport(public_key)?;

    attestation::get_quote(td_report.as_bytes()).map_err(|e| {
        log::error!("Failed to get quote from TD report. Error: {:?}\n", e);
        RatlsError::GetQuote
    })
}

pub fn gen_tdreport(public_key: &[u8]) -> Result<TdxReport> {
    let hash = digest_sha384(public_key).map_err(|e| {
        log::error!("Failed to compute SHA384 digest: {:?}\n", e);
        e
    })?;

    // Generate the TD Report that contains the public key hash as nonce
    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());

    tdx_tdcall::tdreport::tdcall_report(&additional_data).map_err(|e| {
        log::error!("Failed to get TD report via tdcall. Error: {:?}\n", e);
        e.into()
    })
}

fn create_certificate_for_server(signing_key: &EcdsaPk) -> Result<(Vec<u8>, Vec<u8>)> {
    let pub_key = signing_key.public_key().map_err(|e| {
        log::error!(
            "gen_cert signing_key.public_key() failed with error {:?}\n",
            e
        );
        e
    })?;
    let quote = gen_quote(&pub_key).map_err(|e| {
        log::error!("gen_cert gen_quote() failed with error {:?}\n", e);
        e
    })?;

    #[cfg(feature = "policy_v2")]
    let policy_hash = {
        let policy = get_policy().ok_or_else(|| {
            log::error!(
                "gen_cert client policy_v2 Failed to get migration policy for policy hash.\n"
            );
            RatlsError::InvalidPolicy
        })?;
        digest_sha384(policy)
    }
    .map_err(|e| {
        log::error!("gen_cert digest_sha384() failed with error {:?}\n", e);
        e
    })?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?.add_extension(
            Extension::new(
                EXTNID_MIGTD_QUOTE_REPORT,
                Some(false),
                Some(quote.as_slice()),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for EXTNID_MIGTD_QUOTE_REPORT failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for EXTNID_MIGTD_QUOTE_REPORT failed with error {:?}\n",
                e
            );
            e
        })?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for policy hash failed with error {:?}.\n",
                e
            );
            e
        })?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok((x509_cert_der, quote))
}

fn create_certificate_for_client(signing_key: &EcdsaPk) -> Result<(Vec<u8>, Vec<u8>)> {
    let pub_key = signing_key.public_key().map_err(|e| {
        log::error!(
            "gen_cert signing_key.public_key() failed with error {:?}\n",
            e
        );
        e
    })?;
    let quote = gen_quote(&pub_key).map_err(|e| {
        log::error!("gen_cert gen_quote() failed with error {:?}\n", e);
        e
    })?;

    #[cfg(feature = "policy_v2")]
    let policy_hash = {
        let policy = get_policy().ok_or_else(|| {
            log::error!(
                "gen_cert client policy_v2 Failed to get migration policy for policy hash.\n"
            );
            RatlsError::InvalidPolicy
        })?;
        digest_sha384(policy)
    }
    .map_err(|e| {
        log::error!("gen_cert digest_sha384() failed with error {:?}\n", e);
        e
    })?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?.add_extension(
            Extension::new(
                EXTNID_MIGTD_QUOTE_REPORT,
                Some(false),
                Some(quote.as_slice()),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for EXTNID_MIGTD_QUOTE_REPORT failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for EXTNID_MIGTD_QUOTE_REPORT failed with error {:?}\n",
                e
            );
            e
        })?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for policy hash failed with error {:?}.\n",
                e
            );
            e
        })?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok((x509_cert_der, quote))
}

#[cfg(feature = "policy_v2")]
fn create_certificate_for_rebinding_old(
    signing_key: &EcdsaPk,
    init_policy_hash: &[u8],
    init_tdreport: &[u8],
    init_event_log: &[u8],
    servtd_ext: &ServtdExt,
) -> Result<Vec<u8>> {
    let pub_key = signing_key.public_key().map_err(|e| {
        log::error!(
            "gen_cert signing_key.public_key() failed with error {:?}\n",
            e
        );
        e
    })?;
    let tdreport = gen_tdreport(&pub_key).map_err(|e| {
        log::error!("gen_cert gen_tdreport() failed with error {:?}\n", e);
        e
    })?;

    let policy = get_policy().ok_or_else(|| {
        log::error!(
            "gen_cert rebinding old policy_v2 Failed to get migration policy for policy hash.\n"
        );
        RatlsError::InvalidPolicy
    })?;
    let policy_hash = digest_sha384(policy).map_err(|e| {
        log::error!("gen_cert digest_sha384() failed with error {:?}\n", e);
        e
    })?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_TDREPORT,
                Some(false),
                Some(tdreport.as_bytes()),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for EXTNID_MIGTD_TDREPORT failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for EXTNID_MIGTD_TDREPORT failed with error {:?}\n",
                e
            );
            e
        })?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for policy hash failed with error {:?}.\n",
                e
            );
            e
        })?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_SERVTD_EXT,
                Some(false),
                Some(servtd_ext.as_bytes()),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for servtd_ext failed with error {:?}.\n",
                e
            );
            e
        })?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_TDREPORT_INIT,
                Some(false),
                Some(&init_tdreport),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for tdreport init failed with error {:?}.\n",
                e
            );
            e
        })?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_EVENT_LOG_INIT,
                Some(false),
                Some(&init_event_log),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for event log init failed with error {:?}.\n",
                e
            );
            e
        })?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_INIT_POLICY_HASH,
                Some(false),
                Some(&init_policy_hash),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for init policy hash failed with error {:?}.\n",
                e
            );
            e
        })?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok(x509_cert_der)
}

#[cfg(feature = "policy_v2")]
fn create_certificate_for_rebinding_new(signing_key: &EcdsaPk) -> Result<Vec<u8>> {
    let pub_key = signing_key.public_key().map_err(|e| {
        log::error!(
            "gen_cert signing_key.public_key() failed with error {:?}\n",
            e
        );
        e
    })?;
    let tdreport = gen_tdreport(&pub_key).map_err(|e| {
        log::error!("gen_cert gen_quote() failed with error {:?}\n", e);
        e
    })?;

    let policy_hash = {
        let policy = get_policy().ok_or_else(|| {
            log::error!(
                "gen_cert rebinding old policy_v2 Failed to get migration policy for policy hash.\n"
            );
            RatlsError::InvalidPolicy
        })?;
        digest_sha384(policy)
    }
    .map_err(|e| {
        log::error!("gen_cert digest_sha384() failed with error {:?}\n", e);
        e
    })?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_TDREPORT,
                Some(false),
                Some(tdreport.as_bytes()),
            )
            .map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for EXTNID_MIGTD_TDREPORT failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for EXTNID_MIGTD_TDREPORT failed with error {:?}\n",
                e
            );
            e
        })?;

    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert policy_v2 add_extension for policy hash failed with error {:?}.\n",
                e
            );
            e
        })?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok(x509_cert_der)
}

fn create_tls_tbs_common<'a>(
    public_key: &'a [u8],
    key_usage: &'a [u8],
    eku: &'a [u8],
) -> Result<CertificateBuilder<'a>> {
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(AnyRef::new(
            Tag::ObjectIdentifier,
            SECP384R1_OID.as_bytes(),
        )?),
    };
    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    let event_log = get_event_log().ok_or_else(|| {
        log::error!("gen_cert get_event_log() failed with error RatlsError::InvalidEventlog.\n");
        RatlsError::InvalidEventlog
    })?;

    let x509_builder = CertificateBuilder::new(sig_alg, algorithm, public_key)
        .map_err(|e| {
            log::error!(
                "gen_cert CertificateBuilder::new failed with error {:?}\n",
                e
            );
            e
        })?
        // 1970-01-01T00:00:00Z
        .set_not_before(core::time::Duration::new(0, 0))
        .map_err(|e| {
            log::error!("gen_cert set_not_before failed with error {:?}\n", e);
            e
        })?
        // 9999-12-31T23:59:59Z
        .set_not_after(core::time::Duration::new(253402300799, 0))
        .map_err(|e| {
            log::error!("gen_cert set_not_after failed with error {:?}\n", e);
            e
        })?
        .add_extension(
            Extension::new(KEY_USAGE_EXTENSION, Some(true), Some(key_usage)).map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for KEY_USAGE_EXTENSION failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for KEY_USAGE_EXTENSION failed with error {:?}\n",
                e
            );
            e
        })?
        .add_extension(
            Extension::new(EXTENDED_KEY_USAGE, Some(false), Some(eku)).map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for EXTENDED_KEY_USAGE failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for EXTENDED_KEY_USAGE failed with error {:?}\n",
                e
            );
            e
        })?
        .add_extension(
            Extension::new(EXTNID_MIGTD_EVENT_LOG, Some(false), Some(event_log)).map_err(|e| {
                log::error!(
                    "gen_cert Extension::new for EXTNID_MIGTD_EVENT_LOG failed with error {:?}\n",
                    e
                );
                e
            })?,
        )
        .map_err(|e| {
            log::error!(
                "gen_cert add_extension for EXTNID_MIGTD_EVENT_LOG failed with error {:?}\n",
                e
            );
            e
        })?;

    Ok(x509_builder)
}

fn sign_tls_tbs(x509_builder: CertificateBuilder, signing_key: &EcdsaPk) -> Result<Vec<u8>> {
    let mut x509_certificate = x509_builder.build();
    let tbs = x509_certificate.tbs_certificate.to_der().map_err(|e| {
        log::error!(
            "gen_cert x509_certificate.tbs_certificate.to_der failed with error {:?}.\n",
            e
        );
        e
    })?;
    let signature = signing_key.sign(&tbs).map_err(|e| {
        log::error!("gen_cert signing_key.sign failed with error {:?}.\n", e);
        e
    })?;
    x509_certificate.set_signature(&signature).map_err(|e| {
        log::error!(
            "gen_cert x509_certificate.set_signature failed with error {:?}.\n",
            e
        );
        e
    })?;

    Ok(x509_certificate.to_der().map_err(|e| {
        log::error!(
            "gen_cert x509_certificate.to_der failed with error {:?}.\n",
            e
        );
        e
    })?)
}

fn create_eku() -> Result<Vec<u8>> {
    Ok(vec![SERVER_AUTH, CLIENT_AUTH, MIGTD_EXTENDED_KEY_USAGE]
        .to_der()
        .map_err(|e| {
            log::error!("gen_cert to_der failed with error {:?}\n", e);
            e
        })?)
}

fn create_key_usage() -> Result<Vec<u8>> {
    Ok(BitStringRef::from_bytes(&[0x80])
        .map_err(|e| {
            log::error!(
                "gen_cert BitStringRef::from_bytes() failed with error {:?}\n",
                e
            );
            e
        })?
        .to_der()
        .map_err(|e| {
            log::error!(
                "gen_cert BitStringRef::to_der() failed with error {:?}\n",
                e
            );
            e
        })?)
}

fn verify_server_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(true, cert, quote)
}

fn verify_client_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(false, cert, quote)
}

#[cfg(not(feature = "test_disable_ra_and_accept_all"))]
mod verify {
    use super::*;
    use crate::mig_policy;

    use alloc::string::ToString;
    use crypto::ecdsa::ecdsa_verify;
    use crypto::{Error as CryptoError, Result as CryptoResult};
    use policy::PolicyError;
    use tdx_tdcall::tdreport::TdxReport;

    #[cfg(not(feature = "policy_v2"))]
    pub fn verify_peer_cert(
        is_client: bool,
        cert: &[u8],
        quote_local: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let verified_report_local = attestation::verify_quote(quote_local).map_err(|e| {
            log::error!("Mutual attestation error {:?}.\n", e);
            CryptoError::TlsVerifyPeerCert(MUTUAL_ATTESTATION_ERROR.to_string())
        })?;
        let cert = Certificate::from_der(cert).map_err(|e| {
            log::error!("Failed to parse certificate from DER. Error: {:?}\n", e);
            CryptoError::ParseCertificate
        })?;
        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;

        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).map_err(|e| {
            log::error!("Failed to check MIGTD EKU: {:?}\n", e);
            e
        })?;
        // Parse out quote report and event log from certificate extensions
        let quote_report =
            find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT).ok_or_else(|| {
                log::error!("Failed to find quote report extension.\n");
                CryptoError::ParseCertificate
            })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;

        if let Ok(verified_report_peer) = attestation::verify_quote(quote_report) {
            verify_signature(&cert, verified_report_peer.as_slice()).map_err(|e| {
                log::error!("Failed to verify signature: {:?}\n", e);
                e
            })?;

            // MigTD-src acts as TLS client
            let policy_check_result = mig_policy::authenticate_policy(
                is_client,
                verified_report_local.as_slice(),
                verified_report_peer.as_slice(),
                event_log,
            );

            if let Err(e) = &policy_check_result {
                log::error!("Policy check failed, below is the detail information:\n");
                log::error!("{:x?}\n", e);
            }

            policy_check_result.map_err(|e| match e {
                PolicyError::InvalidPolicy => {
                    log::error!("Invalid migration policy.\n");
                    CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
                }
                _ => {
                    log::error!("Migration policy unsatisfied.\n");
                    CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
                }
            })
        } else {
            log::error!("Mutual attestation error.\n");
            Err(CryptoError::TlsVerifyPeerCert(
                MUTUAL_ATTESTATION_ERROR.to_string(),
            ))
        }
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_peer_cert(
        is_client: bool,
        cert: &[u8],
        policy: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| {
            log::error!("Failed to parse certificate from DER.\n");
            CryptoError::ParseCertificate
        })?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).map_err(|e| {
            log::error!("Failed to check MIGTD EKU: {:?}\n", e);
            e
        })?;
        // Parse out quote, event log and policy from certificate extensions
        let quote_report =
            find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT).ok_or_else(|| {
                log::error!("Failed to find quote report extension.\n");
                CryptoError::ParseCertificate
            })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find expected policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;

        let exact_policy_hash = digest_sha384(policy)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            log::error!("Invalid migration policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }
        // MigTD-src acts as TLS client
        let policy_check_result =
            mig_policy::authenticate_remote(is_client, quote_report, policy, event_log);

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                log::error!("Invalid migration policy.\n");
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => {
                log::error!("Migration policy unsatisfied.\n");
                CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
            }
        })?;

        verify_signature(&cert, suppl_data.as_slice())
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_rebinding_old_cert(
        cert: &[u8],
        pre_session_data: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| {
            log::error!("Failed to parse certificate from DER.\n");
            CryptoError::ParseCertificate
        })?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).map_err(|e| {
            log::error!("Failed to check MIGTD EKU: {:?}\n", e);
            e
        })?;

        let td_report = find_extension(extensions, &EXTNID_MIGTD_TDREPORT).ok_or_else(|| {
            log::error!("Failed to find tdreport extension.\n");
            CryptoError::ParseCertificate
        })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find expected policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;
        let init_td_report =
            find_extension(extensions, &EXTNID_MIGTD_TDREPORT_INIT).ok_or_else(|| {
                log::error!("Failed to find init tdreport extension.\n");
                CryptoError::ParseCertificate
            })?;
        let init_event_log =
            find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG_INIT).ok_or_else(|| {
                log::error!("Failed to find init event log extension.\n");
                CryptoError::ParseCertificate
            })?;
        let init_policy_hash = find_extension(extensions, &EXTNID_MIGTD_INIT_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find init policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;
        let servtd_ext = find_extension(extensions, &EXTNID_MIGTD_SERVTD_EXT).ok_or_else(|| {
            log::error!("Failed to find servtd ext extension.\n");
            CryptoError::ParseCertificate
        })?;

        let remote_policy_size = u32::from_le_bytes(
            pre_session_data
                .get(..4)
                .ok_or(CryptoError::TlsVerifyPeerCert(
                    INVALID_MIG_POLICY_ERROR.to_string(),
                ))?
                .try_into()
                .unwrap(),
        ) as usize;
        let remote_policy = pre_session_data.get(4..4 + remote_policy_size).ok_or(
            CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string()),
        )?;
        let init_policy_offset = 4 + remote_policy_size;
        let init_policy_size = u32::from_le_bytes(
            pre_session_data
                .get(init_policy_offset..4 + init_policy_offset)
                .ok_or(CryptoError::TlsVerifyPeerCert(
                    INVALID_MIG_POLICY_ERROR.to_string(),
                ))?
                .try_into()
                .unwrap(),
        ) as usize;
        let init_policy = pre_session_data
            .get(init_policy_offset + 4..init_policy_offset + 4 + init_policy_size)
            .ok_or(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ))?;
        let exact_policy_hash = digest_sha384(remote_policy)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            log::error!("Invalid rebinding policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }
        let exact_init_policy_hash = digest_sha384(init_policy)?;
        if init_policy_hash != exact_init_policy_hash.as_slice() {
            log::error!("Invalid init rebinding policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }

        let policy_check_result = mig_policy::authenticate_rebinding_old(
            td_report,
            event_log,
            remote_policy,
            init_policy,
            init_event_log,
            init_td_report,
            servtd_ext,
        );

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                log::error!("Invalid rebinding policy.\n");
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => {
                log::error!("Rebinding policy unsatisfied.\n");
                CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
            }
        })?;

        verify_signature_with_tdreport(&cert, suppl_data.as_slice())
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_rebinding_new_cert(
        cert: &[u8],
        policy: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| {
            log::error!("Failed to parse certificate from DER.\n");
            CryptoError::ParseCertificate
        })?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).map_err(|e| {
            log::error!("Failed to check MIGTD EKU: {:?}\n", e);
            e
        })?;

        let td_report = find_extension(extensions, &EXTNID_MIGTD_TDREPORT).ok_or_else(|| {
            log::error!("Failed to find quote report extension.\n");
            CryptoError::ParseCertificate
        })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find expected policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;

        let exact_policy_hash = digest_sha384(policy)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            log::error!("Invalid migration policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }

        let policy_check_result =
            mig_policy::authenticate_rebinding_new(td_report, event_log, policy);

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                log::error!("Invalid rebinding policy.\n");
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => {
                log::error!("Rebinding policy unsatisfied.\n");
                CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
            }
        })?;

        verify_signature_with_tdreport(&cert, suppl_data.as_slice())
    }

    fn verify_signature(cert: &Certificate, verified_report: &[u8]) -> CryptoResult<()> {
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                log::error!("Failed to get public key bytes from certificate.\n");
                CryptoError::ParseCertificate
            })?;
        let tbs = cert.tbs_certificate.to_der().map_err(|e| {
            log::error!("Failed to get tbs_certificate der: {:?}\n", e);
            e
        })?;
        let signature = cert.signature_value.as_bytes().ok_or_else(|| {
            log::error!("Failed to get signature bytes from certificate.\n");
            CryptoError::ParseCertificate
        })?;
        verify_public_key(verified_report, public_key).map_err(|e| {
            log::error!("Public key verification failed: {:?}\n", e);
            e
        })?;
        ecdsa_verify(public_key, &tbs, signature)
    }

    #[cfg(feature = "policy_v2")]
    fn verify_signature_with_tdreport(cert: &Certificate, tdreport: &[u8]) -> CryptoResult<()> {
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                log::error!("Failed to get public key bytes from certificate.\n");
                CryptoError::ParseCertificate
            })?;
        let tbs = cert.tbs_certificate.to_der().map_err(|e| {
            log::error!("Failed to get tbs_certificate der: {:?}\n", e);
            e
        })?;
        let signature = cert.signature_value.as_bytes().ok_or_else(|| {
            log::error!("Failed to get signature bytes from certificate.\n");
            CryptoError::ParseCertificate
        })?;
        verify_public_key_with_tdreport(tdreport, public_key).map_err(|e| {
            log::error!("Public key verification failed: {:?}\n", e);
            e
        })?;
        ecdsa_verify(public_key, &tbs, signature)
    }

    fn verify_public_key(verified_report: &[u8], public_key: &[u8]) -> CryptoResult<()> {
        if cfg!(feature = "AzCVMEmu") {
            // In AzCVMEmu mode, REPORTDATA is constructed differently.
            // Bypass public key hash check in this development environment.
            log::warn!(
                "AzCVMEmu mode: Skipping public key verification in TD report. This is NOT secure for production use.\n"
            );
            return Ok(());
        }
        const PUBLIC_KEY_HASH_SIZE: usize = 48;

        let report_data = &verified_report[520..520 + PUBLIC_KEY_HASH_SIZE];
        let digest = digest_sha384(public_key).map_err(|e| {
            log::error!("Failed to compute SHA384 digest: {:?}\n", e);
            e
        })?;

        if report_data == digest.as_slice() {
            Ok(())
        } else {
            log::error!("Public key verification failed in TD report.\n");
            Err(CryptoError::TlsVerifyPeerCert(
                MISMATCH_PUBLIC_KEY.to_string(),
            ))
        }
    }

    #[cfg(feature = "policy_v2")]
    fn verify_public_key_with_tdreport(tdreport: &[u8], public_key: &[u8]) -> CryptoResult<()> {
        if cfg!(feature = "AzCVMEmu") {
            // In AzCVMEmu mode, REPORTDATA is constructed differently.
            // Bypass public key hash check in this development environment.
            log::warn!(
                "AzCVMEmu mode: Skipping public key verification in TD report. This is NOT secure for production use.\n"
            );
            return Ok(());
        }
        const PUBLIC_KEY_HASH_SIZE: usize = 48;

        let tdx_report = TdxReport::read_from_bytes(tdreport).ok_or(
            CryptoError::TlsVerifyPeerCert(MISMATCH_PUBLIC_KEY.to_string()),
        )?;
        let report_data = &tdx_report.report_mac.report_data[..PUBLIC_KEY_HASH_SIZE];
        let digest = digest_sha384(public_key).map_err(|e| {
            log::error!("Failed to compute SHA384 digest: {:?}\n", e);
            e
        })?;

        if report_data == digest.as_slice() {
            Ok(())
        } else {
            log::error!("Public key verification failed in TD report.\n");
            Err(CryptoError::TlsVerifyPeerCert(
                MISMATCH_PUBLIC_KEY.to_string(),
            ))
        }
    }
}

// Only for test to bypass the quote verification
#[cfg(feature = "test_disable_ra_and_accept_all")]
mod verify {
    use super::*;

    pub fn verify_peer_cert(
        _is_client: bool,
        cert: &[u8],
        _quote_local: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(CryptoError::ParseCertificate)?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions)?;
        // Parse out quote report and event log from certificate extensions
        let quote_report = find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT)
            .ok_or(CryptoError::ParseCertificate)?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG)
            .ok_or(CryptoError::ParseCertificate)?;

        // As the remote attestation is disabled, the certificate can't be verified. Aways return
        // success for test purpose.
        Ok(())
    }
}

fn check_migtd_eku(extensions: &Extensions) -> core::result::Result<(), CryptoError> {
    for extn in extensions.get() {
        if extn.extn_id == EXTENDED_KEY_USAGE {
            if let Some(extn_value) = extn.extn_value {
                let eku = ExtendedKeyUsage::from_der(extn_value.as_bytes()).map_err(|e| {
                    log::error!("Failed to parse ExtendedKeyUsage: {:?}\n", e);
                    e
                })?;
                if eku.contains(&MIGTD_EXTENDED_KEY_USAGE) {
                    return Ok(());
                }
            }
        }
    }

    log::error!("check_migtd_eku MIGTD Extended Key Usage not found in certificate.\n");
    Err(CryptoError::ParseCertificate)
}

pub(crate) fn find_extension<'a>(
    extensions: &'a Extensions,
    id: &ObjectIdentifier,
) -> Option<&'a [u8]> {
    extensions.get().iter().find_map(|extn| {
        if &extn.extn_id == id {
            extn.extn_value.map(|v| v.as_bytes())
        } else {
            None
        }
    })
}
