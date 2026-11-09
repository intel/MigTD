#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Generate the public signer/CRL/JSON fixtures in this directory.

Private keys remain in memory and are never written. Leaf serials 0x80 and
0x81 exercise DER INTEGER sign-padding normalization. The profile_* fixtures
come from generate_profile.py.
"""

import datetime
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUTPUT = Path(__file__).resolve().parent
START = datetime.datetime(2026, 1, 1)
END = datetime.datetime(2036, 1, 1)
SIGNER_EKU = x509.ObjectIdentifier("1.3.6.1.4.1.32473.1.1")

TD_IDENTITY = {
    "attributes": "0000000000000000",
    "id": "A0998F0F-B2F3-4872-8138-FBC2B853E8C6",
    "issueDate": "2025-01-01T00:00:00Z",
    "isvProdId": 1,
    "mrConfigId": "00" * 48,
    "mrOwner": "00" * 48,
    "mrOwnerConfig": "00" * 48,
    "mrsigner": "00" * 48,
    "nextUpdate": "2026-01-01T00:00:00Z",
    "tcbEvaluationNumber": 1,
    "tcbLevels": [
        {"tcb": {"isvsvn": 1}, "tcbDate": "2024-01-01T00:00:00Z", "tcbStatus": "UpToDate"}
    ],
    "version": 1,
    "xfam": "E71A060000000000",
}
TD_TCB_MAPPING = {
    "id": "BB9668CA-4EE8-4523-941A-B3B03BE46E03",
    "issueDate": "2025-01-01T00:00:00Z",
    "nextUpdate": "2026-01-01T00:00:00Z",
    "svnMappings": [
        {"isvsvn": 1, "tdMeasurements": {"servtdInfoHash": "AABBCCDDEEFF00112233445566778899" * 3}},
        {"isvsvn": 2, "tdMeasurements": {"servtdInfoHash": "11" * 48}},
    ],
    "version": 1,
}


def name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def new_key():
    return ec.generate_private_key(ec.SECP384R1())


def certificate(subject, key, issuer, issuer_key, serial, ca):
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(serial)
        .not_valid_before(START).not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=not ca, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([SIGNER_EKU]), critical=False)
    return builder.sign(issuer_key, hashes.SHA384())


def crl(issuer, key, number, revoked=(), authority_key_id=False):
    builder = (
        x509.CertificateRevocationListBuilder().issuer_name(issuer)
        .last_update(START).next_update(END)
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    if authority_key_id:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
    for serial in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(START).build()
        )
    return builder.sign(key, hashes.SHA384())


def pem(value):
    return value.public_bytes(serialization.Encoding.PEM)


def write(file, data):
    (OUTPUT / file).write_bytes(data)


def tampered(value):
    """Return a well-formed CRL whose signature no longer verifies."""
    der = bytearray(value.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    return pem(x509.load_der_x509_crl(bytes(der)))


def signed_json(member, value, key):
    # The signature covers the compact, key-sorted encoding of `value`.
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    signature = key.sign(data, ec.ECDSA(hashes.SHA384())).hex().upper()
    return json.dumps(
        {"signature": signature, member: value}, separators=(",", ":"), sort_keys=True
    ).encode() + b"\n"


ROOT = name("MigTD CRL Test Root")
ISSUER = name("MigTD CRL Test Issuer")
POLICY = name("MigTD CRL Test Policy")
IDENTITY = name("MigTD CRL Test Identity")
UNRELATED = name("MigTD Unrelated CRL Test Root")

root_key, issuer_key, unrelated_key = new_key(), new_key(), new_key()
policy_key, policy_rotated_key = new_key(), new_key()
identity_key, identity_other_key = new_key(), new_key()

write("root.pem", pem(certificate(ROOT, root_key, ROOT, root_key, 1, True)))
write("issuer.pem", pem(certificate(ISSUER, issuer_key, ROOT, root_key, 2, True)))
write("policy.pem", pem(certificate(POLICY, policy_key, ISSUER, issuer_key, 0x80, False)))
write("identity.pem", pem(certificate(IDENTITY, identity_key, ISSUER, issuer_key, 0x81, False)))
write("identity_other_issuer.pem", pem(
    certificate(IDENTITY, identity_other_key, ROOT, root_key, 0x82, False)))
write("policy_rotated.pem", pem(
    certificate(POLICY, policy_rotated_key, ISSUER, issuer_key, 0x83, False)))

write("empty.crl.pem", pem(crl(ISSUER, issuer_key, 7)))
write("revoked_policy.crl.pem", pem(crl(ISSUER, issuer_key, 8, [0x80])))
write("revoked_identity.crl.pem", pem(crl(ISSUER, issuer_key, 9, [0x81])))
write("revoked_issuer.crl.pem", pem(crl(ROOT, root_key, 10, [2])))
write("unrelated.crl.pem", pem(crl(UNRELATED, unrelated_key, 11)))
write("non_ca.crl.pem", pem(crl(POLICY, policy_key, 12)))
write("root_empty.crl.pem", pem(crl(ROOT, root_key, 13)))
write("tampered.crl.pem", tampered(crl(ISSUER, issuer_key, 7)))
write("no_number.crl.pem", pem(crl(ISSUER, issuer_key, None, authority_key_id=True)))

write("signed_identity.json", signed_json("tdIdentity", TD_IDENTITY, identity_key))
write("signed_identity_other_issuer.json",
      signed_json("tdIdentity", TD_IDENTITY, identity_other_key))
write("signed_mapping.json", signed_json("tdTcbMapping", TD_TCB_MAPPING, policy_key))
write("signed_mapping_rotated.json",
      signed_json("tdTcbMapping", TD_TCB_MAPPING, policy_rotated_key))
