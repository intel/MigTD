#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Generate the signed JSON mapping with conflicting SVNs and its signer chain.

The two entries carry the same hash in different letter case with different
SVNs: the signature is valid, but mapping validation must reject it. The
private keys remain in memory and are never written.
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
HASH = "00112233445566778899aabbccddeeff" * 3
MAPPING = {
    "id": "BB9668CA-4EE8-4523-941A-B3B03BE46E03",
    "issueDate": "2026-01-01T00:00:00Z",
    "nextUpdate": "2036-01-01T00:00:00Z",
    "svnMappings": [
        {"isvsvn": 1, "tdMeasurements": {"servtdInfoHash": HASH}},
        {"isvsvn": 2, "tdMeasurements": {"servtdInfoHash": HASH.upper()}},
    ],
    "version": 1,
}


def name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


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
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            x509.ObjectIdentifier("1.3.6.1.4.1.32473.1.1"),
        ]), critical=False)
    return builder.sign(issuer_key, hashes.SHA384())


def pem(value):
    return value.public_bytes(serialization.Encoding.PEM)


root_name = name("MigTD JSON Mapping Validation Test Root")
root_key = ec.generate_private_key(ec.SECP384R1())
signer_key = ec.generate_private_key(ec.SECP384R1())
root = certificate(root_name, root_key, root_name, root_key, 1, True)
signer = certificate(
    name("MigTD JSON Mapping Validation Test Signer"), signer_key, root_name, root_key, 2, False)
(OUTPUT / "issuer_chain.pem").write_bytes(pem(signer) + pem(root))

# The signature covers the exact bytes embedded as `tdTcbMapping`.
mapping = json.dumps(MAPPING, separators=(",", ":"), sort_keys=True)
signature = signer_key.sign(mapping.encode(), ec.ECDSA(hashes.SHA384())).hex().upper()
(OUTPUT / "conflicting_svn_signed.json").write_bytes(
    f'{{"tdTcbMapping":{mapping},"signature":"{signature}"}}'.encode())
