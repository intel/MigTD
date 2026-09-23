#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Generate public CRL-profile fixtures; private keys remain in memory."""

import base64
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUTPUT = Path(__file__).resolve().parent
START = datetime.datetime(2026, 1, 1)
END = datetime.datetime(2036, 1, 1)


def name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def usage(ca, crl_sign):
    return x509.KeyUsage(
        digital_signature=not ca, content_commitment=False,
        key_encipherment=False, data_encipherment=False, key_agreement=False,
        key_cert_sign=ca, crl_sign=crl_sign, encipher_only=False, decipher_only=False,
    )


def certificate(subject, key, issuer, issuer_key, serial, ca, key_usage, extra=()):
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(serial)
        .not_valid_before(START).not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            x509.ObjectIdentifier("1.3.6.1.4.1.32473.1.1"),
        ]), critical=False)
    for value, critical in extra:
        builder = builder.add_extension(value, critical)
    return builder.sign(issuer_key, hashes.SHA384())


def crl(key, extensions=(), entries=()):
    builder = (
        x509.CertificateRevocationListBuilder().issuer_name(ISSUER_NAME)
        .last_update(START).next_update(END)
        .add_extension(x509.CRLNumber(7), critical=False)
    )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    for serial, entry_extensions in entries:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(START)
        for value, critical in entry_extensions:
            entry = entry.add_extension(value, critical)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(key, hashes.SHA384())


def pem(value):
    return value.public_bytes(serialization.Encoding.PEM)


def write(suffix, value):
    (OUTPUT / f"profile_{suffix}.pem").write_bytes(value)


def wrap(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else (
        bytes([0x80 + (length.bit_length() + 7) // 8])
        + length.to_bytes((length.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + encoded + value


def children(sequence):
    offset = 2 + ((sequence[1] & 0x7f) if sequence[1] & 0x80 else 0)
    result = []
    while offset < len(sequence):
        length = sequence[offset + 1]
        header = 2
        if length & 0x80:
            count = length & 0x7f
            length = int.from_bytes(sequence[offset + 2:offset + 2 + count], "big")
            header += count
        end = offset + header + length
        result.append(sequence[offset:end])
        offset = end
    assert offset == len(sequence)
    return result


def duplicate_extension(value, oid, key, label):
    # The normal builder rejects duplicate extensions before it can sign them.
    parts = children(value.public_bytes(serialization.Encoding.DER))
    tbs = children(parts[0])
    extensions = children(children(tbs[-1])[0])
    duplicate = next(ext for ext in extensions if children(ext)[0] == oid)
    tbs[-1] = wrap(tbs[-1][0], wrap(0x30, b"".join(extensions + [duplicate])))
    signed = wrap(0x30, b"".join(tbs))
    signature = key.sign(signed, ec.ECDSA(hashes.SHA384()))
    der = wrap(0x30, signed + parts[1] + wrap(0x03, b"\0" + signature))
    data = base64.b64encode(der)
    return (f"-----BEGIN {label}-----\n".encode()
            + b"\n".join(data[i:i + 64] for i in range(0, len(data), 64))
            + f"\n-----END {label}-----\n".encode())


ROOT_NAME = name("MigTD Profile Root")
ISSUER_NAME = name("MigTD Profile Issuer")
LEAF_NAME = name("MigTD Profile Signer")
root_key, issuer_key, other_key, leaf_key = (
    ec.generate_private_key(ec.SECP384R1()) for _ in range(4)
)
root = certificate(ROOT_NAME, root_key, ROOT_NAME, root_key, 1, True, usage(True, True))
issuer = certificate(ISSUER_NAME, issuer_key, ROOT_NAME, root_key, 2, True, usage(True, True))
leaf = certificate(LEAF_NAME, leaf_key, ISSUER_NAME, issuer_key, 128, False, usage(False, False))
write("chain", pem(leaf) + pem(issuer) + pem(root))
write("issuer", pem(issuer))
write("empty_crl", pem(crl(issuer_key)))
write("collision_crl", pem(crl(issuer_key, entries=((1, ()), (2, ())))))
write("revoked_crl", pem(crl(issuer_key, entries=((128, ()),))))
for suffix, key_usage in (
    ("no_crl_sign", usage(True, False)),
    ("missing_key_usage", None),
    ("malformed_key_usage", x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.15"), b"\x05\x00")),
):
    invalid = certificate(ISSUER_NAME, issuer_key, ROOT_NAME, root_key, 2, True, key_usage)
    write(suffix + "_chain", pem(leaf) + pem(invalid) + pem(root))
write("duplicate_key_usage_chain", pem(leaf) + duplicate_extension(
    issuer, b"\x06\x03\x55\x1d\x0f", root_key, "CERTIFICATE") + pem(root))
other_issuer = certificate(ISSUER_NAME, other_key, ROOT_NAME, root_key, 3, True, usage(True, True))
other_leaf = certificate(LEAF_NAME, leaf_key, ISSUER_NAME, other_key, 128, False, usage(False, False))
write("other_issuer_chain", pem(other_leaf) + pem(other_issuer) + pem(root))
write("other_issuer_crl", pem(crl(other_key)))
direct_leaf = certificate(LEAF_NAME, leaf_key, ROOT_NAME, root_key, 128, False, usage(False, False))
write("root_issued_chain", pem(direct_leaf) + pem(root))
normal_point = x509.DistributionPoint(
    full_name=[x509.UniformResourceIdentifier("https://example.invalid/issuer.crl")],
    relative_name=None, reasons=None, crl_issuer=None,
)
for suffix, point in (
    ("direct", normal_point),
    ("reason_scoped", x509.DistributionPoint(
        normal_point.full_name, None, frozenset([x509.ReasonFlags.key_compromise]), None)),
    ("delegated", x509.DistributionPoint(
        normal_point.full_name, None, None, [x509.DirectoryName(ISSUER_NAME)])),
):
    value = certificate(LEAF_NAME, leaf_key, ISSUER_NAME, issuer_key, 128, False,
                        usage(False, False), [(x509.CRLDistributionPoints([point]), False)])
    write(suffix + "_chain", pem(value) + pem(issuer) + pem(root))
for suffix, extensions in (
    ("delta", [(x509.DeltaCRLIndicator(6), True)]),
    ("noncritical_delta", [(x509.DeltaCRLIndicator(6), False)]),
    ("partitioned", [(x509.IssuingDistributionPoint(
        full_name=normal_point.full_name, relative_name=None,
        only_contains_user_certs=False, only_contains_ca_certs=False,
        only_some_reasons=None, indirect_crl=False, only_contains_attribute_certs=False,
    ), True)]),
    ("unknown_critical", [(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"), True)]),
    ("unknown_noncritical", [(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.1"), b"\x02\x01\x00"), False)]),
):
    write(suffix + "_crl", pem(crl(issuer_key, extensions)))
write("indirect_entry_crl", pem(crl(issuer_key, entries=(
    (2, [(x509.CertificateIssuer([x509.DirectoryName(ROOT_NAME)]), True)]),
))))
write("remove_entry_crl", pem(crl(issuer_key, entries=(
    (128, [(x509.CRLReason(x509.ReasonFlags.remove_from_crl), False)]),
))))
write("key_compromise_crl", pem(crl(issuer_key, entries=(
    (128, [(x509.CRLReason(x509.ReasonFlags.key_compromise), False)]),
))))
write("duplicate_number_crl", duplicate_extension(
    crl(issuer_key), b"\x06\x03\x55\x1d\x14", issuer_key, "X509 CRL"))
