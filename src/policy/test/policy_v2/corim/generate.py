#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Regenerate public emulation fixtures; signing keys never leave memory."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID


START = datetime(2020, 1, 1, tzinfo=timezone.utc)
END = datetime(2120, 1, 1, tzinfo=timezone.utc)
SIGNER_EKU = x509.ObjectIdentifier("1.3.6.1.4.1.32473.1.1")
SIGNER_EKU_DER = bytes.fromhex("060a2b0601040181fd590101")


def certificate(
    subject, issuer, public_key, issuer_key, serial, is_ca,
    *, san_names=None, eku_oids=(SIGNER_EKU,),
):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(START)
        .not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=is_ca, crl_sign=is_ca, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if not is_ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)
        if san_names is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    return builder.sign(issuer_key, hashes.SHA384())


def signed_json(name, value, key):
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return {name: value, "signature": key.sign(payload, ec.ECDSA(hashes.SHA384())).hex()}


def signer_anchor(root, leaf):
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san_input = b"\x00"
    else:
        san_input = b"\x01" + names.public_bytes()
    components = [
        b"MIGTD-RTMR1-ANCHOR-V2",
        hashlib.sha384(root.public_bytes(serialization.Encoding.DER)).digest(),
        hashlib.sha384(leaf.subject.public_bytes()).digest(),
        hashlib.sha384(san_input).digest(),
        SIGNER_EKU_DER,
    ]
    return hashlib.sha384(b"\x00".join(components)).digest()


def signed_corim(payload, leaf, issuer, root, key):
    protected = cbor2.dumps({
        1: -35,
        3: "application/rim+cbor",
        15: {1: "MigTD emulation fixture"},
        33: [
            leaf.public_bytes(serialization.Encoding.DER),
            issuer.public_bytes(serialization.Encoding.DER),
            root.public_bytes(serialization.Encoding.DER),
        ],
    })
    tbs = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = key.sign(tbs, ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(signature)
    cose = cbor2.CBORTag(
        18, [protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")],
    )
    return cbor2.dumps(cose)


def generate(policy_path):
    output = Path(__file__).resolve().parent
    source = json.loads(policy_path.read_text())["policyData"]["servtdCollateral"]
    mapping = source["servtdTcbMapping"]["tdTcbMapping"]
    identity = source["servtdIdentity"]["tdIdentity"]
    identity = {
        name: identity[name]
        for name in ("id", "version", "issueDate", "nextUpdate", "tcbLevels")
    }

    root_key = ec.generate_private_key(ec.SECP384R1())
    issuer_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MigTD CoRIM Emulation Root")])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MigTD CoRIM Emulation Issuer")])
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MigTD Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MigTD CoRIM Emulation Signer"),
    ])
    san_names = [
        x509.DNSName("migtd.example"),
        x509.UniformResourceIdentifier("urn:tdx:migtd"),
    ]
    root = certificate(root_name, root_name, root_key.public_key(), root_key, 1, True)
    issuer = certificate(issuer_name, root_name, issuer_key.public_key(), root_key, 2, True)
    leaf = certificate(
        leaf_name, issuer_name, leaf_key.public_key(), issuer_key, 3, False, san_names=san_names,
    )
    chain_pem = (
        leaf.public_bytes(serialization.Encoding.PEM)
        + issuer.public_bytes(serialization.Encoding.PEM)
        + root.public_bytes(serialization.Encoding.PEM)
    )
    (output / "issuer_chain.pem").write_bytes(chain_pem)
    (output / "signer_anchor.bin").write_bytes(signer_anchor(root, leaf))

    for number, revoked, filename in (
        (7, False, "servtd.crl.pem"),
        (8, True, "revoked.crl.pem"),
    ):
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer_name)
            .last_update(START)
            .next_update(END)
            .add_extension(x509.CRLNumber(number), critical=False)
        )
        if revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(3)
                .revocation_date(START)
                .build()
            )
        crl = builder.sign(issuer_key, hashes.SHA384())
        (output / filename).write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    environment = {0: {1: "Intel", 2: "TDX"}, 1: cbor2.CBORTag(560, b"migration-td")}
    references = []
    series = []
    for entry in mapping["svnMappings"]:
        digest = bytes.fromhex(entry["tdMeasurements"]["tdinfo_hash"])
        if len(digest) != 48:
            raise ValueError("TCB mapping requires 48-byte hashes")
        # Match the producer's existing algorithm-ID convention.
        measurement = {1: {2: [[1, digest]]}}
        addition = {1: {1: cbor2.CBORTag(552, entry["isvsvn"])}}
        references.append([environment, [measurement]])
        series.append([[environment, []], [[[measurement], [addition]]]])
    comid = {1: {0: "migtd-emulation"}, 4: {0: references, 8: series}}
    payload = cbor2.dumps(cbor2.CBORTag(
        501, {0: "migtd-emulation", 1: [cbor2.CBORTag(506, cbor2.dumps(comid))]},
    ))
    (output / "tcb_mapping.corim").write_bytes(signed_corim(payload, leaf, issuer, root, leaf_key))
    other_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Other Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MigTD CoRIM Emulation Signer"),
    ])
    other_san = [san_names[0], x509.UniformResourceIdentifier("urn:tdx:other")]
    variants = [
        ("rotated", leaf_name, san_names, [SIGNER_EKU]),
        ("subject_mismatch", other_subject, san_names, [SIGNER_EKU]),
        ("san_mismatch", leaf_name, other_san, [SIGNER_EKU]),
        ("no_san", leaf_name, None, [SIGNER_EKU]),
        ("other_eku", leaf_name, san_names, [x509.ObjectIdentifier("1.3.6.1.4.1.32473.1.2")]),
        ("multiple_eku", leaf_name, san_names, [
            x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3"), SIGNER_EKU,
        ]),
    ]
    for serial, (name, subject, names, purposes) in enumerate(variants, start=4):
        key = ec.generate_private_key(ec.SECP384R1())
        cert = certificate(
            subject, issuer_name, key.public_key(), issuer_key, serial, False,
            san_names=names, eku_oids=purposes,
        )
        (output / f"tcb_mapping_{name}.corim").write_bytes(signed_corim(payload, cert, issuer, root, key))

    collateral = {
        "majorVersion": 1,
        "minorVersion": 0,
        "servtdTcbMappingIssuerChain": chain_pem.decode(),
        "servtdTcbMapping": signed_json("tdTcbMapping", mapping, leaf_key),
        "servtdIdentityIssuerChain": chain_pem.decode(),
        "servtdIdentity": signed_json("tdIdentity", identity, leaf_key),
        "servtdCrl": (output / "servtd.crl.pem").read_text(),
    }
    (output / "servtd_collateral.json").write_text(
        json.dumps(collateral, separators=(",", ":"), sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True, help="Generated mock-report v2 policy")
    generate(parser.parse_args().policy)
