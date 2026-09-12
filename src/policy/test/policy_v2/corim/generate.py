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


def certificate(subject, issuer, public_key, issuer_key, serial, is_ca):
    return (
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
        .sign(issuer_key, hashes.SHA384())
    )


def signed_json(name, value, key):
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return {name: value, "signature": key.sign(payload, ec.ECDSA(hashes.SHA384())).hex()}


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
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MigTD CoRIM Emulation Root")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MigTD CoRIM Emulation Signer")])
    root = certificate(root_name, root_name, root_key.public_key(), root_key, 1, True)
    leaf = certificate(leaf_name, root_name, leaf_key.public_key(), root_key, 2, False)
    root_der = root.public_bytes(serialization.Encoding.DER)
    chain_der = [leaf.public_bytes(serialization.Encoding.DER), root_der]
    chain_pem = (
        leaf.public_bytes(serialization.Encoding.PEM)
        + root.public_bytes(serialization.Encoding.PEM)
    )
    anchor = hashlib.sha384(
        b"MIGTD-RTMR1-ANCHOR-V1\0"
        + hashlib.sha384(root_der).digest()
        + b"\0"
        + hashlib.sha384(leaf.subject.public_bytes()).digest()
    ).digest()
    (output / "issuer_chain.pem").write_bytes(chain_pem)
    (output / "signer_anchor.bin").write_bytes(anchor)

    for number, revoked, filename in (
        (7, False, "servtd.crl.pem"),
        (8, True, "revoked.crl.pem"),
    ):
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(root_name)
            .last_update(START)
            .next_update(END)
            .add_extension(x509.CRLNumber(number), critical=False)
        )
        if revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(2)
                .revocation_date(START)
                .build()
            )
        crl = builder.sign(root_key, hashes.SHA384())
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
    protected = cbor2.dumps({
        1: -35,
        3: "application/rim+cbor",
        15: {1: "MigTD emulation fixture"},
        33: chain_der,
    })
    tbs = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = leaf_key.sign(tbs, ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(signature)
    cose = cbor2.CBORTag(18, [protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")])
    (output / "tcb_mapping.corim").write_bytes(cbor2.dumps(cose))

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
