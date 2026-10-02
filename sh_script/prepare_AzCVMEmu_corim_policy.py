#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Prepare an emulation-only policy using the public signed CoRIM fixtures."""

import argparse
import json
from pathlib import Path


FIXTURES = Path(__file__).resolve().parent.parent / "src/policy/test/policy_v2/corim"


def prepare(base, output, with_identity):
    policy = json.loads(base.read_text())
    data = policy["policyData"]
    data.pop("servtdCollateral", None)
    data.pop("servtdCrl", None)
    identity_rules = {"isvsvn": {"operation": "greater-or-equal", "reference": 1}}
    if with_identity:
        data["servtdCollateral"] = json.loads((FIXTURES / "servtd_collateral.json").read_text())
        identity_rules["tcbStatusAccepted"] = {
            "operation": "string-equal", "reference": "UpToDate",
        }
        identity_rules["tcbDate"] = {
            "operation": "greater-or-equal", "reference": "2024-01-01T00:00:00Z",
        }
    else:
        data["servtdCrl"] = (FIXTURES / "servtd.crl.pem").read_text()
    servtd_rule = {
        "servtd": {
            "migtdIdentity": identity_rules,
            "servtdCrlNum": {"operation": "greater-or-equal", "reference": 7},
        }
    }
    data["policy"].append(servtd_rule)
    for name in ("forwardPolicy", "backwardPolicy"):
        if data.get(name) is not None:
            data[name].append(servtd_rule)
    output.write_text(json.dumps(policy, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-identity", action="store_true")
    arguments = parser.parse_args()
    prepare(arguments.base, arguments.output, arguments.with_identity)
