#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Test artifact selection; set MIGTD_EMU_BINARY to also check native startup errors."""

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parent.parent


class LauncherArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migtdemu-artifacts-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copy2(REPOSITORY / "migtdemu.sh", self.root / "migtdemu.sh")
        for directory in ("bin", "config", "target/release", "sh_script"):
            (self.root / directory).mkdir(parents=True)
        self.policy = self.file("policy.json", b"{}")
        self.chain = self.file("chain.pem", b"issuer chain")
        self.anchor = self.file("anchor.bin", bytes(range(48)))
        self.corim = self.file("mapping.corim", b"opaque signed CoRIM")
        self.file("config/policy.json", b"{}")
        self.file("config/Intel_SGX_Provisioning_Certification_RootCA.cer", b"root CA")
        self.executable(
            "bin/cargo",
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            "pathlib.Path('cargo-args.json').write_text(json.dumps(sys.argv[1:]))\n",
        )
        self.executable("bin/taskset", '#!/bin/sh\nshift 2\nexec "$@"\n')
        self.executable(
            "bin/ss",
            "#!/bin/sh\n"
            "if [ -f record-destination.json ]; then echo LISTEN; fi\n",
        )
        self.executable(
            "sh_script/build_AzCVMEmu_policy_and_test.sh",
            "#!/bin/sh\ntouch policy-generation-ran\nexit 99\n",
        )
        self.executable(
            "target/release/migtd",
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "role = sys.argv[sys.argv.index('--role') + 1]\n"
            "names = ('MIGTD_POLICY_FILE', 'MIGTD_POLICY_ISSUER_CHAIN_FILE', "
            "'MIGTD_SIGNER_ANCHOR_FILE', 'MIGTD_SERVTD_CORIM_FILE')\n"
            "record = {'args': sys.argv[1:], "
            "'env': {name: os.environ.get(name) for name in names}}\n"
            "pathlib.Path('record-' + role + '.json').write_text(json.dumps(record))\n",
        )

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return str(path)

    def executable(self, name, text):
        path = Path(self.file(name, text.encode()))
        path.chmod(0o755)

    def run_launcher(self, *arguments, error=None):
        for name in (
            "record-source.json",
            "record-destination.json",
            "cargo-args.json",
            "policy-generation-ran",
        ):
            (self.root / name).unlink(missing_ok=True)
        environment = os.environ.copy()
        environment["PATH"] = str(self.root / "bin") + os.pathsep + environment["PATH"]
        environment["MIGTD_SIGNER_ANCHOR_FILE"] = "ambient anchor must not leak"
        environment["MIGTD_SERVTD_CORIM_FILE"] = "ambient CoRIM must not leak"
        result = subprocess.run(
            ["bash", str(self.root / "migtdemu.sh"), "--mock-report", "--no-sudo", *arguments],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=25,
        )
        output = result.stdout + result.stderr
        if error is None:
            self.assertEqual(result.returncode, 0, output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn(error, output)
            self.assertFalse((self.root / "cargo-args.json").exists(), output)
        self.assertFalse((self.root / "policy-generation-ran").exists(), output)

    def runtime_environment(self, role="source"):
        return json.loads((self.root / f"record-{role}.json").read_text())["env"]

    def features(self):
        arguments = json.loads((self.root / "cargo-args.json").read_text())
        return arguments[arguments.index("--features") + 1].split(",")

    def test_shared_anchor_and_corim_enable_feature_and_reach_both_peers(self):
        self.run_launcher(
            "--policy-v2", "--policy-file", self.policy,
            "--signer-anchor-file", self.anchor, "--servtd-corim-file", self.corim,
            "--both",
        )
        for role in ("source", "destination"):
            environment = self.runtime_environment(role)
            self.assertEqual(environment["MIGTD_SIGNER_ANCHOR_FILE"], self.anchor)
            self.assertEqual(environment["MIGTD_SERVTD_CORIM_FILE"], self.corim)
        self.assertIn("servtd_corim", self.features())

    def test_per_peer_overrides_reach_the_correct_peer(self):
        other_anchor = self.file("other-anchor.bin", bytes([7]) * 48)
        other_corim = self.file("other-mapping.corim", b"another signed CoRIM")
        self.run_launcher(
            "--policy-v2", "--policy-file", self.policy,
            "--signer-anchor-file", self.anchor, "--servtd-corim-file", self.corim,
            "--dst-signer-anchor-file", other_anchor,
            "--dst-servtd-corim-file", other_corim, "--both",
        )
        self.assertEqual(self.runtime_environment()["MIGTD_SIGNER_ANCHOR_FILE"], self.anchor)
        destination = self.runtime_environment("destination")
        self.assertEqual(destination["MIGTD_SIGNER_ANCHOR_FILE"], other_anchor)
        self.assertEqual(destination["MIGTD_SERVTD_CORIM_FILE"], other_corim)

    def test_single_peer_inputs_do_not_require_unused_peer_files_or_generate_policy(self):
        for role, prefix in (("source", "src"), ("destination", "dst")):
            with self.subTest(role=role):
                self.run_launcher(
                    "--policy-v2", "--role", role,
                    f"--{prefix}-policy-file", self.policy,
                    f"--{prefix}-signer-anchor-file", self.anchor,
                    f"--{prefix}-servtd-corim-file", self.corim,
                )
                environment = self.runtime_environment(role)
                self.assertEqual(environment["MIGTD_POLICY_FILE"], self.policy)
                self.assertEqual(environment["MIGTD_SIGNER_ANCHOR_FILE"], self.anchor)
                self.assertEqual(environment["MIGTD_SERVTD_CORIM_FILE"], self.corim)

    def test_anchor_takes_precedence_over_an_unused_pem_path(self):
        self.run_launcher(
            "--policy-v2", "--policy-file", self.policy,
            "--policy-issuer-chain-file", str(self.root / "not-enrolled.pem"),
            "--signer-anchor-file", self.anchor,
        )
        self.assertEqual(self.runtime_environment()["MIGTD_SIGNER_ANCHOR_FILE"], self.anchor)

    def test_corim_feature_alone_allows_json_and_clears_ambient_artifacts(self):
        self.run_launcher(
            "--policy-v2", "--policy-file", self.policy,
            "--policy-issuer-chain-file", self.chain, "--features", "servtd_corim",
        )
        environment = self.runtime_environment()
        self.assertEqual(environment["MIGTD_POLICY_ISSUER_CHAIN_FILE"], self.chain)
        self.assertEqual(environment["MIGTD_SIGNER_ANCHOR_FILE"], "")
        self.assertEqual(environment["MIGTD_SERVTD_CORIM_FILE"], "")
        self.assertIn("servtd_corim", self.features())

    def test_legacy_mode_does_not_inherit_new_artifacts(self):
        self.run_launcher()
        environment = self.runtime_environment()
        self.assertEqual(environment["MIGTD_SIGNER_ANCHOR_FILE"], "")
        self.assertEqual(environment["MIGTD_SERVTD_CORIM_FILE"], "")
        self.assertNotIn("servtd_corim", self.features())

    def test_new_artifacts_and_feature_require_policy_v2(self):
        for option, value in (
            ("--signer-anchor-file", self.anchor),
            ("--servtd-corim-file", self.corim),
            ("--features", "servtd_corim"),
        ):
            with self.subTest(option=option):
                self.run_launcher(option, value, error="require --policy-v2")

    def test_invalid_anchor_sizes_are_rejected_before_building(self):
        for size in (0, 47, 49, 96):
            with self.subTest(size=size):
                Path(self.anchor).write_bytes(bytes(size))
                self.run_launcher(
                    "--policy-v2", "--policy-file", self.policy,
                    "--signer-anchor-file", self.anchor,
                    error="exactly 48 raw bytes",
                )

    def test_empty_or_missing_corim_is_rejected_before_building(self):
        Path(self.corim).write_bytes(b"")
        self.run_launcher(
            "--policy-v2", "--policy-file", self.policy,
            "--signer-anchor-file", self.anchor, "--servtd-corim-file", self.corim,
            error="CoRIM must not be empty",
        )
        Path(self.corim).unlink()
        self.run_launcher(
            "--policy-v2", "--policy-file", self.policy,
            "--signer-anchor-file", self.anchor, "--servtd-corim-file", self.corim,
            error="CoRIM file not found",
        )

    def test_missing_file_option_values_are_rejected(self):
        for option in ("--signer-anchor-file", "--servtd-corim-file"):
            with self.subTest(option=option):
                self.run_launcher(option, error="requires a file path")


@unittest.skipUnless(os.environ.get("MIGTD_EMU_BINARY"), "MIGTD_EMU_BINARY not supplied")
class NativeArtifactInitializationTests(unittest.TestCase):
    def test_invalid_artifacts_report_errors_before_the_vmm_log_area_exists(self):
        binary = Path(os.environ["MIGTD_EMU_BINARY"]).resolve()
        with tempfile.TemporaryDirectory(prefix="migtdemu-native-inputs-") as temporary:
            root = Path(temporary)
            policy = root / "policy.json"
            policy.write_bytes(b"{}")
            anchor = root / "anchor.bin"
            anchor.write_bytes(bytes(48))
            environment = os.environ.copy()
            environment.update({
                "MIGTD_POLICY_FILE": str(policy),
                "MIGTD_POLICY_ISSUER_CHAIN_FILE": "",
                "MIGTD_SIGNER_ANCHOR_FILE": str(anchor),
                "MIGTD_SERVTD_CORIM_FILE": "",
                "MIGTD_LOG_FILE": str(root / "migtd.log"),
            })
            for name, variable, data, expected in (
                ("short-anchor", "MIGTD_SIGNER_ANCHOR_FILE", bytes(47), "exactly 48 raw bytes"),
                ("long-anchor", "MIGTD_SIGNER_ANCHOR_FILE", bytes(49), "exactly 48 raw bytes"),
                ("empty-corim", "MIGTD_SERVTD_CORIM_FILE", b"", "Failed to load servtd CoRIM"),
                ("oversized-corim", "MIGTD_SERVTD_CORIM_FILE", bytes(1024 * 1024 + 1), "Failed to load servtd CoRIM"),
                ("missing-corim", "MIGTD_SERVTD_CORIM_FILE", None, "Failed to load servtd CoRIM"),
            ):
                with self.subTest(artifact=name):
                    path = root / name
                    if data is not None:
                        path.write_bytes(data)
                    # Argument parsing connects before artifact initialization.
                    with socket.socket() as peer:
                        peer.bind(("127.0.0.1", 0))
                        peer.listen(1)
                        result = subprocess.run(
                            [
                                str(binary), "--role", "source", "--dest-ip", "127.0.0.1",
                                "--dest-port", str(peer.getsockname()[1]),
                            ],
                            env=dict(environment, **{variable: str(path)}),
                            cwd=root,
                            text=True,
                            capture_output=True,
                            timeout=15,
                        )
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertIn(expected, output)


if __name__ == "__main__":
    unittest.main()
