import base64
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import secrets
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release-macos-xcode.yml"


def step_script(name):
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index("      - name: " + name)
    start = lines.index("        run: |", start) + 1
    body = []
    for line in lines[start:]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body)


def signing_module():
    module = types.ModuleType("native_signing")
    exec(compile(step_script("Sign and notarize native app"), str(WORKFLOW), "exec"), module.__dict__)
    return module


class NativeSigningTests(unittest.TestCase):
    def setUp(self):
        self.module = signing_module()

    def test_command_failure_withholds_protected_output_and_arguments(self):
        value = secrets.token_hex(24)
        for command in ("az", "/usr/bin/security", "/usr/bin/openssl", "/usr/bin/xcrun"):
            result = subprocess.CompletedProcess([command], 4, value, value + " errSecInternalComponent")
            with self.subTest(command=command), patch.object(self.module.subprocess, "run", return_value=result):
                with self.assertRaises(RuntimeError) as error:
                    self.module.run([command, value])
            self.assertNotIn(value, str(error.exception))
            self.assertNotIn("errSecInternalComponent", str(error.exception))
            self.assertIn("exit 4", str(error.exception))

    def test_protected_timeout_withholds_arguments_and_captured_output(self):
        value = secrets.token_hex(24)
        timeout = subprocess.TimeoutExpired(["az", value], 120, output=value, stderr=value)
        with patch.object(self.module.subprocess, "run", side_effect=timeout):
            with self.assertRaises(RuntimeError) as error:
                self.module.run(["az", value])
        self.assertNotIn(value, str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_codesign_failure_reports_only_fixed_phrases_and_relative_target(self):
        value = secrets.token_hex(24)
        app = Path("/private/hidden/Fixture.app")
        path = app / "Contents/Frameworks/Core.framework/Versions/A/Core"
        result = subprocess.CompletedProcess([], 1, "unrelated output " + value, (
            f'{path}: errSecInternalComponent\n'
            f'Warning: unable to build chain to self-signed root for signer "{value}"\n'
            f'private data: {value}\n::error::untrusted workflow command'
        ))
        with patch.object(self.module.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as error:
                self.module.codesign(["--force", "--sign", value], operation="sign", path=path, app=app)
        message = str(error.exception)
        self.assertIn("codesign sign failed", message)
        self.assertIn(path.relative_to(app).as_posix(), message)
        self.assertIn("errSecInternalComponent", message)
        self.assertIn("unable to build chain to self-signed root", message)
        self.assertIn("exit 1", message)
        for withheld in (value, str(app), "private data", "::error::", "unrelated output", "for signer"):
            self.assertNotIn(withheld, message)

    def test_codesign_unknown_output_and_timeout_remain_protected(self):
        value = secrets.token_hex(24)
        app = Path("/private/hidden/Fixture.app")
        failures = (
            subprocess.CompletedProcess([], 1, value, value),
            subprocess.TimeoutExpired(["codesign", value], 120, output=value, stderr=value),
        )
        for failure in failures:
            options = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
            with self.subTest(failure=type(failure).__name__), patch.object(self.module.subprocess, "run", **options):
                with self.assertRaises(RuntimeError) as error:
                    self.module.codesign(["--sign", value], operation="sign", path=app, app=app)
            self.assertIn('bundle target "."', str(error.exception))
            self.assertIn("protected output withheld", str(error.exception))
            self.assertNotIn(value, str(error.exception))
            self.assertNotIn(str(app), str(error.exception))

    def test_codesign_diagnostics_are_bounded_and_target_controls_are_escaped(self):
        app = Path("/private/hidden/Fixture.app")
        path = app / ("nested\n::warning::" + chr(27) + chr(0x1F600) * 200)
        output = "\n".join((
            "errSecInternalComponent", "CSSMERR_TP_NOT_TRUSTED", "User interaction is not allowed",
            "unable to build chain to self-signed root", "no identity found",
        )) * 1000
        result = subprocess.CompletedProcess([], 1, output, output)
        with patch.object(self.module.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as error:
                self.module.codesign(["--verify"], operation="verify signed bundle", path=path, app=app)
        message = str(error.exception)
        self.assertLess(len(message), 2048)
        self.assertNotIn("\n", message)
        self.assertNotIn(chr(27), message)
        self.assertNotIn("no identity found", message)
        self.assertIn("...", message)

    def test_passwords_reach_stdin_or_environment_but_never_process_arguments(self):
        password = secrets.token_hex(24) + " ' \" $ \\"
        calls = []

        def run(arguments, **kwargs):
            calls.append((arguments, kwargs))
            if arguments[1] == "list-keychains":
                return ""
            if "-out" in arguments:
                Path(arguments[arguments.index("-out") + 1]).write_bytes(b"synthetic")
            return ""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(self.module, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                self.module.import_identity(root, base64.b64encode(os.urandom(24)).decode(), password)
            sensitive = [password]
            for arguments, kwargs in calls:
                if arguments == ["/usr/bin/security", "-i"]:
                    tokens = shlex.split(kwargs["input"])
                    if tokens[0] == "create-keychain":
                        sensitive.append(tokens[tokens.index("-p") + 1])
                    if tokens[0] == "import":
                        sensitive.append(tokens[tokens.index("-P") + 1])
            self.assertEqual(len(sensitive), 3)
            for arguments, _ in calls:
                for value in sensitive:
                    self.assertNotIn(value, " ".join(arguments))
            self.assertFalse((root / "certificate.pem").exists())

    def test_rejected_notarization_never_staples_or_assesses(self):
        calls = []
        password = secrets.token_hex(24)

        def run(arguments, **kwargs):
            calls.append((arguments, kwargs))
            return json.dumps({"status": "Invalid"}) if "submit" in arguments else ""

        environment = {"APPLE_ID": "synthetic@example.invalid", "APPLE_TEAM_ID": "SYNTHETIC0"}
        with patch.dict(os.environ, environment), patch.object(self.module, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "did not accept"):
                self.module.notarize(Path("/tmp/App.app"), Path("/tmp"), Path("/tmp/signing"), password)
        self.assertFalse(any("stapler" in " ".join(arguments) for arguments, _ in calls))
        self.assertEqual(calls[0][1]["input"], password + "\n")
        for arguments, _ in calls:
            self.assertNotIn(password, " ".join(arguments))

    def test_accepted_notarization_staples_then_verifies(self):
        calls = []

        def run(arguments, **_):
            calls.append(arguments)
            return json.dumps({"status": "Accepted"}) if "submit" in arguments else ""

        with patch.dict(os.environ, APPLE_ID="synthetic@example.invalid", APPLE_TEAM_ID="SYNTHETIC0"):
            with patch.object(self.module, "run", side_effect=run), patch.object(self.module, "codesign") as signing:
                self.module.notarize(Path("/tmp/App.app"), Path("/tmp"), Path("/tmp/signing"),
                                     secrets.token_hex(24))
        self.assertEqual(signing.call_args.args[0], ["--verify", "--deep", "--strict"])
        self.assertEqual(signing.call_args.kwargs, {
            "operation": "verify stapled bundle", "path": Path("/tmp/App.app"), "app": Path("/tmp/App.app"),
        })
        self.assertEqual([command[2] for command in calls if command[1:2] == ["stapler"]],
                         ["staple", "validate"])
        self.assertIn("--assess", calls[-1])

    def test_frameworks_are_signed_inside_out_and_thin_binaries_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "App.app"
            framework = app / "Contents/Frameworks/Core.framework"
            framework.mkdir(parents=True)
            binary = framework / "Core"
            binary.write_bytes(b"\xcf\xfa\xed\xfe")
            with patch.object(self.module, "run", return_value="arm64 x86_64"):
                self.assertEqual(self.module.code_objects(app), [binary, framework, app])
            with patch.object(self.module, "run", return_value="arm64"):
                with self.assertRaisesRegex(RuntimeError, "slices"):
                    self.module.code_objects(app)

    def test_bundle_version_mismatch_fails_before_loading_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "native-signing-test"
            contents = root / "products/App.app/Contents"
            contents.mkdir(parents=True)
            (contents / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "41",
            }))
            environment = dict(SIGNING_TEMP=str(root), RUNNER_TEMP=directory, APP_NAME="App",
                               VAULT_URI="https://" + "synthetic-vault" + ".vault.azure.net",
                               APPLE_ID="synthetic@example.invalid", APPLE_TEAM_ID="SYNTHETIC0",
                               APPLE_SIGNING_IDENTITY="Developer ID Application: Fixture (SYNTHETIC0)",
                               GITHUB_REF_NAME="v1.2.3", GITHUB_RUN_NUMBER="42")
            with patch.dict(os.environ, environment), patch.object(self.module, "fetch_secret") as fetch:
                with self.assertRaisesRegex(RuntimeError, "build version"):
                    self.module.main()
            fetch.assert_not_called()

    def test_cleanup_restores_search_list_even_if_keychain_deletion_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "native-signing-test"
            root.mkdir()
            (root / "keychains.json").write_text(json.dumps(["original.keychain-db"]))
            (root / "signing.keychain-db").touch()
            (root / "certificate.pem").write_bytes(os.urandom(32))
            results = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
            with patch.dict(os.environ, SIGNING_TEMP=str(root), RUNNER_TEMP=directory):
                with patch("subprocess.run", side_effect=results) as run:
                    with self.assertRaisesRegex(RuntimeError, "delete"):
                        exec(step_script("Remove temporary native credentials"), {})
            self.assertEqual(run.call_args_list[1].args[0][-1], "original.keychain-db")
            self.assertFalse((root / "certificate.pem").exists())

    def test_published_releases_and_lookup_failures_cannot_upload(self):
        for response in (
            subprocess.CompletedProcess([], 0, '[[{"tag_name":"v1.2.3","draft":false}]]', ""),
            subprocess.CompletedProcess([], 1, "", "Forbidden"),
        ):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "native-release"
                output.mkdir()
                (output / "App-v1.2.3-universal-macos.zip").touch()
                environment = dict(RUNNER_TEMP=directory, APP_NAME="App",
                                   GITHUB_REF_NAME="v1.2.3", GITHUB_REPOSITORY="owner/app")
                options = {"return_value": response} if response.returncode == 0 else {
                    "side_effect": subprocess.CalledProcessError(response.returncode, ["gh"])}
                with patch.dict(os.environ, environment), patch("subprocess.run", **options) as run:
                    with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                        exec(step_script("Create or update release asset"), {})
                self.assertEqual(run.call_count, 1)

    def test_existing_draft_on_later_page_is_reused_and_duplicates_fail(self):
        release = {"tag_name": "v1.2.3", "draft": True}
        for pages in ([[], [release]], [[release], [release]]):
            with self.subTest(pages=pages), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "native-release"
                output.mkdir()
                (output / "App-v1.2.3-universal-macos.zip").touch()
                environment = dict(RUNNER_TEMP=directory, APP_NAME="App", RELEASE_DRAFT="true",
                                   GITHUB_REF_NAME="v1.2.3", GITHUB_REPOSITORY="owner/app")
                response = subprocess.CompletedProcess([], 0, json.dumps(pages), "")
                with patch.dict(os.environ, environment), patch("subprocess.run", return_value=response) as run:
                    if len(pages[0]) > 0:
                        with self.assertRaisesRegex(RuntimeError, "Multiple releases"):
                            exec(step_script("Create or update release asset"), {})
                        self.assertEqual(run.call_count, 1)
                    else:
                        exec(step_script("Create or update release asset"), {})
                        self.assertEqual(run.call_args_list[1].args[0][1:3], ["release", "upload"])
                        self.assertEqual(run.call_count, 2)

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS Keychain and notarytool")
    def test_real_native_tools_accept_synthetic_credentials_without_secret_arguments(self):
        original_run = subprocess.run
        calls = []

        def run(arguments, **kwargs):
            calls.append(arguments)
            return original_run(arguments, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            password = secrets.token_hex(24) + " ' \" $ \\"
            environment = dict(os.environ, FIXTURE_PASSWORD=password)
            config = (
                "[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\n"
                "[ext]\nbasicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n"
            )
            original_run(
                ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(root / "fixture.key"), "-out", str(root / "fixture.crt"),
                 "-days", "1", "-subj", "/CN=Native Signing Fixture", "-config", "/dev/stdin"],
                input=config, text=True, capture_output=True, check=True,
            )
            original_run(
                ["/usr/bin/openssl", "pkcs12", "-export", "-inkey", str(root / "fixture.key"),
                 "-in", str(root / "fixture.crt"), "-out", str(root / "fixture.p12"),
                 "-passout", "env:FIXTURE_PASSWORD"],
                env=environment, capture_output=True, check=True,
            )
            keychain = root / "signing.keychain-db"
            try:
                with patch.object(self.module.subprocess, "run", side_effect=run):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.module.import_identity(root, base64.b64encode(
                            (root / "fixture.p12").read_bytes()).decode(), password)
                    search_list = shlex.split(self.module.run(
                        ["/usr/bin/security", "list-keychains", "-d", "user"]))
                    actual_keychains = [Path(path).resolve() for path in search_list]
                    self.assertTrue(keychain.resolve() in actual_keychains,
                                    "codesign must be able to find the imported certificate chain")
                    original_keychains = json.loads((root / "keychains.json").read_text())
                    expected_keychains = [keychain.resolve(), *[Path(path).resolve() for path in original_keychains]]
                    self.assertTrue(actual_keychains == expected_keychains,
                                    "The original keychain search list must be preserved")
                    identities = self.module.run(
                        ["/usr/bin/security", "find-identity", "-p", "codesigning", str(keychain)])
                    self.assertIn("Native Signing Fixture", identities)
                    self.module.run(
                        ["/usr/bin/xcrun", "notarytool", "store-credentials", "native-test",
                         "--apple-id", "synthetic@example.invalid", "--team-id", "SYNTHETIC0",
                         "--keychain", str(keychain), "--no-validate"],
                        input=password + "\n",
                    )
                    app = root / "products/App.app"
                    (app / "Contents").mkdir(parents=True)
                    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
                        "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "42",
                    }))
                    environment = dict(SIGNING_TEMP=str(root), RUNNER_TEMP=directory, APP_NAME="App",
                                       VAULT_URI="https://" + "synthetic-vault" + ".vault.azure.net",
                                       APPLE_ID="synthetic@example.invalid", APPLE_TEAM_ID="SYNTHETIC0",
                                       APPLE_SIGNING_IDENTITY="Developer ID Application: Fixture (SYNTHETIC0)",
                                       GITHUB_REF_NAME="v1.2.3", GITHUB_RUN_NUMBER="42")
                    with patch.dict(os.environ, environment):
                        with patch.object(self.module, "import_identity", return_value=keychain):
                            with patch.object(self.module, "fetch_secret", return_value=password):
                                with patch.object(self.module, "code_objects", return_value=[app]):
                                    with patch.object(self.module, "notarize"):
                                        with patch.object(self.module, "run", return_value=(
                                                '"Developer ID Application: Fixture (SYNTHETIC0)"')):
                                            with patch.object(self.module, "codesign") as signing:
                                                self.module.main()
                    self.assertEqual(signing.call_count, 3)
                    sign, verify, developer_id = signing.call_args_list
                    self.assertEqual(sign.args[0], [
                        "--force", "--sign", environment["APPLE_SIGNING_IDENTITY"], "--keychain", str(keychain),
                        "--options", "runtime", "--timestamp",
                    ])
                    self.assertEqual(sign.kwargs, {"operation": "sign", "path": app, "app": app})
                    self.assertEqual(verify.args[0], ["--verify", "--deep", "--strict"])
                    self.assertEqual(verify.kwargs, {"operation": "verify signed bundle", "path": app, "app": app})
                    self.assertEqual(developer_id.args[0][:3], ["--verify", "--strict", "-R"])
                    self.assertEqual(developer_id.kwargs, {"operation": "verify Developer ID", "path": app,
                                                         "app": app})
                    requirement = next(call.args[0] for call in signing.call_args_list if "-R" in call.args[0])
                    self.module.run(["/usr/bin/csreq", "-r", requirement[-1], "-t"])
                for arguments in calls:
                    self.assertNotIn(password, " ".join(arguments))
            finally:
                if keychain.exists():
                    original_run(["/usr/bin/security", "delete-keychain", str(keychain)],
                                 capture_output=True, check=True)
                snapshot = root / "keychains.json"
                if snapshot.exists():
                    original_run(
                        ["/usr/bin/security", "list-keychains", "-d", "user", "-s",
                         *json.loads(snapshot.read_text())], capture_output=True, check=True,
                    )

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS codesign")
    def test_real_codesign_failure_is_labeled_without_absolute_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Fixture.app"
            target = app / "Contents/MacOS/unsigned"
            target.parent.mkdir(parents=True)
            target.write_bytes(os.urandom(24))
            with self.assertRaises(RuntimeError) as error:
                self.module.codesign(["--verify", "--strict"],
                                     operation="verify signed bundle", path=target, app=app)
        self.assertIn("Contents/MacOS/unsigned", str(error.exception))
        self.assertIn("exit 1", str(error.exception))
        self.assertIn("code object is not signed at all", str(error.exception))
        self.assertNotIn(directory, str(error.exception))


if __name__ == "__main__":
    unittest.main()
