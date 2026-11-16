import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import secrets
import shlex
import shutil
import stat
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


@contextlib.contextmanager
def native_fixture():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "native-signing-test"
        app = root / "products/Test App.app"
        contents = app / "Contents"
        contents.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "42",
        }))
        environment = dict(SIGNING_TEMP=str(root), RUNNER_TEMP=directory, APP_NAME="Test App",
                           VAULT_URI="https://" + "synthetic-vault" + ".vault.azure.net",
                           APPLE_ID="synthetic@example.invalid", APPLE_TEAM_ID="SYNTHETIC0",
                           APPLE_SIGNING_IDENTITY="Developer ID Application: Fixture (SYNTHETIC0)",
                           GITHUB_REF_NAME="v1.2.3", GITHUB_RUN_NUMBER="42")
        with patch.dict(os.environ, environment):
            yield root, app


class NativeSigningTests(unittest.TestCase):
    def setUp(self):
        self.module = signing_module()
        self.umask = os.umask(0o022)

    def tearDown(self):
        os.umask(self.umask)

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
                self.module.codesign(["--force", "--sign", value], operation="sign", path=path, root=app)
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
                    self.module.codesign(["--sign", value], operation="sign", path=app, root=app)
            self.assertIn('target "."', str(error.exception))
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
                self.module.codesign(["--verify"], operation="verify signed bundle", path=path, root=app)
        message = str(error.exception)
        self.assertLess(len(message), 2048)
        self.assertNotIn("\n", message)
        self.assertNotIn(chr(27), message)
        self.assertNotIn("no identity found", message)
        self.assertIn("...", message)

    def test_disk_image_diagnostic_uses_safe_artifact_relative_path(self):
        root = Path("/private/hidden/native-release")
        image = root / "Test App-v1.2.3-universal-macos.dmg"
        value = secrets.token_hex(24)
        result = subprocess.CompletedProcess([], 1, str(image), value + " no identity found")
        with patch.object(self.module.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as error:
                self.module.codesign(["--sign", value], operation="sign disk image", path=image, root=root)
        self.assertIn(image.name, str(error.exception))
        self.assertIn("no identity found", str(error.exception))
        self.assertNotIn(str(root), str(error.exception))
        self.assertNotIn(value, str(error.exception))

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
            "operation": "verify stapled bundle", "path": Path("/tmp/App.app"), "root": Path("/tmp/App.app"),
        })
        self.assertEqual([command[2] for command in calls if command[1:2] == ["stapler"]],
                         ["staple", "validate"])
        self.assertIn("--assess", calls[-1])

    def test_distribution_modes_preserve_executables_and_do_not_follow_links(self):
        with native_fixture() as (root, app):
            binary = app / "Contents/MacOS/Test"
            binary.parent.mkdir(mode=0o700)
            binary.write_bytes(os.urandom(24))
            binary.chmod(0o710)
            ticket = app / "Contents/_CodeSignature/CodeResources"
            ticket.parent.mkdir(mode=0o700)
            ticket.write_bytes(os.urandom(24))
            ticket.chmod(0o600)
            external = root / "external"
            external.mkdir(mode=0o700)
            target = external / "resource"
            target.write_bytes(os.urandom(24))
            target.chmod(0o600)
            (app / "Contents/directory-link").symlink_to(external, target_is_directory=True)
            (app / "Contents/file-link").symlink_to(target)
            self.module.distribution_modes(app)
            self.assertEqual(stat.S_IMODE(app.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(ticket.parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(ticket.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)
            self.assertTrue((app / "Contents/directory-link").is_symlink())

    def test_packaging_orders_both_notarizations_and_stops_on_failure(self):
        for failure in (None, "app-submit", "image-submit", "image-sign", "image-staple"):
            with self.subTest(failure=failure), native_fixture() as (root, app):
                events = []

                def run(arguments, **kwargs):
                    events.append(arguments)
                    if "find-identity" in arguments:
                        return '"' + os.environ["APPLE_SIGNING_IDENTITY"] + '"'
                    if arguments[0] == "/usr/bin/ditto":
                        if "-c" in arguments:
                            Path(arguments[-1]).write_bytes(os.urandom(24))
                        else:
                            shutil.copytree(arguments[-2], arguments[-1], symlinks=True)
                    if arguments[:2] == ["/usr/bin/hdiutil", "create"]:
                        Path(arguments[-1]).write_bytes(os.urandom(24))
                    if arguments[1:3] == ["notarytool", "submit"]:
                        kind = "image" if arguments[3].endswith(".dmg") else "app"
                        return json.dumps({"status": "Invalid" if failure == kind + "-submit" else "Accepted"})
                    if arguments[1:3] == ["stapler", "staple"]:
                        if arguments[-1].endswith(".dmg") and failure == "image-staple":
                            raise RuntimeError("stapling failed")
                        if arguments[-1].endswith(".app"):
                            ticket = app / "Contents/_CodeSignature/CodeResources"
                            ticket.parent.mkdir(mode=0o700)
                            ticket.write_bytes(os.urandom(24))
                            ticket.chmod(0o600)
                    return ""

                def codesign(options, **kwargs):
                    events.append(["codesign", kwargs["operation"]])
                    if failure == "image-sign" and kwargs["operation"] == "sign disk image":
                        raise RuntimeError("signing failed")

                with patch.object(self.module, "run", side_effect=run), \
                        patch.object(self.module, "codesign", side_effect=codesign), \
                        patch.object(self.module, "import_identity", return_value=root / "signing.keychain-db"), \
                        patch.object(self.module, "fetch_secret", return_value=secrets.token_hex(24)):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            self.module.main()
                    else:
                        self.module.main()
                submissions = [event for event in events if event[1:3] == ["notarytool", "submit"]]
                if failure == "app-submit":
                    self.assertEqual(len(submissions), 1)
                    self.assertFalse(any(event[1:2] == ["stapler"] for event in events))
                    self.assertFalse((root.parent / "native-release").exists())
                    continue
                app_staple = events.index(["/usr/bin/xcrun", "stapler", "staple", str(app)])
                zip_create = next(index for index, event in enumerate(events)
                                  if event[0] == "/usr/bin/ditto" and event[-1].endswith("macos.zip"))
                self.assertLess(app_staple, zip_create)
                self.assertLess(zip_create, events.index(["codesign", "sign disk image"]))
                if failure == "image-sign":
                    self.assertEqual(len(submissions), 1)
                    continue
                self.assertEqual(len(submissions), 2)
                self.assertTrue(submissions[-1][3].endswith(".dmg"))
                for submission in submissions:
                    self.assertIn("15m", submission)
                self.assertEqual(sum(event[1:3] == ["notarytool", "store-credentials"] for event in events), 1)
                if failure:
                    self.assertFalse(any(event[:2] == ["/usr/bin/hdiutil", "verify"] for event in events))
                    continue
                image = root.parent / "native-release/Test.App-v1.2.3-universal-macos.dmg"
                image_staple = events.index(["/usr/bin/xcrun", "stapler", "staple", str(image)])
                self.assertLess(events.index(submissions[-1]), image_staple)
                self.assertLess(image_staple, events.index(["codesign", "verify stapled disk image"]))
                self.assertEqual(events[-1], ["/usr/sbin/spctl", "--assess", "--type", "open",
                                             "--context", "context:primary-signature", str(image)])
                self.assertEqual(stat.S_IMODE((app / "Contents/_CodeSignature/CodeResources").stat().st_mode),
                                 0o644)

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

    def test_release_file_cleanup_removes_only_owned_output_and_input_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            for name in ("native-release", "native-input", "unrelated"):
                (temporary / name).mkdir()
                (temporary / name / "payload").write_bytes(os.urandom(24))
            (temporary / "native-release-notes.txt").write_text("notes")
            with patch.dict(os.environ, RUNNER_TEMP=directory):
                exec(step_script("Remove temporary native release files"), {})
            self.assertEqual(list(temporary.iterdir()), [temporary / "unrelated"])
            (temporary / "native-release").symlink_to(temporary / "unrelated", target_is_directory=True)
            with patch.dict(os.environ, RUNNER_TEMP=directory):
                exec(step_script("Remove temporary native release files"), {})
            self.assertTrue((temporary / "unrelated/payload").is_file())
            self.assertFalse((temporary / "native-release").is_symlink())

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
                                            with patch.object(self.module, "codesign") as signing, \
                                                    patch.object(self.module, "create_disk_image"), \
                                                    patch.object(self.module, "submit_and_staple"):
                                                self.module.main()
                    self.assertEqual(signing.call_count, 8)
                    sign, verify, developer_id = signing.call_args_list[:3]
                    self.assertEqual(sign.args[0], [
                        "--force", "--sign", environment["APPLE_SIGNING_IDENTITY"], "--keychain", str(keychain),
                        "--options", "runtime", "--timestamp",
                    ])
                    self.assertEqual(sign.kwargs, {"operation": "sign", "path": app, "root": app})
                    self.assertEqual(verify.args[0], ["--verify", "--deep", "--strict"])
                    self.assertEqual(verify.kwargs, {"operation": "verify signed bundle", "path": app, "root": app})
                    self.assertEqual(developer_id.args[0][:3], ["--verify", "--strict", "-R"])
                    self.assertEqual(developer_id.kwargs, {"operation": "verify Developer ID", "path": app,
                                                         "root": app})
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
                                     operation="verify signed bundle", path=target, root=app)
        self.assertIn("Contents/MacOS/unsigned", str(error.exception))
        self.assertIn("exit 1", str(error.exception))
        self.assertIn("code object is not signed at all", str(error.exception))
        self.assertNotIn(directory, str(error.exception))

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS disk image tools")
    def test_real_disk_image_and_zip_preserve_app_tree_modes_and_symlinks(self):
        def tree_snapshot(root):
            entries = {}
            for path in [root, *root.rglob("*")]:
                relative = str(path.relative_to(root))
                mode = stat.S_IMODE(path.lstat().st_mode)
                if path.is_symlink():
                    entries[relative] = ("link", os.readlink(path))
                elif path.is_dir():
                    entries[relative] = ("directory", mode)
                else:
                    entries[relative] = ("file", mode, hashlib.sha256(path.read_bytes()).hexdigest())
            return entries

        with native_fixture() as (root, app):
            original_run = self.module.run
            info = app / "Contents/Info.plist"
            info.write_bytes(plistlib.dumps({
                **plistlib.loads(info.read_bytes()), "CFBundleIdentifier": "example.native.fixture",
                "CFBundleExecutable": "Test", "CFBundlePackageType": "APPL",
            }))
            binary = app / "Contents/MacOS/Test"
            binary.parent.mkdir()
            shutil.copyfile("/usr/bin/true", binary)
            binary.chmod(0o700)
            framework = app / "Contents/Frameworks/Core.framework"
            version = framework / "Versions/A"
            version.mkdir(parents=True)
            shutil.copyfile("/usr/bin/true", version / "Core")
            (version / "Core").chmod(0o700)
            (version / "Resources").mkdir()
            (version / "Resources/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "example.native.framework", "CFBundleExecutable": "Core",
                "CFBundlePackageType": "FMWK", "CFBundleVersion": "1",
            }))
            (framework / "Versions/Current").symlink_to("A", target_is_directory=True)
            (framework / "Core").symlink_to("Versions/Current/Core")
            (framework / "Resources").symlink_to("Versions/Current/Resources", target_is_directory=True)
            original_run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(framework)])
            original_run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(app)])
            ticket = app / "Contents/_CodeSignature/CodeResources"
            ticket.parent.chmod(0o700)
            ticket.chmod(0o600)
            self.module.distribution_modes(app)
            self.module.codesign(["--verify", "--deep", "--strict"],
                                 operation="verify distributable bundle", path=app, root=app)
            expected = tree_snapshot(app)

            def run(arguments, **kwargs):
                # The fixture has no Apple ticket. All file and image tools run for real.
                if arguments[1:3] == ["stapler", "validate"]:
                    return ""
                return original_run(arguments, **kwargs)

            image = root / "Test App-v1.2.3-universal-macos.dmg"
            with patch.object(self.module, "run", side_effect=run):
                self.module.create_disk_image(app, root, image)
            self.module.codesign(["--force", "--sign", "-", "--timestamp=none"],
                                 operation="sign disk image", path=image, root=root)
            self.module.codesign(["--verify", "--strict"],
                                 operation="verify disk image", path=image, root=root)
            original_run(["/usr/bin/hdiutil", "verify", str(image)])
            archive = root / "Test App-v1.2.3-universal-macos.zip"
            original_run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)])
            extracted = root / "extracted"
            original_run(["/usr/bin/ditto", "-x", "-k", str(archive), str(extracted)])
            self.assertEqual(tree_snapshot(extracted / app.name), expected)
            self.module.codesign(["--verify", "--deep", "--strict"], operation="verify extracted bundle",
                                 path=extracted / app.name, root=extracted)
            mount = (root / "mounted").resolve()
            mount.mkdir()
            try:
                result = plistlib.loads(original_run([
                    "/usr/bin/hdiutil", "attach", str(image), "-readonly", "-nobrowse", "-noautoopen",
                    "-owners", "on", "-mountpoint", str(mount), "-plist",
                ]).encode())
                mounted = [entity for entity in result["system-entities"] if "mount-point" in entity]
                self.assertEqual([Path(entity["mount-point"]) for entity in mounted], [mount])
                self.assertEqual(stat.S_IMODE(mount.stat().st_mode), 0o755)
                self.assertEqual({path.name for path in mount.iterdir()}, {app.name, "Applications"})
                self.assertEqual(os.readlink(mount / "Applications"), "/Applications")
                self.assertTrue((mount / "Applications").is_dir())
                self.assertEqual(tree_snapshot(mount / app.name), expected)
                self.module.codesign(["--verify", "--deep", "--strict"], operation="verify mounted bundle",
                                     path=mount / app.name, root=mount)
                self.assertEqual(subprocess.run(["/sbin/mount"], text=True, capture_output=True,
                                                check=True).stdout.count(f" on {mount} "), 1)
                with self.assertRaises(OSError):
                    (mount / "should-not-write").touch()
            finally:
                if os.path.ismount(mount):
                    result = subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)], capture_output=True)
                    if result.returncode:
                        original_run(["/usr/bin/hdiutil", "detach", "-force", str(mount)])
                    self.assertFalse(os.path.ismount(mount))


class NativePublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "native-release"
        self.output.mkdir()
        self.assets = [self.output / ("Test.App-v1.2.3-universal-macos" + suffix)
                       for suffix in (".zip", ".dmg")]
        for asset in self.assets:
            asset.write_bytes(os.urandom(32))
        self.environment = patch.dict(os.environ, RUNNER_TEMP=self.directory.name, APP_NAME="Test App",
                                      RELEASE_DRAFT="true", RELEASE_NAME="Test App", RELEASE_BODY="Install the DMG.",
                                      GITHUB_REF_NAME="v1.2.3", GITHUB_REPOSITORY="owner/app")
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.pages = [[], [{"tag_name": "v1.2.3", "draft": True}]]
        self.remote_assets = [
            {"name": asset.name, "state": "uploaded", "size": asset.stat().st_size,
             "digest": "sha256:" + hashlib.sha256(asset.read_bytes()).hexdigest()}
            for asset in self.assets
        ]

    def gh(self, arguments, **_):
        if arguments[1] == "api":
            value = [self.remote_assets] if arguments[-1].endswith("/assets") else self.pages
        elif arguments[1:3] == ["release", "view"]:
            value = {"isDraft": True, "databaseId": 123}
        else:
            value = ""
        return subprocess.CompletedProcess(arguments, 0, json.dumps(value), "")

    def publish(self):
        exec(step_script("Create or update release asset"), {})

    def test_incomplete_empty_symlink_and_extra_local_assets_cannot_call_github(self):
        for kind in ("missing", "empty", "symlink", "extra"):
            with self.subTest(kind=kind):
                image = self.assets[-1]
                original = image.read_bytes()
                if kind == "missing":
                    image.unlink()
                elif kind == "empty":
                    image.write_bytes(b"")
                elif kind == "symlink":
                    image.unlink()
                    image.symlink_to(self.assets[0])
                else:
                    (self.output / "unexpected.txt").write_text("extra")
                with patch("subprocess.run") as run:
                    with self.assertRaisesRegex(RuntimeError, "exactly"):
                        self.publish()
                run.assert_not_called()
                if image.is_symlink():
                    image.unlink()
                image.write_bytes(original)
                (self.output / "unexpected.txt").unlink(missing_ok=True)

    def test_published_duplicates_and_failed_lookup_cannot_mutate_releases(self):
        draft = {"tag_name": "v1.2.3", "draft": True}
        for pages in ([[{**draft, "draft": False}]], [[draft], [draft]], None):
            with self.subTest(pages=pages):
                self.pages = pages
                options = {"side_effect": self.gh if pages is not None else
                           subprocess.CalledProcessError(1, ["gh"])}
                with patch("subprocess.run", **options) as run:
                    with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                        self.publish()
                self.assertEqual(run.call_count, 1)

    def test_retry_replaces_only_known_assets_and_preserves_notes_and_unrelated_assets(self):
        self.remote_assets.append({"name": "unrelated.txt"})
        with patch("subprocess.run", side_effect=self.gh) as run:
            self.publish()
        commands = [call.args[0] for call in run.call_args_list]
        uploads = [command for command in commands if command[1:3] == ["release", "upload"]]
        self.assertEqual(uploads, [["gh", "release", "upload", "v1.2.3", *map(str, self.assets),
                                    "--repo", "owner/app", "--clobber"]])
        self.assertFalse(any(command[1:3] in (["release", "create"], ["release", "edit"],
                                            ["release", "delete-asset"]) for command in commands))

    def test_new_release_remains_draft_until_both_assets_are_verified_and_explicitly_published(self):
        self.pages = [[]]
        with patch.dict(os.environ, RELEASE_DRAFT="false"), patch("subprocess.run", side_effect=self.gh) as run:
            self.publish()
        commands = [call.args[0] for call in run.call_args_list]
        create = next(command for command in commands if command[1:3] == ["release", "create"])
        self.assertIn("--draft", create)
        self.assertIn("--generate-notes", create)
        self.assertEqual((Path(self.directory.name) / "native-release-notes.txt").read_text(),
                         "Install the DMG.")
        self.assertTrue(commands[-2][-1].endswith("/assets"))
        self.assertEqual(commands[-1][1:3], ["release", "edit"])
        self.assertIn("--draft=false", commands[-1])

    def test_upload_and_remote_verification_failures_never_publish(self):
        for failure in ("upload", "missing", "duplicate", "state", "size", "digest", "no-digest", "published"):
            with self.subTest(failure=failure):
                remote = [dict(asset) for asset in self.remote_assets]
                if failure == "missing":
                    remote.pop()
                elif failure == "duplicate":
                    remote[-1] = dict(remote[0])
                elif failure in ("state", "size", "digest"):
                    remote[-1][failure] = "incorrect"
                elif failure == "no-digest":
                    remote[-1]["digest"] = None
                calls = []

                def run(arguments, **kwargs):
                    calls.append(arguments)
                    if failure == "upload" and arguments[1:3] == ["release", "upload"]:
                        raise subprocess.CalledProcessError(1, ["gh"])
                    if arguments[-1].endswith("/assets"):
                        return subprocess.CompletedProcess(arguments, 0, json.dumps([remote]), "")
                    if failure == "published" and arguments[1:3] == ["release", "view"]:
                        return subprocess.CompletedProcess(arguments, 0, '{"isDraft":false}', "")
                    return self.gh(arguments, **kwargs)

                with patch.dict(os.environ, RELEASE_DRAFT="false"), patch("subprocess.run", side_effect=run):
                    with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                        self.publish()
                self.assertFalse(any(command[1:3] == ["release", "edit"] for command in calls))
                if failure == "published":
                    self.assertFalse(any(command[1:3] == ["release", "upload"] for command in calls))


if __name__ == "__main__":
    unittest.main()
