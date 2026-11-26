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
import struct
import subprocess
import sys
import tempfile
import tarfile
import types
import unittest
import zlib
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
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def execute_step(name, environment):
    module = types.ModuleType("embedded_step")
    with patch.dict(os.environ, environment):
        exec(compile(step_script(name), str(WORKFLOW), "exec"), module.__dict__)
    return module


def write_png(path, width, height):
    def chunk(name, data):
        body = name + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    row = b"\x00" + bytes((48, 96, 144)) * width
    image = b"".join(row for _ in range(height))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">2I5B", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(image))
        + chunk(b"IEND", b"")
    )


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
                           GITHUB_REF_NAME="v1.2.3", GITHUB_RUN_NUMBER="42", DMG_LAYOUT_ENABLED="false")
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

    def test_bundle_digest_covers_contents_modes_symlinks_and_extended_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Fixture.app"
            contents = app / "Contents"
            contents.mkdir(parents=True)
            file = contents / "resource"
            file.write_bytes(b"fixture")
            first = self.module.bundle_digest(app)
            file.write_bytes(b"changed")
            second = self.module.bundle_digest(app)
            self.assertNotEqual(first, second)
            file.write_bytes(b"fixture")
            (contents / "link").symlink_to("resource")
            self.assertNotEqual(first, self.module.bundle_digest(app))
            (contents / "link").unlink()
            file.chmod(0o600)
            self.assertNotEqual(first, self.module.bundle_digest(app))
            file.chmod(0o644)
            if hasattr(os, "setxattr"):
                attribute = "com.apple.FinderInfo" if sys.platform == "darwin" else "user.fixture"
                os.setxattr(file, attribute, bytes(32))
                self.assertNotEqual(first, self.module.bundle_digest(app))
            elif sys.platform == "darwin":
                subprocess.run([
                    "/usr/bin/xattr", "-w", "com.example.fixture", "value", str(file),
                ], check=True)
                self.assertNotEqual(first, self.module.bundle_digest(app))

    def test_optional_finder_inputs_and_metadata_contract_are_static_and_fail_closed(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("dmg-background-path:", workflow)
        self.assertIn("dmg-background-2x-path:", workflow)
        self.assertIn('default: ""', workflow)
        self.assertIn('set toolbar visible of dmgWindow to false', workflow)
        self.assertIn('set sidebar width of dmgWindow to 0', workflow)
        self.assertIn('set statusbar visible of dmgWindow to false', workflow)
        self.assertIn('set pathbar visible of dmgWindow to false', workflow)
        self.assertIn("windowHeight to (item 4 of argv) as integer", workflow)
        self.assertIn("set position of item appBundle of dmgWindow to {appX, appY}", workflow)
        self.assertIn('set position of item "Applications" of dmgWindow to {applicationsX, applicationsY}', workflow)
        self.assertNotIn("SetFile", workflow)
        self.assertNotIn("extension hidden", workflow.casefold())
        self.assertNotIn("--hide-extension", workflow)
        for name in ("Package unsigned app and optional Finder layout",
                     "Extract unsigned bundle", "Sign and notarize native app"):
            compile(step_script(name), str(WORKFLOW), "exec")

    @unittest.skipUnless(
        sys.platform == "darwin" and os.environ.get("NATIVE_FINDER_INTEGRATION") == "1",
        "Requires the hosted macOS Finder integration job",
    )
    def test_hosted_finder_layout_persists_without_signing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "caller"
            app = root / "runner/native-build/Build/Products/Release/Test App.app"
            (app / "Contents").mkdir(parents=True)
            (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "example.native.fixture",
                "CFBundlePackageType": "APPL",
            }))
            background = workspace / "background.png"
            background_2x = workspace / "background@2x.png"
            workspace.mkdir()
            write_png(background, 680, 400)
            write_png(background_2x, 1360, 800)
            output = root / "github-output"
            environment = {
                "APP_NAME": "Test App",
                "RUNNER_TEMP": str(root / "runner"),
                "GITHUB_OUTPUT": str(output),
                "DMG_BACKGROUND_PATH": "background.png",
                "DMG_BACKGROUND_2X_PATH": "background@2x.png",
                "DMG_WINDOW_WIDTH": "680",
                "DMG_WINDOW_HEIGHT": "428",
                "DMG_ICON_SIZE": "120",
                "DMG_TEXT_SIZE": "13",
                "DMG_APP_X": "180",
                "DMG_APP_Y": "170",
                "DMG_APPLICATIONS_X": "500",
                "DMG_APPLICATIONS_Y": "170",
            }
            with working_directory(workspace):
                execute_step("Package unsigned app and optional Finder layout", environment)
            layout = root / "runner/finder-layout.dmg"
            metadata = root / "runner/finder-layout"
            self.assertTrue(layout.is_file())
            self.assertTrue((metadata / ".DS_Store").is_file())
            self.assertTrue((metadata / ".background/background.tiff").is_file())
            stored_layout = (metadata / ".DS_Store").read_bytes()
            for record in (b"pBBk", b"bwsp", b"Iloc"):
                self.assertIn(record, stored_layout)
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(values["layout-enabled"], "true")
            self.assertNotIn("layout-sha256", values)
            self.assertEqual(
                values["ds-store-sha256"],
                hashlib.sha256((metadata / ".DS_Store").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                values["background-sha256"],
                hashlib.sha256((metadata / ".background/background.tiff").read_bytes()).hexdigest(),
            )

            signing = signing_module()
            image = root / "final-macos.dmg"
            mount = root / "final-image-mount"
            original_run = signing.run

            def run(arguments, **kwargs):
                if (arguments[1:3] == ["stapler", "validate"]
                        or arguments[:2] == ["/usr/sbin/spctl", "--assess"]):
                    return ""
                return original_run(arguments, **kwargs)

            verify_script = r'''
          on run argv
            set mountPath to item 1 of argv
            set appBundle to item 2 of argv
            tell application "Finder"
              activate
              open (POSIX file mountPath as alias)
              delay 2
              set dmgWindow to front window
              if (bounds of dmgWindow) is not {200, 120, 880, 548} then error "Final Finder bounds changed."
              if toolbar visible of dmgWindow or sidebar width of dmgWindow is not 0 or ¬
                  statusbar visible of dmgWindow or pathbar visible of dmgWindow then error "Final Finder chrome changed."
              if (icon size of icon view options of dmgWindow) is not 120 or ¬
                  (text size of icon view options of dmgWindow) is not 13 then error "Final Finder icon settings changed."
              if (position of item appBundle of dmgWindow) is not {180, 170} or ¬
                  (position of item "Applications" of dmgWindow) is not {500, 170} then error "Final Finder icon positions changed."
              close dmgWindow
            end tell
          end run
          '''
            with patch.dict(os.environ, {
                    "RUNNER_TEMP": str(root),
                    "FINDER_DS_STORE_SHA256": values["ds-store-sha256"],
                    "FINDER_BACKGROUND_SHA256": values["background-sha256"],
            }), patch.object(signing, "codesign"), patch.object(signing, "run", side_effect=run):
                expected_digest, expected_layout = signing.create_disk_image(
                    app, root, image, metadata
                )
                signing.verify_disk_image(image, app, root, expected_digest, expected_layout)
                with signing.mounted_image(image, mount, readonly=True):
                    result = subprocess.run([
                        "/usr/bin/osascript", "-", str(mount.resolve()), app.name,
                    ], input=verify_script, text=True, capture_output=True, timeout=180)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_unsigned_artifact_stays_app_only_and_is_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "caller"
            app = root / "runner/native-build/Build/Products/Release/Test App.app"
            (app / "Contents").mkdir(parents=True)
            (app / "Contents/Info.plist").write_bytes(b"fixture")
            outputs = root / "outputs"
            workspace.mkdir()
            with working_directory(workspace):
                environment = {
                    "APP_NAME": "Test App",
                    "RUNNER_TEMP": str(root / "runner"),
                    "GITHUB_OUTPUT": str(outputs),
                    "DMG_BACKGROUND_PATH": "",
                    "DMG_BACKGROUND_2X_PATH": "",
                    "DMG_WINDOW_WIDTH": "680",
                    "DMG_WINDOW_HEIGHT": "428",
                    "DMG_ICON_SIZE": "120",
                    "DMG_TEXT_SIZE": "13",
                    "DMG_APP_X": "180",
                    "DMG_APP_Y": "170",
                    "DMG_APPLICATIONS_X": "500",
                    "DMG_APPLICATIONS_Y": "170",
                }
                execute_step("Package unsigned app and optional Finder layout", environment)
            archive_path = root / "runner/unsigned-app.tar"
            with tarfile.open(archive_path) as archive:
                self.assertTrue(archive.getnames())
                self.assertTrue(all(name.startswith("Test App.app") for name in archive.getnames()))
            output_values = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
            self.assertEqual(output_values["layout-enabled"], "false")
            self.assertNotIn("layout-sha256", output_values)
            self.assertEqual(output_values["app-sha256"], hashlib.sha256(archive_path.read_bytes()).hexdigest())
            self.assertFalse((root / "runner/finder-layout.dmg").exists())

    def test_invalid_finder_artwork_inputs_fail_before_packaging(self):
        for case in ("one-sided", "traversal", "symlink", "missing", "not-directory", "not-png", "empty",
                     "oversize", "malformed-integer", "fractional", "negative", "too-wide",
                     "app-below-content", "applications-below-content"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                workspace = root / "caller"
                workspace.mkdir()
                app = root / "runner/native-build/Build/Products/Release/Test App.app"
                (app / "Contents").mkdir(parents=True)
                (app / "Contents/Info.plist").write_bytes(b"fixture")
                (workspace / "one.png").write_bytes(b"not a PNG")
                (workspace / "two.png").write_bytes(b"not a PNG")
                environment = {
                    "APP_NAME": "Test App",
                    "RUNNER_TEMP": str(root / "runner"),
                    "GITHUB_OUTPUT": str(root / "outputs"),
                    "DMG_BACKGROUND_PATH": "one.png",
                    "DMG_BACKGROUND_2X_PATH": "two.png",
                    "DMG_WINDOW_WIDTH": "680",
                    "DMG_WINDOW_HEIGHT": "428",
                    "DMG_ICON_SIZE": "120",
                    "DMG_TEXT_SIZE": "13",
                    "DMG_APP_X": "180",
                    "DMG_APP_Y": "170",
                    "DMG_APPLICATIONS_X": "500",
                    "DMG_APPLICATIONS_Y": "170",
                }
                if case == "one-sided":
                    environment["DMG_BACKGROUND_2X_PATH"] = ""
                elif case == "traversal":
                    environment["DMG_BACKGROUND_PATH"] = "../outside.png"
                elif case == "symlink":
                    (workspace / "link.png").symlink_to("one.png")
                    environment["DMG_BACKGROUND_PATH"] = "link.png"
                elif case == "missing":
                    environment["DMG_BACKGROUND_PATH"] = "missing.png"
                elif case == "not-directory":
                    environment["DMG_BACKGROUND_PATH"] = "one.png/child.png"
                elif case == "empty":
                    (workspace / "one.png").write_bytes(b"")
                elif case == "oversize":
                    with (workspace / "one.png").open("wb") as stream:
                        stream.truncate(20 * 1024 * 1024 + 1)
                elif case in ("malformed-integer", "fractional", "negative", "too-wide",
                              "app-below-content", "applications-below-content"):
                    (workspace / "one.png").write_bytes(b"\x89PNG\r\n\x1a\n")
                    (workspace / "two.png").write_bytes(b"\x89PNG\r\n\x1a\n")
                if case == "malformed-integer":
                    environment["DMG_WINDOW_WIDTH"] = "invalid"
                elif case == "fractional":
                    environment["DMG_ICON_SIZE"] = "120.5"
                elif case == "negative":
                    environment["DMG_APP_X"] = "-1"
                elif case == "too-wide":
                    environment["DMG_APPLICATIONS_X"] = "681"
                elif case == "app-below-content":
                    environment["DMG_APP_Y"] = "401"
                elif case == "applications-below-content":
                    environment["DMG_APPLICATIONS_Y"] = "401"
                expected = {
                    "one-sided": "Both 1x and 2x",
                    "traversal": "safe relative path",
                    "symlink": "symbolic links",
                    "missing": "existing file",
                    "not-directory": "existing file",
                    "not-png": "PNG image",
                    "empty": "non-empty file",
                    "oversize": "no larger than 20 MiB",
                    "malformed-integer": "must be an integer",
                    "fractional": "must be an integer",
                    "negative": "must be an integer",
                    "too-wide": "outside the supported range",
                    "app-below-content": "outside the supported range",
                    "applications-below-content": "outside the supported range",
                }[case]
                with working_directory(workspace), self.assertRaisesRegex(RuntimeError, expected):
                    execute_step("Package unsigned app and optional Finder layout", environment)
                self.assertFalse((root / "runner/finder-layout.dmg").exists())

    def test_nondefault_finder_geometry_accepts_matching_artwork(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "caller"
            workspace.mkdir()
            app = root / "runner/native-build/Build/Products/Release/Test App.app"
            (app / "Contents").mkdir(parents=True)
            (app / "Contents/Info.plist").write_bytes(b"fixture")
            write_png(workspace / "one.png", 500, 300)
            write_png(workspace / "two.png", 1000, 600)
            environment = {
                "APP_NAME": "Test App",
                "RUNNER_TEMP": str(root / "runner"),
                "GITHUB_OUTPUT": str(root / "outputs"),
                "DMG_BACKGROUND_PATH": "one.png",
                "DMG_BACKGROUND_2X_PATH": "two.png",
                "DMG_WINDOW_WIDTH": "500",
                "DMG_WINDOW_HEIGHT": "328",
                "DMG_ICON_SIZE": "80",
                "DMG_TEXT_SIZE": "12",
                "DMG_APP_X": "100",
                "DMG_APP_Y": "150",
                "DMG_APPLICATIONS_X": "400",
                "DMG_APPLICATIONS_Y": "150",
            }

            def image_tools(arguments, **kwargs):
                if arguments[0] == "/usr/bin/sips":
                    dimensions = (500, 300) if arguments[-1].endswith("one.png") else (1000, 600)
                    return subprocess.CompletedProcess(
                        arguments, 0, f"pixelWidth: {dimensions[0]}\npixelHeight: {dimensions[1]}\n", ""
                    )
                if arguments[0] == "/usr/bin/tiffutil":
                    Path(arguments[-1]).write_bytes(b"II*\x00")
                    return subprocess.CompletedProcess(arguments, 0, "", "")
                if arguments[:2] == ["/usr/bin/hdiutil", "create"]:
                    raise RuntimeError("geometry accepted")
                raise AssertionError(f"Unexpected command: {arguments}")

            with working_directory(workspace), patch("subprocess.run", side_effect=image_tools):
                with self.assertRaisesRegex(RuntimeError, "geometry accepted"):
                    execute_step("Package unsigned app and optional Finder layout", environment)

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS image tools")
    def test_incorrect_retina_artwork_dimensions_fail_before_creating_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "caller"
            workspace.mkdir()
            app = root / "runner/native-build/Build/Products/Release/Test App.app"
            (app / "Contents").mkdir(parents=True)
            (app / "Contents/Info.plist").write_bytes(b"fixture")
            write_png(workspace / "one.png", 680, 400)
            write_png(workspace / "two.png", 1360, 799)
            environment = {
                "APP_NAME": "Test App",
                "RUNNER_TEMP": str(root / "runner"),
                "GITHUB_OUTPUT": str(root / "outputs"),
                "DMG_BACKGROUND_PATH": "one.png",
                "DMG_BACKGROUND_2X_PATH": "two.png",
                "DMG_WINDOW_WIDTH": "680",
                "DMG_WINDOW_HEIGHT": "428",
                "DMG_ICON_SIZE": "120",
                "DMG_TEXT_SIZE": "13",
                "DMG_APP_X": "180",
                "DMG_APP_Y": "170",
                "DMG_APPLICATIONS_X": "500",
                "DMG_APPLICATIONS_Y": "170",
            }
            with working_directory(workspace), self.assertRaisesRegex(RuntimeError, "exact 1x/2x sizes"):
                execute_step("Package unsigned app and optional Finder layout", environment)
            self.assertFalse((root / "runner/finder-layout.dmg").exists())

    def test_artifact_extraction_checks_cross_job_digest_and_exact_app_allowlist(self):
        for tamper in (False, True):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifact = root / "runner/native-input"
                artifact.mkdir(parents=True)
                app_prefix = "Test App.app"
                archive_path = artifact / "unsigned-app.tar"
                with tarfile.open(archive_path, "w") as archive:
                    app = tarfile.TarInfo(app_prefix)
                    app.type = tarfile.DIRTYPE
                    archive.addfile(app)
                    contents = tarfile.TarInfo(app_prefix + "/Contents")
                    contents.type = tarfile.DIRTYPE
                    archive.addfile(contents)
                    payload = tarfile.TarInfo(app_prefix + "/Contents/Info.plist")
                    payload.size = 7
                    archive.addfile(payload, io.BytesIO(b"fixture"))
                expected_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
                if tamper:
                    with archive_path.open("ab") as stream:
                        stream.write(b"altered")
                environment = {
                    "SIGNING_TEMP": str(root / "signing"),
                    "RUNNER_TEMP": str(root / "runner"),
                    "APP_NAME": "Test App",
                    "DMG_LAYOUT_ENABLED": "false",
                    "BUILD_LAYOUT_ENABLED": "false",
                    "UNSIGNED_APP_SHA256": expected_hash,
                    "FINDER_DS_STORE_SHA256": "",
                    "FINDER_BACKGROUND_SHA256": "",
                }
                if tamper:
                    with self.assertRaisesRegex(RuntimeError, "digest"):
                        execute_step("Extract unsigned bundle", environment)
                    self.assertFalse((root / "signing/products").exists())
                else:
                    execute_step("Extract unsigned bundle", environment)
                    self.assertEqual((root / "signing/products/Test App.app/Contents/Info.plist").read_bytes(),
                                     b"fixture")

    def test_artifact_extraction_accepts_internal_hardlinks_and_rejects_escaping_targets(self):
        for target in ("Test App.app/Contents/original", "../outside"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifact = root / "runner/native-input"
                artifact.mkdir(parents=True)
                archive_path = artifact / "unsigned-app.tar"
                with tarfile.open(archive_path, "w") as archive:
                    app = tarfile.TarInfo("Test App.app")
                    app.type = tarfile.DIRTYPE
                    archive.addfile(app)
                    contents = tarfile.TarInfo("Test App.app/Contents")
                    contents.type = tarfile.DIRTYPE
                    archive.addfile(contents)
                    original = tarfile.TarInfo("Test App.app/Contents/original")
                    original.size = 7
                    archive.addfile(original, io.BytesIO(b"fixture"))
                    link = tarfile.TarInfo("Test App.app/Contents/link")
                    link.type = tarfile.LNKTYPE
                    link.linkname = target
                    archive.addfile(link)
                environment = {
                    "SIGNING_TEMP": str(root / "signing"),
                    "RUNNER_TEMP": str(root / "runner"),
                    "APP_NAME": "Test App",
                    "DMG_LAYOUT_ENABLED": "false",
                    "BUILD_LAYOUT_ENABLED": "false",
                    "UNSIGNED_APP_SHA256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    "FINDER_DS_STORE_SHA256": "",
                    "FINDER_BACKGROUND_SHA256": "",
                }
                if target.startswith("../"):
                    with self.assertRaisesRegex(RuntimeError, "unsafe hard link"):
                        execute_step("Extract unsigned bundle", environment)
                else:
                    execute_step("Extract unsigned bundle", environment)
                    contents = root / "signing/products/Test App.app/Contents"
                    self.assertEqual((contents / "link").read_bytes(), b"fixture")
                    self.assertTrue(os.path.samefile(contents / "link", contents / "original"))

    def test_artifact_extraction_binds_custom_finder_metadata_to_build_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "runner/native-input"
            metadata = artifact / "finder-layout"
            background_dir = metadata / ".background"
            background_dir.mkdir(parents=True)
            archive_path = artifact / "unsigned-app.tar"
            with tarfile.open(archive_path, "w") as archive:
                app_dir = tarfile.TarInfo("Test App.app")
                app_dir.type = tarfile.DIRTYPE
                archive.addfile(app_dir)
            ds_store = metadata / ".DS_Store"
            ds_store.write_bytes(b"\x00\x00\x00\x01Bud1" + bytes(8))
            background = background_dir / "background.tiff"
            background.write_bytes(b"II*\x00" + bytes(16))
            environment = {
                "SIGNING_TEMP": str(root / "signing"),
                "RUNNER_TEMP": str(root / "runner"),
                "APP_NAME": "Test App",
                "DMG_LAYOUT_ENABLED": "true",
                "BUILD_LAYOUT_ENABLED": "true",
                "UNSIGNED_APP_SHA256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                "FINDER_DS_STORE_SHA256": hashlib.sha256(ds_store.read_bytes()).hexdigest(),
                "FINDER_BACKGROUND_SHA256": hashlib.sha256(background.read_bytes()).hexdigest(),
            }
            execute_step("Extract unsigned bundle", environment)
            self.assertTrue((root / "signing/products/Test App.app").is_dir())
            shutil.rmtree(root / "signing")
            background.write_bytes(b"II*\x00" + bytes(17))
            with self.assertRaisesRegex(RuntimeError, "metadata digest"):
                execute_step("Extract unsigned bundle", environment)

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
                        patch.object(self.module, "fetch_secret", return_value=secrets.token_hex(24)), \
                        patch.object(self.module, "verify_disk_image"):
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
                               GITHUB_REF_NAME="v1.2.3", GITHUB_RUN_NUMBER="42",
                               DMG_LAYOUT_ENABLED="false")
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
                                       GITHUB_REF_NAME="v1.2.3", GITHUB_RUN_NUMBER="42",
                                       DMG_LAYOUT_ENABLED="false")
                    with patch.dict(os.environ, environment):
                        with patch.object(self.module, "import_identity", return_value=keychain):
                            with patch.object(self.module, "fetch_secret", return_value=password):
                                with patch.object(self.module, "code_objects", return_value=[app]):
                                    with patch.object(self.module, "notarize"):
                                        with patch.object(self.module, "run", return_value=(
                                                '"Developer ID Application: Fixture (SYNTHETIC0)"')):
                                            with patch.object(self.module, "codesign") as signing, \
                                                    patch.object(self.module, "create_disk_image",
                                                                 return_value=("fixture-digest", None)), \
                                                    patch.object(self.module, "submit_and_staple"), \
                                                    patch.object(self.module, "verify_disk_image"):
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
                if (arguments[1:3] == ["stapler", "validate"]
                        or arguments[:2] == ["/usr/sbin/spctl", "--assess"]):
                    return ""
                return original_run(arguments, **kwargs)

            image = root / "Test App-v1.2.3-universal-macos.dmg"
            with patch.object(self.module, "run", side_effect=run):
                self.module.create_disk_image(app, root, image)
                expected_digest = self.module.bundle_digest(app)
                self.module.verify_disk_image(image, app, root, expected_digest, None)
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
                    try:
                        result = subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)],
                                                capture_output=True, timeout=120)
                    except subprocess.TimeoutExpired:
                        result = None
                    if result is None or result.returncode:
                        subprocess.run(["/usr/bin/hdiutil", "detach", "-force", str(mount)],
                                       capture_output=True, timeout=120, check=True)
                    self.assertFalse(os.path.ismount(mount))

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS disk image and code-signing tools")
    def test_finder_payload_survives_fresh_compressed_image_and_readonly_verification(self):
        with native_fixture() as (root, app):
            info = app / "Contents/Info.plist"
            info.write_bytes(plistlib.dumps({
                **plistlib.loads(info.read_bytes()), "CFBundleIdentifier": "example.native.fixture",
                "CFBundleExecutable": "Test", "CFBundlePackageType": "APPL",
            }))
            binary = app / "Contents/MacOS/Test"
            binary.parent.mkdir()
            shutil.copyfile("/usr/bin/true", binary)
            binary.chmod(0o755)
            (app / "Contents/binary-link").symlink_to("MacOS/Test")
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(app)],
                           capture_output=True, check=True)
            subprocess.run(["/usr/bin/xattr", "-w", "com.example.fixture", "value", str(binary)],
                           capture_output=True, check=True)

            payload = root.parent / "native-input/finder-layout"
            background_dir = payload / ".background"
            background_dir.mkdir(parents=True)
            ds_store = payload / ".DS_Store"
            ds_store.write_bytes(b"\x00\x00\x00\x01Bud1" + bytes(8))
            background = background_dir / "background.tiff"
            background.write_bytes(b"II*\x00" + bytes(16))
            expected_layout = (
                hashlib.sha256(ds_store.read_bytes()).hexdigest(),
                hashlib.sha256(background.read_bytes()).hexdigest(),
            )
            image = root.parent / "Finder Layout.dmg"

            original_run = self.module.run

            def run(arguments, **kwargs):
                if (arguments[1:3] == ["stapler", "validate"]
                        or arguments[:2] == ["/usr/sbin/spctl", "--assess"]):
                    return ""
                return original_run(arguments, **kwargs)

            environment = {
                "RUNNER_TEMP": str(root.parent),
                "FINDER_DS_STORE_SHA256": expected_layout[0],
                "FINDER_BACKGROUND_SHA256": expected_layout[1],
            }
            with patch.dict(os.environ, environment), patch.object(self.module, "run", side_effect=run):
                previous_umask = os.umask(0o077)
                try:
                    expected_digest, actual_layout = self.module.create_disk_image(app, root, image, payload)
                finally:
                    os.umask(previous_umask)
                self.assertEqual(actual_layout, expected_layout)
                self.module.verify_disk_image(image, app, root, expected_digest, expected_layout)
                with self.module.mounted_image(image, root / "metadata-mount", readonly=True):
                    self.assertEqual(stat.S_IMODE((root / "metadata-mount/.background").stat().st_mode), 0o755)
                    self.assertEqual(stat.S_IMODE((root / "metadata-mount/.DS_Store").stat().st_mode), 0o644)
                    self.assertEqual(
                        stat.S_IMODE((root / "metadata-mount/.background/background.tiff").stat().st_mode),
                        0o644,
                    )


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
