"""Non-destructive installer contract tests; no root, systemd or Docker required."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, *arguments):
        return subprocess.run(["bash", str(ROOT / "bootstrap.sh"), *arguments], capture_output=True, text=True)

    def test_process_substitution_help(self):
        result = subprocess.run(["bash", "-c", 'bash <(cat "$1") --help', "test", str(ROOT / "bootstrap.sh")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--download-only", result.stdout)

    def test_dry_run_never_creates_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "new-checkout")
            result = self.run_bootstrap("--dry-run", "--directory", target, "--port", "8443")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(Path(target).exists())
            self.assertIn("8443", result.stdout)

    def test_rejects_unsafe_arguments(self):
        for arguments in [("--port", "0"), ("--port", "65536"), ("--port", "443;id"), ("--release", "../main"), ("--target", "uninstall"), ("--directory", "/"), ("--directory", "/tmp/../etc"), ("--unknown",)]:
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.run_bootstrap("--dry-run", *arguments).returncode, 0)


class InstallerTests(unittest.TestCase):
    def test_invalid_values_fail_before_root_or_host_changes(self):
        for arguments in [("--port", "99999"), ("--prefix", "/tmp/a b"), ("--donor", 'example.org"'), ("--domain", "https://example.org")]:
            with self.subTest(arguments=arguments):
                result = subprocess.run(["bash", str(ROOT / "install.sh"), "server", *arguments], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("must run as root", result.stderr)

    def test_existing_panel_environment_survives_reinstallation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / "install.sh", root / "install.sh")
            (root / "panel").mkdir()
            original = "BPROTO_DOMAIN=old.example.org\nBPROTO_TAG_KEY=fixture-key\nBPROTO_ADMIN_PASSWORD=fixture-password\n"
            environment_file = root / "panel" / ".env"
            environment_file.write_text(original)
            (root / "bin").mkdir()
            docker = root / "bin" / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n")
            docker.chmod(0o755)
            environment = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", str(root / "install.sh"), "panel", "--domain", "new.example.org"], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(environment_file.read_text(), original)
            self.assertNotIn("fixture-password", result.stdout + result.stderr)
            self.assertEqual(environment_file.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
