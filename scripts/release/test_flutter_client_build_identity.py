#!/usr/bin/env python3
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/flutter_client_build_identity.py"


class FlutterClientBuildIdentityTest(unittest.TestCase):
    def test_emits_all_required_defines_for_current_checkout(self):
        output = subprocess.check_output(
            ["python3", str(SCRIPT), "windows", "--release"],
            cwd=ROOT,
            text=True,
        )
        values = {
            line.split("=", 2)[1]: line.split("=", 2)[2]
            for line in output.splitlines()
        }
        expected_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        self.assertEqual(values["P2WLAN_CLIENT_GIT_COMMIT"], expected_commit)
        self.assertIn(values["P2WLAN_CLIENT_DIRTY"], {"true", "false"})
        if values["P2WLAN_CLIENT_DIRTY"] == "true":
            self.assertTrue(values["P2WLAN_CLIENT_DIFF_HASH"])
            self.assertTrue(
                values["P2WLAN_CLIENT_BUILD_ID"].endswith(
                    f"-dirty-{values['P2WLAN_CLIENT_DIFF_HASH'][:12]}"
                )
            )
        else:
            self.assertEqual(values["P2WLAN_CLIENT_DIFF_HASH"], "")
            self.assertEqual(
                values["P2WLAN_CLIENT_BUILD_ID"], expected_commit[:12]
            )
        self.assertEqual(values["P2WLAN_CLIENT_PROFILE"], "release")
        self.assertEqual(
            set(values),
            {
                "P2WLAN_CLIENT_APP_VERSION",
                "P2WLAN_CLIENT_GIT_COMMIT",
                "P2WLAN_CLIENT_BUILD_ID",
                "P2WLAN_CLIENT_DIRTY",
                "P2WLAN_CLIENT_DIFF_HASH",
                "P2WLAN_CLIENT_PROFILE",
            },
        )


if __name__ == "__main__":
    unittest.main()
