from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from verify_profile_artifacts import VerificationError, require_equal


class ArtifactVerifierTests(unittest.TestCase):
    def test_identity_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(VerificationError, "SHA-256 mismatch"):
            require_equal("SHA-256", "actual", "expected")


if __name__ == "__main__":
    unittest.main()
