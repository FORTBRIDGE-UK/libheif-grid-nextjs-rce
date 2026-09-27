from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fresh_process_validation import compact_classification_attempts


class FreshProcessValidationTests(unittest.TestCase):
    def test_attempt_compaction_keeps_decision_but_drops_bulk_evidence(self) -> None:
        result = {
            "classification": {
                "attempts": [{
                    "attempt": 3,
                    "status": "no_match",
                    "supported_pair_count": 0,
                    "selected_profile_id": None,
                    "selected_base": None,
                    "rejected_candidates": ["ubuntu", "debian"],
                    "candidates": [{"pointer_qword_occurrences": 900}],
                    "image": {"alpha_bytes": 1048576},
                }],
            },
        }
        compact_classification_attempts(result)
        self.assertEqual(result["classification"]["attempts"], [{
            "attempt": 3,
            "status": "no_match",
            "supported_pair_count": 0,
            "selected_profile_id": None,
            "selected_base": None,
            "rejected_candidates": ["ubuntu", "debian"],
        }])


if __name__ == "__main__":
    unittest.main()
