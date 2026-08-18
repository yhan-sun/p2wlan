#!/usr/bin/env python3
"""Regression tests for live_analyze percentiles + prediction-error extraction.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "punch-research"))
import live_analyze  # noqa: E402


class PercentileTests(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(live_analyze.percentiles([]), {})

    def test_single_value_is_flat(self):
        p = live_analyze.percentiles([7])
        self.assertEqual(p, {50: 7, 75: 7, 90: 7, 95: 7, 99: 7})

    def test_nearest_rank_large_sample(self):
        # 100 values 0..99: P50=49, P75=74, P90=89, P95=94, P99=98
        p = live_analyze.percentiles(list(range(100)))
        self.assertEqual(p[50], 49)
        self.assertEqual(p[75], 74)
        self.assertEqual(p[90], 89)
        self.assertEqual(p[95], 94)
        self.assertEqual(p[99], 98)

    def test_nearest_rank_small_sample(self):
        # [1,2,3,4]: P50=2 (ceil(0.5*4)=2 -> idx2 val 2), P75=3, P90=4, P99=4
        p = live_analyze.percentiles([1, 2, 3, 4])
        self.assertEqual(p[50], 2)
        self.assertEqual(p[75], 3)
        self.assertEqual(p[90], 4)

    def test_custom_marks(self):
        p = live_analyze.percentiles([10, 20, 30], marks=[50, 100])
        self.assertEqual(p, {50: 20, 100: 30})


class PredictionErrorTests(unittest.TestCase):
    def test_list_offsets_abs(self):
        s = {"stats": {"hit_metrics": {"offset_steps": [-3, 2, 0, 5]}}}
        self.assertEqual(live_analyze.prediction_error_distribution(s), [3, 2, 0, 5])

    def test_scalar_offset(self):
        s = {"stats": {"hit_metrics": {"offset_steps": -4}}}
        self.assertEqual(live_analyze.prediction_error_distribution(s), [4])

    def test_missing_offsets_empty(self):
        self.assertEqual(live_analyze.prediction_error_distribution({"stats": {}}), [])
        self.assertEqual(live_analyze.prediction_error_distribution({}), [])

    def test_non_numeric_skipped_and_capped(self):
        s = {"stats": {"hit_metrics": {"offset_steps": ["bad", 70000, 3]}}}
        # 70000 clamps to 32768 (16-bit wrap max); "bad" is skipped.
        self.assertEqual(live_analyze.prediction_error_distribution(s), [32768, 3])


if __name__ == "__main__":
    unittest.main()
