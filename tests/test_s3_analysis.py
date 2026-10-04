# Unit tests for the S3 spike's analysis helpers. No coverage claims: a spike
# measures, it does not implement requirements.
import importlib.util
import pathlib
import unittest

P = pathlib.Path(__file__).resolve().parent.parent / "spikes" / "S3-agent-machines" / "analysis.py"
spec = importlib.util.spec_from_file_location("s3_analysis", P)
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

MiB = 1 << 20


class FitTest(unittest.TestCase):
    def test_exact_line(self):
        pts = [(n, 100 * MiB + n * 30 * MiB) for n in (1, 2, 4, 8)]
        base, slope = an.fit_line(pts)
        self.assertAlmostEqual(base / MiB, 100, places=6)
        self.assertAlmostEqual(slope / MiB, 30, places=6)

    def test_needs_two_distinct_points(self):
        with self.assertRaises(ValueError):
            an.fit_line([(4, 10), (4, 12)])


class ConcurrencyTest(unittest.TestCase):
    def test_floor_division(self):
        self.assertEqual(an.max_concurrency(3000 * MiB, 30 * MiB), 100)
        self.assertEqual(an.max_concurrency(3000 * MiB, 31 * MiB), 96)

    def test_workload_adds_to_overhead(self):
        self.assertEqual(an.max_concurrency(3000 * MiB, 30 * MiB, workload=270 * MiB), 10)

    def test_nonpositive_cost_rejected(self):
        with self.assertRaises(ValueError):
            an.max_concurrency(MiB, 0)


class StatsTest(unittest.TestCase):
    def test_median_and_p90(self):
        s = an.summarize([5, 1, 3, 2, 4, 6, 7, 8, 9, 10])
        self.assertEqual(s["n"], 10)
        self.assertEqual(s["median"], 5.5)
        self.assertEqual(s["p90"], 9.1)


if __name__ == "__main__":
    unittest.main()
