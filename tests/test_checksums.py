"""Check-digit algorithms, verified against published test vectors.

Expected values here come from the algorithm specs and widely-published
examples — not from re-running our own implementation.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_modules import checksums  # noqa: E402


class VerhoeffTest(unittest.TestCase):
    def test_published_vector_236_has_check_digit_3(self):
        self.assertEqual(checksums.verhoeff_check_digit("236"), 3)
        self.assertTrue(checksums.verhoeff_is_valid("2363"))

    def test_appending_the_check_digit_always_validates(self):
        for payload in ("0", "12345", "99999999999", "234123412345"):
            full = payload + str(checksums.verhoeff_check_digit(payload))
            self.assertTrue(checksums.verhoeff_is_valid(full), full)

    def test_catches_single_digit_errors(self):
        valid = "234123412346"
        self.assertTrue(checksums.verhoeff_is_valid(valid))
        for i in range(len(valid)):
            for d in "0123456789":
                if d == valid[i]:
                    continue
                corrupted = valid[:i] + d + valid[i + 1:]
                self.assertFalse(checksums.verhoeff_is_valid(corrupted), corrupted)

    def test_catches_adjacent_transpositions(self):
        valid = "234123412346"
        for i in range(len(valid) - 1):
            if valid[i] == valid[i + 1]:
                continue
            swapped = valid[:i] + valid[i + 1] + valid[i] + valid[i + 2:]
            self.assertFalse(checksums.verhoeff_is_valid(swapped), swapped)


class LuhnTest(unittest.TestCase):
    def test_published_vector(self):
        self.assertEqual(checksums.luhn_check_digit("7992739871"), 3)
        self.assertTrue(checksums.luhn_is_valid("79927398713"))

    def test_known_valid_test_imei(self):
        self.assertTrue(checksums.luhn_is_valid("490154203237518"))

    def test_rejects_wrong_check_digit(self):
        for d in "012456789":
            self.assertFalse(checksums.luhn_is_valid("7992739871" + d))


class GstinChecksumTest(unittest.TestCase):
    def test_published_example_gstin(self):
        # 27AAPFU0939F1ZV is the example GSTIN used throughout GST documentation.
        self.assertEqual(checksums.gstin_check_digit("27AAPFU0939F1Z"), "V")


if __name__ == "__main__":
    unittest.main()
