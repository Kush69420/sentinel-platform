"""Identity-document validation.

Expected values come from the published format specs and from documented
example numbers, not from re-running the implementation.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_modules import identity  # noqa: E402

# Documented example/test numbers.
VALID_AADHAAR = "234123412346"      # Verhoeff-valid, widely used as a test UID
VALID_GSTIN = "27AAPFU0939F1ZV"     # example GSTIN from GST documentation
VALID_IMEI = "490154203237518"      # standard test IMEI
VALID_PAN = "ABCPE1234F"
VALID_IFSC = "SBIN0000001"


class AadhaarTest(unittest.TestCase):
    def test_accepts_a_verhoeff_valid_number(self):
        r = identity.validate_aadhaar(VALID_AADHAAR)
        self.assertTrue(r["valid"])
        self.assertEqual(r["verified_by"], "checksum")

    def test_never_echoes_the_full_number(self):
        r = identity.validate_aadhaar(VALID_AADHAAR)
        self.assertNotIn(VALID_AADHAAR, repr(r))
        self.assertEqual(r["input"], "XXXX XXXX 2346")

    def test_rejects_a_bad_check_digit(self):
        wrong = VALID_AADHAAR[:-1] + ("5" if VALID_AADHAAR[-1] != "5" else "7")
        self.assertFalse(identity.validate_aadhaar(wrong)["valid"])

    def test_rejects_leading_zero_or_one(self):
        for prefix in "01":
            n = prefix + VALID_AADHAAR[1:]
            r = identity.validate_aadhaar(n)
            self.assertFalse(r["valid"])
            self.assertIn("0 or 1", r["reason"])

    def test_rejects_wrong_length(self):
        self.assertFalse(identity.validate_aadhaar("23412341234")["valid"])
        self.assertFalse(identity.validate_aadhaar("2341234123465")["valid"])

    def test_tolerates_spaces_in_pasted_input(self):
        self.assertTrue(identity.validate_aadhaar("2341 2341 2346")["valid"])


class PanTest(unittest.TestCase):
    def test_accepts_well_formed_pan_and_decodes_holder_type(self):
        r = identity.validate_pan(VALID_PAN)
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["holder_type"], "Individual")
        self.assertEqual(r["verified_by"], "structure")

    def test_company_pan_decodes_as_company(self):
        self.assertEqual(identity.validate_pan("ABCCE1234F")["details"]["holder_type"], "Company")

    def test_rejects_unknown_holder_type_character(self):
        r = identity.validate_pan("ABCZE1234F")
        self.assertFalse(r["valid"])
        self.assertIn("holder-type", r["reason"])

    def test_rejects_malformed(self):
        for bad in ("ABCPE1234", "ABCP01234F", "1BCPE1234F", ""):
            self.assertFalse(identity.validate_pan(bad)["valid"], bad)


class GstinTest(unittest.TestCase):
    def test_accepts_documented_example(self):
        r = identity.validate_gstin(VALID_GSTIN)
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["state"], "Maharashtra")
        self.assertEqual(r["details"]["pan"], "AAPFU0939F")

    def test_rejects_wrong_check_character(self):
        wrong = VALID_GSTIN[:14] + ("A" if VALID_GSTIN[14] != "A" else "B")
        r = identity.validate_gstin(wrong)
        self.assertFalse(r["valid"])
        self.assertIn("Check character", r["reason"])

    def test_rejects_unassigned_state_code(self):
        r = identity.validate_gstin("50" + VALID_GSTIN[2:])
        self.assertFalse(r["valid"])
        self.assertIn("state code", r["reason"])


class IfscTest(unittest.TestCase):
    def test_accepts_and_names_the_bank(self):
        r = identity.validate_ifsc(VALID_IFSC)
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["bank"], "State Bank of India")
        self.assertEqual(r["details"]["branch_code"], "000001")

    def test_unknown_bank_code_is_still_structurally_valid(self):
        r = identity.validate_ifsc("ZZZZ0123456")
        self.assertTrue(r["valid"])
        self.assertIn("Unknown", r["details"]["bank"])

    def test_rejects_non_zero_fifth_character(self):
        self.assertFalse(identity.validate_ifsc("SBIN1000001")["valid"])


class ImeiTest(unittest.TestCase):
    def test_accepts_luhn_valid_imei_and_splits_tac(self):
        r = identity.validate_imei(VALID_IMEI)
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["tac"], "49015420")
        self.assertEqual(r["details"]["check_digit"], "8")

    def test_rejects_bad_check_digit_and_names_the_expected_one(self):
        r = identity.validate_imei(VALID_IMEI[:-1] + "9")
        self.assertFalse(r["valid"])
        self.assertIn("expected 8", r["reason"])

    def test_sixteen_digit_imeisv_is_structure_only(self):
        r = identity.validate_imei(VALID_IMEI[:14] + "05")
        self.assertTrue(r["valid"])
        self.assertEqual(r["verified_by"], "structure")
        self.assertEqual(r["details"]["format"], "IMEISV")


class VehicleTest(unittest.TestCase):
    def test_accepts_state_series_and_decodes_state(self):
        r = identity.validate_vehicle("MH12AB1234")
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["state"], "Maharashtra")
        self.assertEqual(r["details"]["rto_code"], "12")

    def test_accepts_bh_series(self):
        r = identity.validate_vehicle("22BH1234AA")
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["registration_year"], "2022")
        self.assertNotIn("state", r["details"])

    def test_tolerates_separators(self):
        self.assertTrue(identity.validate_vehicle("MH-12-AB-1234")["valid"])
        self.assertTrue(identity.validate_vehicle("mh 12 ab 1234")["valid"])

    def test_rejects_unknown_state_prefix(self):
        r = identity.validate_vehicle("XX12AB1234")
        self.assertFalse(r["valid"])
        self.assertIn("state/UT prefix", r["reason"])


class VoterAndPassportTest(unittest.TestCase):
    def test_accepts_epic_number(self):
        r = identity.validate_voter_id("ABC1234567")
        self.assertTrue(r["valid"])
        self.assertEqual(r["details"]["functional_code"], "ABC")

    def test_accepts_passport_number(self):
        self.assertTrue(identity.validate_passport("A1234567")["valid"])

    def test_rejects_unused_passport_series_letters(self):
        for letter in "QXZ":
            self.assertFalse(identity.validate_passport(letter + "1234567")["valid"], letter)


class DetectTypeTest(unittest.TestCase):
    def test_identifies_each_document_from_shape_alone(self):
        cases = {
            VALID_GSTIN: "gstin",
            VALID_IFSC: "ifsc",
            VALID_PAN: "pan",
            VALID_AADHAAR: "aadhaar",
            VALID_IMEI: "imei",
            "MH12AB1234": "vehicle",
            "22BH1234AA": "vehicle",
            "ABC1234567": "voter_id",
            "A1234567": "passport",
        }
        for value, expected in cases.items():
            self.assertEqual(identity.detect_type(value), expected, value)

    def test_returns_none_rather_than_guessing(self):
        for junk in ("", "   ", "hello", "12", "!!!!"):
            self.assertIsNone(identity.detect_type(junk), junk)


class ValidateDispatchTest(unittest.TestCase):
    def test_detects_type_when_not_supplied(self):
        r = identity.validate(VALID_GSTIN)
        self.assertTrue(r["valid"])
        self.assertEqual(r["type"], "gstin")
        self.assertTrue(r["detected"])

    def test_explicit_type_overrides_detection(self):
        # A PAN-shaped string checked as a vehicle registration must fail as one.
        r = identity.validate(VALID_PAN, doc_type="vehicle")
        self.assertEqual(r["type"], "vehicle")
        self.assertFalse(r["valid"])
        self.assertFalse(r["detected"])

    def test_empty_and_unrecognised_input_return_a_result_not_an_exception(self):
        self.assertFalse(identity.validate("")["valid"])
        r = identity.validate("not-an-id-at-all")
        self.assertFalse(r["valid"])
        self.assertIn("supported", r["details"])

    def test_unsupported_explicit_type_is_reported(self):
        r = identity.validate(VALID_PAN, doc_type="drivers_licence")
        self.assertFalse(r["valid"])
        self.assertIn("Unsupported", r["reason"])

    def test_every_advertised_type_is_dispatchable(self):
        for doc_type in identity.DOCUMENT_TYPES:
            r = identity.validate("ZZZZ", doc_type=doc_type)
            self.assertEqual(r["type"], doc_type)


if __name__ == "__main__":
    unittest.main()
