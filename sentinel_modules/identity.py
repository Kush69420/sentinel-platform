"""Indian identity-document validation.

Fully self-contained: standard library only, no network, no database, no API
keys. Every function is a pure transformation of the string handed to it.

Two kinds of check are performed, and the result always says which one applied:

  * `checksum`  — the document carries a real check digit (Aadhaar, GSTIN,
                  IMEI), so an invalid number can be rejected with confidence.
  * `structure` — the document has no public check digit (PAN, IFSC, voter
                  EPIC, passport, vehicle registration). A "valid" result here
                  means only that the number is well-formed, never that it was
                  issued or that it belongs to anyone.

Nothing here looks a number up anywhere. Aadhaar numbers are masked in the
output so a validation call cannot become a way to log them.
"""
import re

from .checksums import gstin_check_digit, luhn_check_digit, luhn_is_valid, verhoeff_is_valid

__all__ = ["validate", "detect_type", "DOCUMENT_TYPES"]


# ─────────────────────────────────────────────
# REFERENCE TABLES
# ─────────────────────────────────────────────

# GST state codes (also the leading two digits of every GSTIN).
GST_STATE_CODES = {
    "01": "Jammu & Kashmir", "02": "Himachal Pradesh", "03": "Punjab",
    "04": "Chandigarh", "05": "Uttarakhand", "06": "Haryana", "07": "Delhi",
    "08": "Rajasthan", "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim",
    "12": "Arunachal Pradesh", "13": "Nagaland", "14": "Manipur",
    "15": "Mizoram", "16": "Tripura", "17": "Meghalaya", "18": "Assam",
    "19": "West Bengal", "20": "Jharkhand", "21": "Odisha",
    "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
    "25": "Daman & Diu (pre-merger)", "26": "Dadra & Nagar Haveli and Daman & Diu",
    "27": "Maharashtra", "28": "Andhra Pradesh (pre-bifurcation)",
    "29": "Karnataka", "30": "Goa", "31": "Lakshadweep", "32": "Kerala",
    "33": "Tamil Nadu", "34": "Puducherry", "35": "Andaman & Nicobar Islands",
    "36": "Telangana", "37": "Andhra Pradesh", "38": "Ladakh",
    "97": "Other Territory", "99": "Centre Jurisdiction",
}

# Fourth character of a PAN encodes the holder category.
PAN_HOLDER_TYPES = {
    "A": "Association of Persons (AOP)", "B": "Body of Individuals (BOI)",
    "C": "Company", "F": "Firm / LLP", "G": "Government Agency",
    "H": "Hindu Undivided Family (HUF)", "J": "Artificial Juridical Person",
    "L": "Local Authority", "P": "Individual", "T": "Trust",
    "E": "Limited Liability Partnership", "K": "Krish (Trust)",
}

# Vehicle registration state/UT prefixes.
RTO_STATE_CODES = {
    "AN": "Andaman & Nicobar Islands", "AP": "Andhra Pradesh",
    "AR": "Arunachal Pradesh", "AS": "Assam", "BR": "Bihar",
    "CG": "Chhattisgarh", "CH": "Chandigarh", "DD": "Daman & Diu",
    "DL": "Delhi", "DN": "Dadra & Nagar Haveli", "GA": "Goa",
    "GJ": "Gujarat", "HP": "Himachal Pradesh", "HR": "Haryana",
    "JH": "Jharkhand", "JK": "Jammu & Kashmir", "KA": "Karnataka",
    "KL": "Kerala", "LA": "Ladakh", "LD": "Lakshadweep",
    "MH": "Maharashtra", "ML": "Meghalaya", "MN": "Manipur",
    "MP": "Madhya Pradesh", "MZ": "Mizoram", "NL": "Nagaland",
    "OD": "Odisha", "OR": "Odisha (legacy prefix)", "PB": "Punjab",
    "PY": "Puducherry", "RJ": "Rajasthan", "SK": "Sikkim",
    "TN": "Tamil Nadu", "TR": "Tripura", "TS": "Telangana",
    "UA": "Uttarakhand (legacy prefix)", "UK": "Uttarakhand",
    "UP": "Uttar Pradesh", "WB": "West Bengal",
}

# First four characters of an IFSC identify the bank.
IFSC_BANK_CODES = {
    "ABHY": "Abhyudaya Co-operative Bank", "AIRP": "Airtel Payments Bank",
    "ALLA": "Allahabad Bank (merged into Indian Bank)", "ANDB": "Andhra Bank (merged into Union Bank)",
    "AUBL": "AU Small Finance Bank", "BARB": "Bank of Baroda",
    "BKDN": "Dena Bank (merged into Bank of Baroda)", "BKID": "Bank of India",
    "CBIN": "Central Bank of India", "CITI": "Citibank",
    "CIUB": "City Union Bank", "CNRB": "Canara Bank",
    "CORP": "Corporation Bank (merged into Union Bank)", "DBSS": "DBS Bank India",
    "DCBL": "DCB Bank", "DEUT": "Deutsche Bank",
    "ESFB": "Equitas Small Finance Bank", "FDRL": "Federal Bank",
    "FINO": "Fino Payments Bank", "HDFC": "HDFC Bank",
    "HSBC": "HSBC India", "IBKL": "IDBI Bank", "ICIC": "ICICI Bank",
    "IDFB": "IDFC First Bank", "IDIB": "Indian Bank", "INDB": "IndusInd Bank",
    "IOBA": "Indian Overseas Bank", "JAKA": "Jammu & Kashmir Bank",
    "JIOP": "Jio Payments Bank", "KARB": "Karnataka Bank",
    "KKBK": "Kotak Mahindra Bank", "KVBL": "Karur Vysya Bank",
    "MAHB": "Bank of Maharashtra", "NSPB": "NSDL Payments Bank",
    "ORBC": "Oriental Bank of Commerce (merged into PNB)", "PSIB": "Punjab & Sind Bank",
    "PUNB": "Punjab National Bank", "PYTM": "Paytm Payments Bank",
    "RATN": "RBL Bank", "SBIN": "State Bank of India",
    "SCBL": "Standard Chartered Bank", "SIBL": "South Indian Bank",
    "SURY": "Suryoday Small Finance Bank", "SYNB": "Syndicate Bank (merged into Canara Bank)",
    "TMBL": "Tamilnad Mercantile Bank", "UBIN": "Union Bank of India",
    "UCBA": "UCO Bank", "UJVN": "Ujjivan Small Finance Bank",
    "UTIB": "Axis Bank", "UTKS": "Utkarsh Small Finance Bank",
    "VIJB": "Vijaya Bank (merged into Bank of Baroda)", "YESB": "YES Bank",
}

DOCUMENT_TYPES = ("aadhaar", "pan", "gstin", "ifsc", "imei", "vehicle", "voter_id", "passport")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _normalize(value: str) -> str:
    """Upper-case and strip spaces/hyphens — the separators people paste in."""
    return re.sub(r"[\s\-]", "", (value or "")).upper()


def _result(doc_type, normalized, valid, method, reason="", **details):
    return {
        "type": doc_type,
        "input": normalized,
        "valid": valid,
        "verified_by": method,
        "reason": reason,
        "details": details,
    }


def _mask_aadhaar(digits: str) -> str:
    """UIDAI permits displaying only the last four digits."""
    return f"XXXX XXXX {digits[-4:]}"


# ─────────────────────────────────────────────
# VALIDATORS
# ─────────────────────────────────────────────

def validate_aadhaar(value: str) -> dict:
    """12 digits, first digit 2-9, Verhoeff check digit."""
    n = _normalize(value)
    masked = _mask_aadhaar(n) if len(n) >= 4 else ""
    if not n.isdigit():
        return _result("aadhaar", masked, False, "checksum", "Aadhaar must contain digits only")
    if len(n) != 12:
        return _result("aadhaar", masked, False, "checksum", f"Aadhaar must be 12 digits, got {len(n)}")
    if n[0] in "01":
        return _result("aadhaar", masked, False, "checksum", "Aadhaar cannot begin with 0 or 1")
    if not verhoeff_is_valid(n):
        return _result("aadhaar", masked, False, "checksum", "Verhoeff check digit does not match")
    return _result(
        "aadhaar", masked, True, "checksum",
        masked=masked,
        note="Checksum only. This does not confirm the number was issued or who holds it.",
    )


def validate_pan(value: str) -> dict:
    """AAAAA9999A — five letters, four digits, one letter. No public checksum."""
    n = _normalize(value)
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", n):
        return _result("pan", n, False, "structure", "PAN must match AAAAA9999A")
    holder = PAN_HOLDER_TYPES.get(n[3])
    if not holder:
        return _result("pan", n, False, "structure", f"'{n[3]}' is not a recognised PAN holder-type character")
    return _result(
        "pan", n, True, "structure",
        holder_type=holder, holder_type_code=n[3], name_initial=n[4],
        note="Structure only — PAN has no public check digit.",
    )


def validate_gstin(value: str) -> dict:
    """15 characters: state code + PAN + entity number + 'Z' + check character."""
    n = _normalize(value)
    if not re.fullmatch(r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]", n):
        return _result("gstin", n, False, "checksum", "GSTIN must match 99AAAAA9999A9Z9")
    state = GST_STATE_CODES.get(n[:2])
    if not state:
        return _result("gstin", n, False, "checksum", f"'{n[:2]}' is not a valid GST state code")
    expected = gstin_check_digit(n[:14])
    if n[14] != expected:
        return _result("gstin", n, False, "checksum", "Check character does not match")
    return _result(
        "gstin", n, True, "checksum",
        state_code=n[:2], state=state, pan=n[2:12], entity_number=n[12],
        note="Checksum valid. Registration status must still be confirmed on the GST portal.",
    )


def validate_ifsc(value: str) -> dict:
    """AAAA0BBBBBB — bank code, reserved '0', branch code."""
    n = _normalize(value)
    if not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", n):
        return _result("ifsc", n, False, "structure", "IFSC must match AAAA0BBBBBB (5th character is always zero)")
    bank_code = n[:4]
    return _result(
        "ifsc", n, True, "structure",
        bank_code=bank_code, bank=IFSC_BANK_CODES.get(bank_code, "Unknown — not in local bank-code table"),
        branch_code=n[5:],
        note="Structure only. Confirm the branch against the RBI IFSC directory.",
    )


def validate_imei(value: str) -> dict:
    """15-digit IMEI with a Luhn check digit, or a 16-digit IMEISV (no check digit)."""
    n = _normalize(value)
    if not n.isdigit():
        return _result("imei", n, False, "checksum", "IMEI must contain digits only")
    if len(n) == 16:
        return _result(
            "imei", n, True, "structure",
            format="IMEISV", tac=n[:8], serial=n[8:14], software_version=n[14:],
            note="IMEISV carries a software version instead of a check digit, so only its structure was checked.",
        )
    if len(n) != 15:
        return _result("imei", n, False, "checksum", f"IMEI must be 15 digits (or 16 for IMEISV), got {len(n)}")
    if not luhn_is_valid(n):
        return _result(
            "imei", n, False, "checksum",
            f"Luhn check digit does not match — expected {luhn_check_digit(n[:14])}",
        )
    return _result(
        "imei", n, True, "checksum",
        format="IMEI", tac=n[:8], reporting_body_id=n[:2], serial=n[8:14], check_digit=n[14],
        note="Checksum only. Model and status require a GSMA TAC database, which this module does not use.",
    )


def validate_vehicle(value: str) -> dict:
    """Indian registration marks, both the state series and the BH series."""
    n = _normalize(value)

    bh = re.fullmatch(r"([0-9]{2})BH([0-9]{4})([A-Z]{1,2})", n)
    if bh:
        year, serial, series = bh.groups()
        return _result(
            "vehicle", n, True, "structure",
            series="Bharat (BH) series", registration_year=f"20{year}",
            serial=serial, series_letters=series,
            note="Structure only. BH-series marks are not tied to a state.",
        )

    state = re.fullmatch(r"([A-Z]{2})([0-9]{1,2})([A-Z]{0,3})([0-9]{1,4})", n)
    if not state:
        return _result("vehicle", n, False, "structure", "Registration must match e.g. MH12AB1234 or 22BH1234AA")
    code, rto, letters, serial = state.groups()
    if code not in RTO_STATE_CODES:
        return _result("vehicle", n, False, "structure", f"'{code}' is not a recognised state/UT prefix")
    return _result(
        "vehicle", n, True, "structure",
        series="State series", state_code=code, state=RTO_STATE_CODES[code],
        rto_code=rto.zfill(2), series_letters=letters, serial=serial,
        note="Structure only. Owner details require a VAHAN lookup, which this module does not perform.",
    )


def validate_voter_id(value: str) -> dict:
    """EPIC number — three letters followed by seven digits."""
    n = _normalize(value)
    if not re.fullmatch(r"[A-Z]{3}[0-9]{7}", n):
        return _result("voter_id", n, False, "structure", "EPIC number must match AAA9999999")
    return _result(
        "voter_id", n, True, "structure",
        functional_code=n[:3], serial=n[3:],
        note="Structure only. The leading code identifies the issuing assembly constituency.",
    )


def validate_passport(value: str) -> dict:
    """Indian passport file number — one letter followed by seven digits."""
    n = _normalize(value)
    if not re.fullmatch(r"[A-Z][0-9]{7}", n):
        return _result("passport", n, False, "structure", "Passport number must match A9999999")
    if n[0] in "QXZ":
        return _result("passport", n, False, "structure", f"'{n[0]}' is not used as an Indian passport series letter")
    return _result(
        "passport", n, True, "structure",
        series_letter=n[0], serial=n[1:],
        note="Structure only. Indian passport numbers carry no check digit.",
    )


_VALIDATORS = {
    "aadhaar": validate_aadhaar,
    "pan": validate_pan,
    "gstin": validate_gstin,
    "ifsc": validate_ifsc,
    "imei": validate_imei,
    "vehicle": validate_vehicle,
    "voter_id": validate_voter_id,
    "passport": validate_passport,
}


# ─────────────────────────────────────────────
# DISPATCH
# ─────────────────────────────────────────────

def detect_type(value: str) -> str | None:
    """Best guess at which document `value` is, from its shape alone.

    Ordered most-specific first so that unambiguous patterns win. Returns None
    when nothing matches, rather than guessing.
    """
    n = _normalize(value)
    if not n:
        return None
    if re.fullmatch(r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]", n):
        return "gstin"
    if re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", n):
        return "ifsc"
    if re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", n):
        return "pan"
    if re.fullmatch(r"[0-9]{2}BH[0-9]{4}[A-Z]{1,2}", n):
        return "vehicle"
    if re.fullmatch(r"[A-Z]{3}[0-9]{7}", n):
        return "voter_id"
    if re.fullmatch(r"[A-Z][0-9]{7}", n):
        return "passport"
    if re.fullmatch(r"[0-9]{15,16}", n):
        return "imei"
    if re.fullmatch(r"[0-9]{12}", n):
        return "aadhaar"
    if re.fullmatch(r"[A-Z]{2}[0-9]{1,2}[A-Z]{0,3}[0-9]{1,4}", n):
        return "vehicle"
    return None


def validate(value: str, doc_type: str | None = None) -> dict:
    """Validate `value`, detecting the document type when one isn't given.

    Always returns a result dict — an unrecognised input comes back as an
    invalid `unknown` result rather than raising.
    """
    if not (value or "").strip():
        return _result("unknown", "", False, "none", "No value supplied")

    resolved = (doc_type or "").strip().lower() or detect_type(value)
    if resolved is None:
        return _result(
            "unknown", _normalize(value), False, "none",
            "Could not identify the document type — pass one explicitly",
            supported=list(DOCUMENT_TYPES),
        )
    if resolved not in _VALIDATORS:
        return _result(
            "unknown", _normalize(value), False, "none",
            f"Unsupported document type '{resolved}'",
            supported=list(DOCUMENT_TYPES),
        )

    result = _VALIDATORS[resolved](value)
    result["detected"] = doc_type is None
    return result
