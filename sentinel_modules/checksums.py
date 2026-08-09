"""Check-digit algorithms.

Pure functions, standard library only. Kept separate from the validators that
use them so the algorithms can be tested against their own published vectors.
"""

# Verhoeff — dihedral group D5. Used by Aadhaar (UIDAI) for its 12th digit.
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_checksum(digits: str) -> int:
    """Verhoeff checksum of `digits`. Zero means the string (including its
    trailing check digit) is valid."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c


def verhoeff_check_digit(payload: str) -> int:
    """The digit that must be appended to `payload` to make it Verhoeff-valid."""
    return _VERHOEFF_INV[verhoeff_checksum(payload + "0")]


def verhoeff_is_valid(digits: str) -> bool:
    return digits.isdigit() and verhoeff_checksum(digits) == 0


def luhn_checksum(digits: str) -> int:
    """Luhn (mod-10) sum. Zero means valid. Used by IMEI."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10


def luhn_check_digit(payload: str) -> int:
    return (10 - luhn_checksum(payload + "0")) % 10


def luhn_is_valid(digits: str) -> bool:
    return digits.isdigit() and luhn_checksum(digits) == 0


# GSTIN check digit — mod-36 over the 36-character alphanumeric set, weights
# alternating 1,2 across the first 14 characters.
_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_digit(payload: str) -> str:
    """Check character for the first 14 characters of a GSTIN."""
    total = 0
    for i, ch in enumerate(payload):
        value = _GSTIN_ALPHABET.index(ch) * (2 if i % 2 else 1)
        total += value // 36 + value % 36
    return _GSTIN_ALPHABET[(36 - total % 36) % 36]
