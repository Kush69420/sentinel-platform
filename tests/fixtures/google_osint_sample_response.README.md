# Provenance of `google_osint_sample_response.json`

Captured live, 2026-09-05, against the public example GAIA id used
throughout this project's research (`111544054649252019208`), via the
verified `_REVIEWS_PB_TEMPLATE` flow (bootstrap token, then the real
request with `max_reviews=50`). This is a **real** `status == 0`
(`data[15] == 0`) response — not synthetic.

What it verifies: `display_name`, `photo_url` (structurally located, not by
fixed index), and `total_reviews` (parsed from the `"Reviews"` stats
section) all round-trip correctly against this real payload.

What it does **not** verify: this account's reviews collection came back
genuinely empty (the trailing `{"46": []}` object) despite its own stats
block reporting "1 review, 1 rating" — varying `max_reviews` (5, 50) and the
embedded map viewport made no difference across several live attempts.
Plausibly that one interaction is a bare star rating with no written text.
Either way, this fixture cannot exercise `_parse_review`'s field extraction
— see `google_osint_synthetic_reviews_populated.json` for that, which is
synthetic/hand-built and unverified against a real populated response.
