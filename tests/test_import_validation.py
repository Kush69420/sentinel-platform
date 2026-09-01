"""Issue 3 — `validate_import_rows()` produced self-referential rows.

When no column mapping is supplied (the wizard's auto-mapping can come back
empty for a file whose headers match nothing), `validate_import_rows()` took the
`else` branch and bound `row` to the *same* dict as `raw`, then did
`row['_raw'] = raw`. That makes the dict contain itself.

Nothing notices until an import is actually executed: every branch of
`import_execute_v2()` stores the row as `json.dumps(row.get('_raw', row))`, and
json.dumps refuses a cycle with `ValueError: Circular reference detected` — a
500 from `/api/admin/import/execute`, mid-loop, after some rows are already
inserted.

Seams under test:
  - `validate_import_rows()` output rows must be JSON-serialisable, which is the
    real contract `import_execute_v2()` depends on.
  - `_raw` must still carry the normalised source row, since that is what lands
    in the `raw_json` column.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module


class ValidateImportRowsSerialisationTests(unittest.TestCase):
    ROWS = [{"Mobile Number": "9990001111", "Subscriber Name": "Test User"}]

    def test_unmapped_rows_are_json_serialisable(self):
        """The regression: no mapping -> row was `raw` itself -> cycle."""
        out, _issues, _summary = app_module.validate_import_rows("subscriber", self.ROWS)
        for row in out:
            json.dumps(row.get("_raw", row), default=str)

    def test_mapped_rows_are_json_serialisable(self):
        """The mapped branch always built a fresh dict, so it never broke —
        pinned here so a future refactor cannot regress it into sharing again."""
        mapping = {"mobile_number": "Mobile Number", "subscriber_name": "Subscriber Name"}
        out, _issues, _summary = app_module.validate_import_rows("subscriber", self.ROWS, mapping)
        for row in out:
            json.dumps(row.get("_raw", row), default=str)

    def test_raw_is_not_the_row_itself(self):
        out, _issues, _summary = app_module.validate_import_rows("subscriber", self.ROWS)
        row = out[0]
        self.assertIsNot(row["_raw"], row)
        self.assertNotIn("_raw", row["_raw"])

    def test_raw_still_carries_the_normalised_source_row(self):
        """`_raw` is what `import_execute_v2()` writes to `raw_json`; copying the
        row must not change which values get stored."""
        out, _issues, _summary = app_module.validate_import_rows("subscriber", self.ROWS)
        self.assertEqual(
            out[0]["_raw"],
            {"mobile_number": "9990001111", "subscriber_name": "Test User"},
        )

    def test_unmapped_row_still_exposes_the_module_key_field(self):
        """Duplicate detection reads `row['mobile_number']` for the subscriber
        module — the copy must keep those keys, not just `_raw`."""
        out, _issues, _summary = app_module.validate_import_rows("subscriber", self.ROWS)
        self.assertEqual(out[0]["mobile_number"], "9990001111")

    def test_duplicate_detection_still_fires_without_a_mapping(self):
        rows = self.ROWS + [{"Mobile Number": "9990001111", "Subscriber Name": "Someone Else"}]
        _out, issues, summary = app_module.validate_import_rows("subscriber", rows)
        self.assertEqual(summary["duplicate_count"], 1)
        self.assertTrue(any(i["type"] == "duplicate_in_file" for i in issues))


if __name__ == "__main__":
    unittest.main()
