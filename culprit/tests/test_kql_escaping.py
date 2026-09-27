"""KQL/OData string-literal escaping - found in review 2026-09-27: query
strings were built via plain `.format()` with no escaping anywhere. Low
exploitability (values come from Azure's own resource metadata, not
directly attacker input) but no defense in depth. This is the fix."""
from __future__ import annotations

from culprit.pipeline.discovery import _quote_ids
from culprit.security.kql import escape_kql_string


def test_escape_doubles_embedded_single_quotes():
    assert escape_kql_string("O'Brien") == "O''Brien"


def test_escape_is_a_no_op_without_quotes():
    assert escape_kql_string("vm-prd-app-0100") == "vm-prd-app-0100"


def test_quote_ids_escapes_each_id():
    assert _quote_ids(["a", "b'; drop"]) == "'a', 'b''; drop'"


def test_quote_ids_empty_list():
    assert _quote_ids([]) == ""
