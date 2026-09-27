"""Escaping for values interpolated into KQL/OData string literals.

Found in review 2026-09-27: every collector built its Resource Graph /
Log Analytics query strings via plain `.format()` with no escaping -
`vm_id`, `computer` (VM name), and the joined `vm_ids` list all flow from
Azure's own resource metadata (not directly attacker-controlled), so
exploitability was assessed as low, but there was no defense in depth at
all. A resource name or tag that ever contains a single quote would at
minimum break the query, and at worst inject an extra query clause.
"""
from __future__ import annotations


def escape_kql_string(value: str) -> str:
    """KQL's string-literal escape for an embedded single quote is to
    double it (`it's` -> `it''s`) - the same rule as OData filters, which
    is why this one helper covers both the Resource Graph KQL queries and
    the Activity Log OData `$filter` string."""
    return value.replace("'", "''")
