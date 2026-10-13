"""Phase 2 remediation execution - the one deliberate, reviewed departure
from Culprit's otherwise strictly read-only design (see SECURITY.md's
"Remediation execution" section).

Deliberately a separate package from culprit/collectors/, whose own
docstrings describe their allow-listed scripts as read-only "entire
guest-side attack surface" - this package is the one place that's allowed
to be otherwise, so that distinction stays obvious in any future review
rather than being buried inside an otherwise-read-only module.

Every action here requires, at execution time, not just at some earlier
diagnosis:
  1. CULPRIT_REMEDIATION_ENABLED=true explicitly set (off by default).
  2. The specific diagnosis is marked phase2_candidate=True.
  3. The diagnosed cause family currently clears the precision gate
     (FamilyPrecision.meets_promotion_bar), re-verified live on every
     single request - never cached, never trusted from an earlier check.
  4. A human supplies their own identity and explicitly confirms the
     action for that specific cluster.
There is no fully-autonomous or zero-touch path, ever - see
api/routes_remediation.py for where all four are enforced together."""
