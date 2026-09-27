"""The failure taxonomy from the proposal (Section 9).

This is a fixed enum rather than a free-text field on purpose: the rule
engine, the RCA agent's structured output, and the precision gate all key
off `CauseFamily`, and "per cause family" precision tracking (the whole
Phase 2 gate) only works if every RCA result is tagged with one of a small,
stable set of values. New families get added here deliberately, not
invented ad hoc by a model.
"""
from __future__ import annotations

import enum


class CauseFamily(str, enum.Enum):
    CAPACITY = "capacity"
    AGENT_EXTENSION = "agent_extension"
    CONFIGURATION = "configuration"
    PACKAGE_MANAGER_STATE = "package_manager_state"
    SOURCE_ENTITLEMENT = "source_entitlement"
    NETWORK_PATH = "network_path"
    REBOOT = "reboot"
    WINDOW_SCHEDULING = "window_scheduling"
    PERMISSION_POLICY = "permission_policy"
    POST_PATCH_REGRESSION = "post_patch_regression"
    UNRESOLVED = "unresolved"


# Whether the family is typically fully settled by a deterministic rule,
# partly settled (some instances resolve by rule, the rest need deep RCA),
# a pure symptom that must always escalate, or something only deep
# reasoning across sources can find (post-patch regression needs the
# Datadog correlation, not just Azure/guest evidence).
RULE_COVERAGE = {
    CauseFamily.CAPACITY: "full",
    CauseFamily.AGENT_EXTENSION: "full",
    CauseFamily.CONFIGURATION: "full",
    CauseFamily.PACKAGE_MANAGER_STATE: "partial",
    CauseFamily.SOURCE_ENTITLEMENT: "full",
    CauseFamily.NETWORK_PATH: "partial",
    CauseFamily.REBOOT: "partial",
    CauseFamily.WINDOW_SCHEDULING: "symptom",
    CauseFamily.PERMISSION_POLICY: "full",
    CauseFamily.POST_PATCH_REGRESSION: "deep_rca_only",
    CauseFamily.UNRESOLVED: "deep_rca_only",
}

# The Phase 2 promotion gate (proposal Section 11): a family only becomes an
# automation candidate once it has sustained this precision over at least
# this many reviewed instances, with human sign-off on top.
PROMOTION_PRECISION_THRESHOLD = 0.95
PROMOTION_MIN_SAMPLE = 50
