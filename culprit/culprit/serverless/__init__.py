"""The Azure Durable Functions port of Culprit's pipeline (serverless
architecture proposal, 2026-11-10 - see culprit/ARCHITECTURE.md's own
"proposal Section" references for the original design this re-hosts).

Nothing in `culprit/pipeline/`, `culprit/collectors/`, `culprit/models/`,
or `culprit/reporting/` changes - this package is a thin re-hosting layer:
`function_app.py` (trigger bindings) -> `orchestrators.py` (the same
discover/collect/diagnose/persist/notify sequence `pipeline/live_run.py::
execute_live_run` already runs, just checkpointed and fanned out by the
Durable Functions runtime instead of one in-process call) -> `activities.py`
(each activity is a few lines of glue calling straight into the existing,
already-tested pipeline modules) -> `serialization.py` (JSON (de)serializers
for the Pydantic/dataclass models that cross an activity boundary, since
Durable Functions activity inputs/outputs must be plain JSON).

Not yet deployed or run against a real Azure Functions host in this repo -
see this package's own README.md for exactly what has and hasn't been
verified, and what real Azure access is needed to finish verifying it.
"""
