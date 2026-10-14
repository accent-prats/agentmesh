"""Email delivery for a specific run's report (api/routes_notifications.py).

Deliberately separate from culprit/reporting/notify.py (Teams/Slack
webhooks) - a different transport (SMTP, not an HTTP webhook POST) with
its own credential storage (SettingsRecord provider="smtp", encrypted via
culprit/security/crypto.py, the same mechanism Azure/Datadog already use).
"""
