# Google Workspace OAuth Fix Runbook

1) Verify Google Cloud OAuth consent screen.
2) Create Web OAuth client with correct redirect URI.
3) Confirm Django settings match provider.
4) Verify domain and TLS.
5) Inspect logs for state/redirect mismatches.
6) Test with a Workspace user.
7) Rollback by disabling provider if needed.
