# AuthPlatform production operations runbook

This runbook describes the controls that must be configured and verified in
Railway before production traffic or real password-vault data is allowed.

## Database and backups

1. Use a dedicated Railway PostgreSQL service in the production environment.
   Do not share the staging database.
2. Set the Vapor service's `DATABASE_URL` to the private connection URL and
   `DIRECT_DATABASE_URL` to the direct connection URL for the same database.
3. In the PostgreSQL service's Railway Backups settings, enable automatic
   backups at a schedule and retention period approved by the service owner.
4. Take a manual backup immediately before any production schema migration.
5. Restore a recent backup into a separate temporary database at least once
   before launch, and record the restore duration and data-integrity checks.
6. Restrict database access to the Vapor service and approved operators. Do
   not expose the database publicly unless a documented operational need exists.

A backup configuration is not considered verified until a restore drill has
completed successfully. Define and record explicit RPO and RTO targets.

## Deployments and rollback

- Deploy from a reviewed, immutable Git commit after all required GitHub and
  CircleCI checks pass and code-owner approval is recorded.
- Keep the previous known-good Railway deployment available.
- For an application rollback, select the previous successful deployment in
  Railway's Deployments view and redeploy/rollback to that exact deployment.
- Verify `/health` after rollback; it checks PostgreSQL readiness. `/live`
  reports process liveness only.
- Do not automatically revert database migrations as part of an application
  rollback. The encrypted-item version migration is additive and old app code
  can ignore the additional column. A destructive schema rollback requires a
  tested backup restore and explicit approval.
- Record deployment commit, migration state, operator, time, health-check
  result, and rollback decision.

## Required production variables

Configure these on the production Railway Vapor service only:

- `DATABASE_URL` and `DIRECT_DATABASE_URL` for production PostgreSQL
- `HOST=0.0.0.0` and Railway-provided `PORT`
- `WEBAUTHN_RP_ID` equal to the production credential domain
- `WEBAUTHN_ORIGIN` equal to the exact production HTTPS origin
- Production WorkOS issuer, client ID, and JWKS URL
- Email provider credentials and verified sender, if email verification/reset is enabled
- Any required rate-limit, session, and audit configuration

Store credentials in Railway's secret variables. Never put tokens, signing
keys, master keys, recovery codes, refresh tokens, or database URLs in GitHub
source, image layers, build arguments, logs, or client-side configuration.

## Monitoring and security

- Alert on failed deployments, repeated health-check failures, database
  connection exhaustion, elevated 5xx rates, and authentication abuse.
- Keep request logs free of Authorization headers, cookies, passwords, vault
  ciphertext where avoidable, recovery codes, and passkey challenge secrets.
- Verify rate limits and audit events for login, refresh, logout, password
  reset, passkey registration, and vault writes.
- Rotate WorkOS/email/database credentials using a documented overlap window.
- Verify that encrypted vault payloads remain unreadable without the user's
  device-held vault key and recovery material.
- Test tenant isolation and tombstone/version conflict behavior with separate
  test accounts before production.

## Release gates

Production remains blocked until all of the following are recorded:

- Green Swift/Vapor, PostgreSQL integration, Xcode host-app, extension, and
  vault XCTest checks; CircleCI must be green as well.
- Code-owner review and required approvals.
- Successful staging deployment, health check, migration, restore drill, and
  rollback rehearsal.
- Signed iOS archive using the correct Apple Developer Team and provisioning
  profiles.
- Physical iPhone passkey, AutoFill, shared Keychain, recovery, and
  multi-device conflict tests.
- Published Apple App Site Association file and matching Associated Domains,
  WorkOS redirect, WebAuthn RP ID, and origin.
