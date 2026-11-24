# Railway staging deployment

This workflow deploys only to a dedicated Railway **staging** service. It is
manual, requires an explicit `deploy-staging` confirmation, and runs the
Swift/Vapor build and PostgreSQL integration tests before deployment.

## 1. Configure the Railway service

In the Railway project:

1. Create or select a dedicated staging environment.
2. Add a PostgreSQL service in that same environment.
3. Create a Vapor service connected to this repository.
4. Leave the service root directory at the repository root.
5. Set the Dockerfile path to `Dockerfile.railway` (the repository's
   `railway.toml` selects it).
6. Generate a Railway domain or attach a staging-only HTTPS domain.
7. Confirm the service uses the staging environment, not production.

The root build context is intentional. `AuthPlatform/Server/Dockerfile` remains
for the existing Render/Fly configurations and is not used by this Railway
workflow.

## 2. Configure Railway service variables

Set these variables on the Vapor service in the Railway staging environment:

- `DATABASE_URL`: private PostgreSQL URL, e.g.
  `${{Postgres.DATABASE_PRIVATE_URL}}` using the actual PostgreSQL service name.
- `DIRECT_DATABASE_URL`: direct PostgreSQL URL used by Fluent migrations.
  Use the direct connection string supplied by the PostgreSQL service.
- `HOST`: `0.0.0.0`
- `PORT`: `8080`
- `WEBAUTHN_RP_ID`: staging hostname only
- `WEBAUTHN_RP_NAME`: `AuthPlatform Staging`
- `WEBAUTHN_ORIGIN`: the staging HTTPS origin
- `WORKOS_CLIENT_ID`, `WORKOS_ISSUER`, `WORKOS_JWKS_URL`: dedicated
  WorkOS test-tenant values
- `RESEND_API_KEY` and `AUTH_EMAIL_FROM`: only if testing email delivery,
  using a dedicated test sender

Never use production OAuth credentials, production database URLs, real user
vaults, or production email keys in staging. Do not put secret values in Git.

The Docker entrypoint runs Fluent migrations against `DIRECT_DATABASE_URL`
before starting the app. The running service uses `DATABASE_URL`. Keep both
URLs pointed at the same staging database.

## 3. Configure GitHub staging environment

In repository Settings → Environments, create an environment named
`staging`. Add:

- Secret `RAILWAY_API_TOKEN` (the existing Railway API token may be stored here)
- Secret `RAILWAY_STAGING_ENVIRONMENT_ID`
- Secret `RAILWAY_STAGING_SERVICE_ID`
- Secret `RAILWAY_STAGING_HEALTHCHECK_URL` (the exact HTTPS URL ending in
  `/health`)
- Variable `RAILWAY_PROJECT_ID`

The service and environment IDs must identify the staging service/environment,
not production. Add required reviewers to the GitHub environment if you want
manual approval before the workflow receives its secrets.

## 4. Deploy

Open Actions → **Deploy AuthPlatform to Railway staging** → Run workflow.
Enter `deploy-staging` in the confirmation field. The workflow builds and tests
against a disposable PostgreSQL 16 database, deploys the root-context Docker
image, then polls the configured HTTPS health endpoint.

A successful `/health` check proves only that the staging process is serving.
It does not prove production readiness, backups, OAuth provider configuration,
physical iPhone AutoFill, or end-to-end password recovery.

## 5. Production gate

Do not copy staging secrets or database data into production. Production
requires a separate environment, database, domain, OAuth registrations,
backup/restore drill, rollback plan, signed iOS release, and successful
security review of vault recovery and synchronization.
