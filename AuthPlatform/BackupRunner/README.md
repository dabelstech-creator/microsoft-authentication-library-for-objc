# AuthPlatform one-time encrypted backup runner

This is a manually invoked Render Cron Job image, not an automatically scheduled backup.

## Required Render runtime secrets

Set these directly in the Render Cron Job environment settings. Never commit them or paste them into chat.

- `DATABASE_URL`: the PostgreSQL **Internal Database URL** for `sign-trigger-passkeys`.
- `DROPBOX_ACCESS_TOKEN`: a short-lived Dropbox OAuth access token restricted to the app folder and the minimum scopes `files.content.write` and `files.metadata.read`. Do not grant sharing scopes.
- `BACKUP_ENCRYPTION_PASSPHRASE`: a randomly generated, unique passphrase of at least 24 characters. Store it separately (for example, in a password manager); it is required for decryption.
- Optional `DROPBOX_DEST`: defaults to `/AuthPlatform Backups`.

## Execution

Build the image from the repository root using this Dockerfile, in Oregon. Configure a deliberately distant cron schedule only to satisfy Render's cron service requirement; **do not wait for that schedule**. Use Render Dashboard > Cron Job > Run Now for the one-time execution, then immediately suspend/delete the cron service after the run. Do not configure AutoDeploy for the job.

## Safety properties

- `pg_dump` is read-only and does not apply migrations.
- Custom-format archive is inspected with `pg_restore --list` before encryption.
- GPG symmetric AES-256 encryption occurs before any network upload.
- Dropbox upload uses the content API only; no shared link is created.
- Plaintext is kept in an ephemeral container directory and removed when the process exits.
- The job emits only destination, byte count, and SHA-256 metadata. It suppresses subprocess stderr to avoid leaking connection details.
- A successful upload and archive listing are **not** a restore test. Restore validation must occur against an isolated, disposable PostgreSQL instance, never production.

## Dropbox app setup

Because the staging folder was created at the Dropbox account root (`/AuthPlatform Backups`), configure the Dropbox app for **Full Dropbox** access, but grant only the `files.content.write` and `files.metadata.read` OAuth scopes. Do not grant sharing scopes. If you prefer App Folder access, create a separate folder inside that app's `/` namespace and change `DROPBOX_DEST` to that app-folder-relative path. Generate a short-lived token for the one-time run and revoke it after upload.

## Decryption

Download the `.dump.gpg` file to a trusted machine and decrypt locally:

```sh
gpg --output authplatform-production.dump --decrypt authplatform-production-*.dump.gpg
pg_restore --list authplatform-production.dump
```

GPG prompts for the passphrase. Do not store it alongside the encrypted dump.
