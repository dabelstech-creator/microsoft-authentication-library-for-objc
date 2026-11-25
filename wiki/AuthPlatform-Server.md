# AuthPlatform Server

## Overview

The server is a separate Swift package at `AuthPlatform/Server`. It uses Vapor and Fluent with PostgreSQL. Its dependencies are declared in `AuthPlatform/Server/Package.swift`; the root `Package.swift` is for the MSAL binary package and is not the server build entry point.

## Prerequisites

- Swift 5.10 or newer.
- PostgreSQL 16 for local integration tests.
- A local copy of the server environment file when running configuration-dependent flows.

## Start disposable PostgreSQL 16

For a local test database, run:

```sh
docker run --rm --name authplatform-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=authplatform_test \
  -p 5432:5432 \
  postgres:16
```

Keep this terminal open while the database is in use. Stop it with Ctrl+C; `--rm` removes the container when it exits.

Set the connection string in the shell where you will run Swift:

```sh
export DATABASE_URL='postgres://postgres:postgres@localhost:5432/authplatform_test?sslmode=disable'
```

The server requires `DATABASE_URL` to configure its PostgreSQL connection. Additional settings and integration examples are in [`AuthPlatform/Server/.env.example`](../AuthPlatform/Server/.env.example). Copy that file to a local `.env` only if your development setup loads it; never commit real credentials or API keys.

## Resolve, build, and test

```sh
cd AuthPlatform/Server
swift package resolve
swift build -c release
swift test
```

The test command runs the server package's unit and integration tests. The PostgreSQL integration tests need the database above.

## CI

The GitHub Actions workflow [Swift](../.github/workflows/swift-ci.yml) validates the root MSAL package manifest and resource files, then resolves and builds the server package and runs its tests against a disposable PostgreSQL 16 service.

## Configuration and security

- Keep provider client secrets and API keys on the server. Do not embed server credentials in the iOS or web client.
- Use unique local credentials and a non-production database for tests.
- Set the relying-party ID and origin to values appropriate for the environment when testing WebAuthn.
- The checked-in `.env.example` documents variable names; it is not a place to store actual secrets.
