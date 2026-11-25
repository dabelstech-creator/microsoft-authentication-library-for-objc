# Project Wiki

Welcome to the repository's documentation hub.

## Pages

- [AuthPlatform Server](AuthPlatform-Server.md) — server layout, local PostgreSQL setup, build, tests, and CI.
- [MSAL for iOS and macOS](../README.md) — SDK overview, installation, usage, and official documentation.
- [MSAL 2.x migration guide](../docs/MSAL_2x_Migration_Guide.md) — breaking changes and migration steps.

## Repository layout

- `Package.swift` at the repository root describes the MSAL binary Swift package.
- `AuthPlatform/Server/Package.swift` describes the separate Vapor server package.
- `AuthPlatform/iOS` contains the AuthPlatform iOS app.
- `AuthPlatform/Web` contains the AuthPlatform web app.

## Contributing to these docs

Update the Markdown page alongside the code change it describes. Keep commands and configuration aligned with the server package and CI workflow.
