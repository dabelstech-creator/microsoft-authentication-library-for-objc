# Physical iPhone release checklist

This checklist is required before calling AuthPlatform production-ready. Simulator
builds do not verify Associated Domains, Keychain Sharing, passkey relying-party
validation, or the real Credential Provider Extension lifecycle.

## Apple signing and entitlements

1. Set the Apple Developer Team in Xcode for both `AuthPlatform` and
   `CredentialProviderExtension`.
2. Enable automatic signing or select valid provisioning profiles for both
   targets.
3. Confirm both targets carry the same Keychain access group prefix and the
   extension can read the host app's vault master-key item.
4. Confirm the host app's Associated Domains entitlement includes
   `webcredentials:<AUTH_WEBAUTHN_RP_ID>`.
5. Do not ship a build produced with `CODE_SIGNING_ALLOWED=NO`.

The repository intentionally does not guess the Apple Developer Team ID. The
AASA template is at
`AuthPlatform/Web/public/.well-known/apple-app-site-association.template.json`.
Replace `YOUR_APPLE_TEAM_ID` with the Team ID and publish the resulting
extensionless file at
`https://<AUTH_WEBAUTHN_RP_ID>/.well-known/apple-app-site-association`.
Serve it as JSON over HTTPS without redirects. Its app identifier must be
`<TEAM_ID>.com.dabelstech.authplatform`.

## Environment-specific builds

The XcodeGen project defines production defaults. For a staging build, override
all three values together so the app, WebAuthn server, and Associated Domains
use the same staging hostname:

```sh
xcodegen generate --spec AuthPlatform/iOS/project.yml
xcodebuild \
  -project AuthPlatform/iOS/AuthPlatform.xcodeproj \
  -scheme AuthPlatform \
  -destination 'generic/platform=iOS' \
  AUTH_API_BASE_URL=https://<staging-host> \
  AUTH_CREDENTIAL_SERVICE=<staging-host> \
  AUTH_WEBAUTHN_RP_ID=<staging-host> \
  archive
```

Set the server's `WEBAUTHN_RP_ID` to the same hostname and
`WEBAUTHN_ORIGIN` to the exact HTTPS origin. Register
`authplatform://auth/callback` in the WorkOS test/production configuration
for the corresponding build.

## Required physical-device tests

- Install the signed host app and Credential Provider Extension on a physical iPhone.
- Enable AuthPlatform under Settings → General → AutoFill & Passwords.
- Save a credential; verify the Keychain record is encrypted and the extension only decrypts after Face ID, Touch ID, or passcode succeeds.
- Trigger AutoFill from Safari and a native app; verify correct domain matching and credential selection.
- Register a platform passkey, then sign out and sign in using that passkey.
- Create a recovery kit; verify the code and package are stored separately.
- Restore the vault on a second clean device using the recovery code and package.
- Test two-device edits, explicit local/cloud conflict resolution, cloud tombstone propagation, and the rule that a deleted item ID is never reused.
- Test refresh-token rotation, reuse detection, session revocation, logout, email verification, and password reset.
- Test airplane-mode access to already-saved local credentials and safe behavior when cloud synchronization fails.
- Verify no password, master key, recovery code, or refresh token appears in application logs, analytics, crash reports, or network payloads.

Record device model, iOS version, build number, test account, and pass/fail evidence
for each test. Do not use real user vault data in staging.
