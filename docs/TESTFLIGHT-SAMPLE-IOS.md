# TestFlight setup for the iOS Swift sample

This release workflow targets the existing `SampleAppiOS-Swift` Xcode scheme in
`Samples/ios/SampleAppiOS-Swift/SampleAppiOS-Swift.xcodeproj`. It does not
publish the MSAL SDK framework as an app.

## One-time Apple setup (account owner)

1. Enroll in the Apple Developer Program using an Apple Account you control:
   https://developer.apple.com/programs/enroll/
   Membership, identity verification, agreements, and any fees must be completed
   by the account holder. This repository automation cannot create or accept
   those account/legal commitments on your behalf.
2. In Certificates, Identifiers & Profiles, register an explicit App ID using a
   unique reverse-DNS bundle identifier that your team controls. Do not use the
   sample's existing `com.microsoft.SampleAppiOS-Swift` identifier unless your
   team is authorized to use it.
3. In App Store Connect, create a new iOS app record and select the same bundle
   identifier and the correct Apple Developer team. Complete any required
   agreements and app information.
4. Create an App Store Connect API key with permission to upload builds
   (App Manager or an appropriately scoped role). Download its `.p8` file once.
   Keep the key private; never commit it, paste it into issues, or add it to
   repository files.

## Configure GitHub Actions secrets

In the repository, open Settings → Secrets and variables → Actions and add:

| Secret | Value |
| --- | --- |
| `ASC_KEY_ID` | Key ID shown when the App Store Connect API key was created |
| `ASC_ISSUER_ID` | Issuer ID shown in App Store Connect API access |
| `ASC_PRIVATE_KEY_BASE64` | Base64 encoding of the downloaded `.p8` file |
| `IOS_TEAM_ID` | Your Apple Developer Team ID |
| `IOS_BUNDLE_ID` | The exact registered App ID / App Store Connect bundle ID |

For example, encode the key locally without printing its contents:

```sh
base64 < AuthKey_XXXXXXXXXX.p8 | tr -d '\\n'
```

Copy the command output directly into the GitHub secret field. Do not send it
in chat. Restrict the workflow's `testflight` environment to trusted
maintainers and enable required reviewers if appropriate.

## Run

1. Open Actions → **Sample iOS TestFlight** → Run workflow.
2. First run with `upload_to_testflight = false` to validate the simulator build.
3. After all five secrets and the Apple app record are ready, run again with
   `upload_to_testflight = true`.
4. Confirm the uploaded build finishes processing in App Store Connect, then
   add TestFlight internal testers and complete export-compliance / beta review
   questions as Apple requests.

The upload job is manual and gated. Pull requests only perform an unsigned
simulator build; they never receive signing credentials or upload a release.
