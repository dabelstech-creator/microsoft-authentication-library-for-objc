import AuthenticationServices
import LocalAuthentication
import SwiftUI
import UIKit

@main
struct AuthPlatformApp: App {
    var body: some Scene {
        WindowGroup {
            AuthenticationDemoView()
        }
    }
}

private struct VaultSyncConflict: Identifiable {
    var id: UUID { localEnvelope.clientItemID }
    let localEnvelope: EncryptedVaultItemEnvelope
    let remoteEnvelope: EncryptedVaultItemEnvelope
    let remoteVersion: Int
    let isRemoteDeleted: Bool
    let service: String
    let username: String
}

@MainActor
private struct AuthenticationDemoView: View {
    @State private var username = ""
    @State private var password = ""
    @State private var newPassword = ""
    @State private var verificationCode = ""
    @State private var signedIn = false
    @State private var currentAccessToken = ""
    @State private var workosSignedIn = false
    @State private var status = "Sign in to your AuthPlatform account."
    @State private var isBusy = false
    @State private var recoveryCode = ""
    @State private var recoveryPackageJSON = ""
    @State private var recoveryImportCode = ""
    @State private var recoveryImportJSON = ""
    @State private var syncConflicts: [VaultSyncConflict] = []

    private var service: String {
        Bundle.main.object(forInfoDictionaryKey: "AUTH_CREDENTIAL_SERVICE") as? String ?? "auth.moredesa.com"
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Sign in to AuthPlatform") {
                    TextField("Email address", text: $username)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                    Button {
                        Task { await signIn() }
                    } label: {
                        if isBusy { ProgressView() } else { Text("Sign in securely") }
                    }
                    .disabled(isBusy || username.isEmpty || password.isEmpty)
                    Button("Sign in with passkey") {
                        Task { await signInWithPasskey() }
                    }
                    .disabled(isBusy || username.isEmpty)
                }

                Section("WorkOS AuthKit") {
                    Button {
                        Task { await signInWithWorkOS() }
                    } label: {
                        if isBusy { ProgressView() } else { Text("Continue with WorkOS") }
                    }
                    .disabled(isBusy || workosSignedIn)
                    if workosSignedIn {
                        Text("WorkOS identity is connected to an AuthPlatform session.")
                            .font(.footnote)
                    }
                }

                if signedIn {
                    Section("Passkeys") {
                        Button("Register this iPhone as a passkey") {
                            Task { await registerPasskey() }
                        }
                        .disabled(isBusy || currentAccessToken.isEmpty)
                        Text("Passkeys are registered and verified by the AuthPlatform WebAuthn server. Face ID or device passcode is required by the platform authenticator.")
                            .font(.footnote)
                    }

                    Section("Encrypted password vault") {
                        Text("Credentials are encrypted on this device before they are stored in the shared Keychain or sent to the server.")
                            .font(.footnote)
                        Button("Create or export recovery kit") {
                            createRecoveryKit()
                        }
                        .disabled(isBusy)
                        if !recoveryCode.isEmpty {
                            Text("Recovery code — store it separately from the recovery package")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(recoveryCode)
                                .textSelection(.enabled)
                                .font(.system(.footnote, design: .monospaced))
                            if !recoveryPackageJSON.isEmpty {
                                ShareLink(item: recoveryPackageJSON) {
                                    Label("Export encrypted recovery package", systemImage: "square.and.arrow.up")
                                }
                            }
                        }
                        Button {
                            Task { await syncVault() }
                        } label: {
                            Label("Synchronize encrypted vault", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .disabled(isBusy || !VaultCryptography.hasVaultKey())
                    }

                    if !syncConflicts.isEmpty {
                        Section("Resolve synchronization conflicts") {
                            ForEach(syncConflicts) { conflict in
                                VStack(alignment: .leading, spacing: 8) {
                                    Text(conflict.username)
                                        .font(.headline)
                                    Text(conflict.service)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(conflict.isRemoteDeleted
                                        ? "The cloud copy was deleted. Keep your local copy as a new item or accept the deletion."
                                        : "Cloud version \(conflict.remoteVersion). Choose which encrypted copy to keep.")
                                        .font(.footnote)
                                    HStack {
                                        Button("Keep this iPhone") {
                                            Task { await resolveSyncConflict(conflict, keepLocal: true) }
                                        }
                                        Button("Use cloud copy") {
                                            Task { await resolveSyncConflict(conflict, keepLocal: false) }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Section("Restore vault on this device") {
                        SecureField("Recovery code", text: $recoveryImportCode)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        TextEditor(text: $recoveryImportJSON)
                            .frame(minHeight: 100)
                            .overlay(alignment: .topLeading) {
                                if recoveryImportJSON.isEmpty {
                                    Text("Paste the exported recovery package JSON")
                                        .foregroundStyle(.secondary)
                                        .padding(.top, 8)
                                        .padding(.leading, 5)
                                        .allowsHitTesting(false)
                                }
                            }
                        Button("Restore encrypted vault key") {
                            restoreVault()
                        }
                        .disabled(isBusy || recoveryImportCode.isEmpty || recoveryImportJSON.isEmpty || VaultCryptography.hasVaultKey())
                    }

                    Section("Apple Password AutoFill") {
                        Text("Save the signed-in credential only after creating a vault key and saving its recovery kit.")
                            .font(.footnote)
                        Button("Encrypt and save this sign-in") {
                            Task { await saveCredential() }
                        }
                        .disabled(isBusy || password.isEmpty || !VaultCryptography.hasVaultKey())
                        Button("Unlock saved sign-in with Face ID / passcode") {
                            Task { await unlockCredential() }
                        }
                        .disabled(isBusy || username.isEmpty)
                        Button("Delete saved sign-in from all devices", role: .destructive) {
                            Task { await deleteCredential() }
                        }
                        .disabled(isBusy || username.isEmpty)
                    }

                    Section("Session") {
                        Button("Sign out and revoke this session", role: .destructive) {
                            Task { await signOut() }
                        }
                        .disabled(isBusy)
                    }
                }

                Section("Create account and verify email") {
                    SecureField("New account password", text: $newPassword)
                        .textContentType(.newPassword)
                    Button("Create account") {
                        Task { await createAccount() }
                    }
                    .disabled(isBusy || username.isEmpty || newPassword.isEmpty)
                    Button("Resend verification email") {
                        Task { await requestEmailVerification() }
                    }
                    .disabled(isBusy || username.isEmpty)
                    SecureField("Verification token from email", text: $verificationCode)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Verify email address") {
                        Task { await verifyEmail() }
                    }
                    .disabled(isBusy || verificationCode.isEmpty)
                }

                Section("Account recovery") {
                    Button("Send password-reset email") {
                        Task { await requestPasswordReset() }
                    }
                    .disabled(isBusy || username.isEmpty)
                    SecureField("New password", text: $newPassword)
                        .textContentType(.newPassword)
                    Button("Reset password using email token") {
                        Task { await resetPassword() }
                    }
                    .disabled(isBusy || verificationCode.isEmpty || newPassword.isEmpty)
                }

                Section("Status") {
                    Text(status)
                        .font(.footnote)
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("AuthPlatform")
        }
        .task {
            await restoreSession()
        }
    }

    private func signInWithPasskey() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let api = try AuthPlatformAPI()
            let options = try await api.passkeyAuthenticationOptions(email: username)
            let challenge = try decodePasskeyBase64URL(options.publicKey.challenge)
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: options.publicKey.rpId
            )
            let request = provider.createCredentialAssertionRequest(challenge: challenge)
            if let allowedCredentials = options.publicKey.allowCredentials {
                request.allowedCredentials = try allowedCredentials.map { descriptor in
                    ASAuthorizationPlatformPublicKeyCredentialDescriptor(
                        credentialID: try decodePasskeyBase64URL(descriptor.id)
                    )
                }
            }
            request.userVerificationPreference = .required

            let authorization = try await PasskeyService(presentationAnchor: currentPresentationAnchor())
                .authorize([request])
            guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
                throw PasskeyFlowError.unexpectedCredential
            }

            let credentialID = credential.credentialID.webAuthnBase64URLEncodedString()
            let userHandle = credential.userID?.isEmpty == false ? credential.userID?.webAuthnBase64URLEncodedString() : nil
            let payload = PasskeyAuthenticationCredentialPayload(
                id: credentialID,
                rawId: credentialID,
                response: PasskeyAssertionResponsePayload(
                    clientDataJSON: credential.rawClientDataJSON.webAuthnBase64URLEncodedString(),
                    authenticatorData: credential.rawAuthenticatorData.webAuthnBase64URLEncodedString(),
                    signature: credential.signature.webAuthnBase64URLEncodedString(),
                    userHandle: userHandle
                )
            )
            let tokens = try await api.finishPasskeyAuthentication(
                challengeID: options.challengeID,
                credential: payload
            )
            guard tokens.emailVerified else {
                status = "The passkey account is not verified. Contact support."
                return
            }
            try AuthSessionVault.save(refreshToken: tokens.refreshToken)
            currentAccessToken = tokens.accessToken
            signedIn = true
            workosSignedIn = false
            status = "Passkey authentication succeeded and the server issued a new session."
            await synchronizeAfterAuthentication()
        } catch {
            status = "Passkey sign-in failed: \(error.localizedDescription)"
        }
    }

    private func registerPasskey() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let api = try AuthPlatformAPI()
            let options = try await api.passkeyRegistrationOptions(accessToken: currentAccessToken)
            let challenge = try decodePasskeyBase64URL(options.publicKey.challenge)
            let userID = try decodePasskeyBase64URL(options.publicKey.user.id)
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: options.publicKey.rp.id
            )
            let request = provider.createCredentialRegistrationRequest(
                challenge: challenge,
                name: options.publicKey.user.name,
                userID: userID
            )
            request.displayName = options.publicKey.user.displayName
            request.userVerificationPreference = .required

            let authorization = try await PasskeyService(presentationAnchor: currentPresentationAnchor())
                .authorize([request])
            guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
                  let attestationObject = credential.rawAttestationObject else {
                throw PasskeyFlowError.missingAttestation
            }

            let credentialID = credential.credentialID.webAuthnBase64URLEncodedString()
            let payload = PasskeyRegistrationCredentialPayload(
                id: credentialID,
                rawId: credentialID,
                response: PasskeyAttestationResponsePayload(
                    clientDataJSON: credential.rawClientDataJSON.webAuthnBase64URLEncodedString(),
                    attestationObject: attestationObject.webAuthnBase64URLEncodedString()
                )
            )
            try await api.finishPasskeyRegistration(
                challengeID: options.challengeID,
                credential: payload,
                accessToken: currentAccessToken
            )
            status = "This iPhone's passkey was verified and registered with AuthPlatform."
        } catch {
            status = "Passkey registration failed: \(error.localizedDescription)"
        }
    }

    private func currentPresentationAnchor() throws -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        guard let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow) else {
            throw PasskeyFlowError.noPresentationWindow
        }
        return window
    }

    private func decodePasskeyBase64URL(_ value: String) throws -> Data {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: base64), !data.isEmpty else {
            throw PasskeyFlowError.invalidServerChallenge
        }
        return data
    }

    private func createAccount() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await AuthPlatformAPI().register(email: username, password: newPassword)
            status = result.emailVerificationRequired
                ? "Account created. Check your email for the verification link, then paste its token above."
                : "Account created. You can now sign in."
        } catch {
            status = "Account registration failed: \(error.localizedDescription)"
        }
    }

    private func requestEmailVerification() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await AuthPlatformAPI().requestEmailVerification(email: username)
            status = "If the account exists and needs verification, a verification email has been sent."
        } catch {
            status = "Could not request email verification: \(error.localizedDescription)"
        }
    }

    private func verifyEmail() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await AuthPlatformAPI().verifyEmail(token: verificationCode)
            verificationCode = ""
            status = "Email verified. Sign in to continue."
        } catch {
            status = "Email verification failed: \(error.localizedDescription)"
        }
    }

    private func requestPasswordReset() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await AuthPlatformAPI().requestPasswordReset(email: username)
            status = "If the account exists, password-reset instructions have been sent."
        } catch {
            status = "Could not request password recovery: \(error.localizedDescription)"
        }
    }

    private func resetPassword() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await AuthPlatformAPI().resetPassword(token: verificationCode, newPassword: newPassword)
            verificationCode = ""
            newPassword = ""
            status = "Password reset successfully. Sign in with the new password."
        } catch {
            status = "Password reset failed: \(error.localizedDescription)"
        }
    }

    private func signIn() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let api = try AuthPlatformAPI()
            let tokens = try await api.login(email: username, password: password)
            guard tokens.emailVerified else {
                status = "Verify your email before using this account."
                return
            }
            try AuthSessionVault.save(refreshToken: tokens.refreshToken)
            currentAccessToken = tokens.accessToken
            signedIn = true
            status = "Signed in. Preparing encrypted vault synchronization."
            await synchronizeAfterAuthentication()
        } catch {
            status = error.localizedDescription
        }
    }

    private func signInWithWorkOS() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let workOS = try await WorkOSAuthKitService().signIn()
            let api = try AuthPlatformAPI()
            let appSession = try await api.exchangeWorkOS(accessToken: workOS.accessToken)
            guard appSession.emailVerified else {
                status = "Your WorkOS identity must have a verified email address."
                return
            }
            try AuthSessionVault.save(refreshToken: appSession.refreshToken)
            currentAccessToken = appSession.accessToken
            signedIn = true
            workosSignedIn = true
            status = "WorkOS sign-in completed. AuthPlatform session established."
            await synchronizeAfterAuthentication()
        } catch {
            status = error.localizedDescription
        }
    }

    private func restoreSession() async {
        guard !signedIn else { return }
        let storedRefreshToken: String
        do {
            guard let token = try AuthSessionVault.refreshToken(), !token.isEmpty else { return }
            storedRefreshToken = token
        } catch {
            status = "Could not read the saved session: \(error.localizedDescription)"
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let tokens = try await AuthPlatformAPI().refresh(refreshToken: storedRefreshToken)
            try AuthSessionVault.save(refreshToken: tokens.refreshToken)
            currentAccessToken = tokens.accessToken
            signedIn = tokens.emailVerified
            if signedIn {
                status = "Your existing session was securely refreshed."
                await synchronizeAfterAuthentication()
            }
        } catch let error as AuthPlatformAPIError {
            if case .rejected(401, _) = error {
                try? AuthSessionVault.deleteRefreshToken()
                status = "Your saved session expired. Please sign in again."
            } else {
                status = "Could not refresh the saved session: \(error.localizedDescription)"
            }
        } catch {
            status = "Could not refresh the saved session: \(error.localizedDescription)"
        }
    }

    private func synchronizeAfterAuthentication() async {
        guard VaultCryptography.hasVaultKey() else {
            status = "Signed in. Create a vault key and recovery kit before saving passwords."
            return
        }
        await syncVault()
    }

    private func createRecoveryKit() {
        do {
            let kit = VaultCryptography.hasVaultKey()
                ? try VaultCryptography.createRecoveryKit()
                : try VaultCryptography.createVaultKey()
            recoveryCode = kit.recoveryCode
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(kit.recoveryPackage)
            recoveryPackageJSON = String(decoding: data, as: UTF8.self)
            status = "Recovery kit created. Save the recovery code and export the encrypted package before storing passwords."
        } catch {
            status = "Could not create a recovery kit: \(error.localizedDescription)"
        }
    }

    private func restoreVault() {
        do {
            let package = try JSONDecoder().decode(
                VaultCryptography.RecoveryPackage.self,
                from: Data(recoveryImportJSON.utf8)
            )
            try VaultCryptography.restoreVaultKey(recoveryCode: recoveryImportCode, package: package)
            recoveryImportCode = ""
            recoveryImportJSON = ""
            status = "Vault key restored. Synchronizing encrypted records."
            Task { await syncVault() }
        } catch {
            status = "Vault recovery failed: \(error.localizedDescription)"
        }
    }

    private func saveCredential() async {
        var savedLocally = false
        guard VaultCryptography.hasVaultKey() else {
            status = "Create and export a recovery kit before saving credentials."
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let credential = StoredPasswordCredential(service: service, username: username, password: password)
            let envelope = try SharedCredentialVault.saveEncrypted(credential)
            savedLocally = true
            SharedCredentialVault.refreshSystemCredentialIdentities { _ in }
            guard !currentAccessToken.isEmpty else {
                status = "Credential encrypted and saved on this iPhone. Sign in again to synchronize it."
                return
            }
            let api = try AuthPlatformAPI()
            let existing = try await api.listVaultItems(accessToken: currentAccessToken)
                .first(where: { $0.clientItemID == envelope.clientItemID })
            if existing?.isDeleted == true {
                throw AuthPlatformAPIError.rejected(409, "This item was deleted on another device. Save it as a new credential instead.")
            }
            _ = try await api.saveVaultItem(
                envelope,
                expectedVersion: existing?.version,
                accessToken: currentAccessToken
            )
            status = "Credential encrypted, saved locally, and synchronized at the server's current item version."
        } catch {
            status = savedLocally
                ? "Credential is saved on this iPhone, but cloud synchronization failed: \(error.localizedDescription)"
                : "Credential could not be saved: \(error.localizedDescription)"
        }
    }

    private func syncVault() async {
        guard !currentAccessToken.isEmpty else {
            status = "Sign in before synchronizing the encrypted vault."
            return
        }
        guard VaultCryptography.hasVaultKey() else {
            status = "Create or restore your vault key before synchronizing."
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let api = try AuthPlatformAPI()
            let remote = try await api.listVaultItems(accessToken: currentAccessToken)
            var local = try SharedCredentialVault.encryptedItems()
            let localByID = Dictionary(uniqueKeysWithValues: local.map { ($0.clientItemID, $0) })
            let remoteIDs = Set(remote.map(\.clientItemID))
            var conflicts: [VaultSyncConflict] = []

            for record in remote {
                let envelope = EncryptedVaultItemEnvelope(
                    clientItemID: record.clientItemID,
                    ciphertext: record.ciphertext,
                    nonce: record.nonce,
                    authenticationTag: record.authenticationTag,
                    formatVersion: record.formatVersion
                )
                if record.isDeleted {
                    if let localEnvelope = localByID[record.clientItemID], localEnvelope != envelope {
                        let localCredential = try VaultCryptography.open(localEnvelope, as: StoredPasswordCredential.self)
                        conflicts.append(VaultSyncConflict(
                            localEnvelope: localEnvelope,
                            remoteEnvelope: envelope,
                            remoteVersion: record.version,
                            isRemoteDeleted: true,
                            service: localCredential.service,
                            username: localCredential.username
                        ))
                    } else {
                        try SharedCredentialVault.delete(clientItemID: record.clientItemID)
                    }
                    continue
                }

                if let localEnvelope = localByID[record.clientItemID] {
                    if localEnvelope != envelope {
                        let localCredential = try VaultCryptography.open(localEnvelope, as: StoredPasswordCredential.self)
                        let remoteCredential = try VaultCryptography.open(envelope, as: StoredPasswordCredential.self)
                        conflicts.append(VaultSyncConflict(
                            localEnvelope: localEnvelope,
                            remoteEnvelope: envelope,
                            remoteVersion: record.version,
                            isRemoteDeleted: false,
                            service: remoteCredential.service,
                            username: localCredential.username == remoteCredential.username
                                ? remoteCredential.username
                                : "\(localCredential.username) / \(remoteCredential.username)"
                        ))
                    }
                } else {
                    try SharedCredentialVault.importEncryptedItem(envelope)
                }
            }

            local = try SharedCredentialVault.encryptedItems()
            for envelope in local where !remoteIDs.contains(envelope.clientItemID) {
                _ = try await api.saveVaultItem(envelope, accessToken: currentAccessToken)
            }

            syncConflicts = conflicts
            SharedCredentialVault.refreshSystemCredentialIdentities { _ in }
            if !conflicts.isEmpty {
                status = "Synchronization found \(conflicts.count) conflict(s). Choose whether to keep the local or cloud copy for each item."
            } else {
                status = "Encrypted vault synchronization completed. Remote tombstones were applied."
            }
        } catch {
            status = "Vault synchronization failed safely: \(error.localizedDescription)"
        }
    }

    private func resolveSyncConflict(_ conflict: VaultSyncConflict, keepLocal: Bool) async {
        isBusy = true
        defer { isBusy = false }
        do {
            if keepLocal {
                let api = try AuthPlatformAPI()
                if conflict.isRemoteDeleted {
                    let credential = try VaultCryptography.open(
                        conflict.localEnvelope,
                        as: StoredPasswordCredential.self
                    )
                    let replacement = try VaultCryptography.seal(credential, clientItemID: UUID())
                    _ = try await api.saveVaultItem(replacement, accessToken: currentAccessToken)
                    try SharedCredentialVault.delete(clientItemID: conflict.localEnvelope.clientItemID)
                    try SharedCredentialVault.importEncryptedItem(replacement)
                } else {
                    _ = try await api.saveVaultItem(
                        conflict.localEnvelope,
                        expectedVersion: conflict.remoteVersion,
                        accessToken: currentAccessToken
                    )
                }
            } else {
                try SharedCredentialVault.delete(clientItemID: conflict.localEnvelope.clientItemID)
                if !conflict.isRemoteDeleted {
                    try SharedCredentialVault.importEncryptedItem(conflict.remoteEnvelope)
                }
            }
            syncConflicts.removeAll { $0.id == conflict.id }
            SharedCredentialVault.refreshSystemCredentialIdentities { _ in }
            status = keepLocal
                ? (conflict.isRemoteDeleted
                    ? "Your local credential was restored as a new vault item; the deleted ID was not reused."
                    : "The local encrypted copy is now the server's current version.")
                : (conflict.isRemoteDeleted
                    ? "The cloud deletion was accepted and the local credential was removed."
                    : "The cloud encrypted copy replaced the local copy on this iPhone.")
        } catch {
            status = "Conflict resolution failed safely: \(error.localizedDescription)"
        }
    }

    private func unlockCredential() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let context = LAContext()
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your saved AuthPlatform sign-in")
            guard let credential = try SharedCredentialVault.credential(service: service, username: username) else {
                status = "No saved credential was found for this email and domain."
                return
            }
            status = "Unlocked \(credential.username) for \(credential.service). The Credential Provider can now offer it to AutoFill."
        } catch {
            status = "Unlock failed: \(error.localizedDescription)"
        }
    }

    private func deleteCredential() async {
        isBusy = true
        defer { isBusy = false }
        do {
            guard let credential = try SharedCredentialVault.credential(service: service, username: username) else {
                status = "No saved credential exists for this account on this iPhone."
                return
            }
            let localEnvelope = try SharedCredentialVault.encryptedItems().first { envelope in
                let stored = try VaultCryptography.open(envelope, as: StoredPasswordCredential.self)
                return stored.service == credential.service && stored.username.lowercased() == credential.username.lowercased()
            }
            if let localEnvelope, !currentAccessToken.isEmpty {
                let api = try AuthPlatformAPI()
                let remote = try await api.listVaultItems(accessToken: currentAccessToken)
                    .first(where: { $0.clientItemID == localEnvelope.clientItemID })
                if let remote, !remote.isDeleted {
                    try await api.deleteVaultItem(
                        clientItemID: remote.clientItemID,
                        expectedVersion: remote.version,
                        accessToken: currentAccessToken
                    )
                }
            }
            try SharedCredentialVault.delete(service: credential.service, username: credential.username)
            SharedCredentialVault.refreshSystemCredentialIdentities { _ in }
            status = "Credential deleted locally and its server tombstone synchronized where a remote copy existed."
        } catch {
            status = "Deletion was not completed: \(error.localizedDescription)"
        }
    }

    private func signOut() async {
        isBusy = true
        defer { isBusy = false }
        do {
            if let refreshToken = try AuthSessionVault.refreshToken() {
                try await AuthPlatformAPI().logout(refreshToken: refreshToken)
            }
            try AuthSessionVault.deleteRefreshToken()
            currentAccessToken = ""
            signedIn = false
            workosSignedIn = false
            password = ""
            status = "Signed out. The server session was revoked."
        } catch {
            status = "Sign-out could not confirm server revocation: \(error.localizedDescription). Your local session remains available so you can retry."
        }
    }
private enum PasskeyFlowError: LocalizedError {
    case noPresentationWindow
    case invalidServerChallenge
    case unexpectedCredential
    case missingAttestation

    var errorDescription: String? {
        switch self {
        case .noPresentationWindow: return "The passkey interface could not find an active app window."
        case .invalidServerChallenge: return "The server returned an invalid WebAuthn challenge or credential identifier."
        case .unexpectedCredential: return "Apple returned an unexpected passkey credential type."
        case .missingAttestation: return "Apple did not return an attestation object for passkey registration."
        }
    }
}


}
