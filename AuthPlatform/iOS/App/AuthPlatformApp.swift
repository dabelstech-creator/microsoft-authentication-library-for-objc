import LocalAuthentication
import SwiftUI

@main
struct AuthPlatformApp: App {
    var body: some Scene {
        WindowGroup {
            AuthenticationDemoView()
        }
    }
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
                    }

                    Section("Session") {
                        Button("Sign out and revoke this session", role: .destructive) {
                            Task { await signOut() }
                        }
                        .disabled(isBusy)
                    }
                }

                Section("Password and verification fields") {
                    SecureField("New password", text: $newPassword)
                        .textContentType(.newPassword)
                    TextField("One-time code", text: $verificationCode)
                        .textContentType(.oneTimeCode)
                        .keyboardType(.numberPad)
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
        guard VaultCryptography.hasVaultKey() else {
            status = "Create and export a recovery kit before saving credentials."
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let credential = StoredPasswordCredential(service: service, username: username, password: password)
            let envelope = try SharedCredentialVault.saveEncrypted(credential)
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
            status = "Credential saved locally only or not saved: \(error.localizedDescription)"
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
            var conflicts = 0

            for record in remote {
                if record.isDeleted {
                    try SharedCredentialVault.delete(clientItemID: record.clientItemID)
                    continue
                }
                let envelope = EncryptedVaultItemEnvelope(
                    clientItemID: record.clientItemID,
                    ciphertext: record.ciphertext,
                    nonce: record.nonce,
                    authenticationTag: record.authenticationTag,
                    formatVersion: record.formatVersion
                )
                if let localEnvelope = localByID[record.clientItemID] {
                    if localEnvelope != envelope { conflicts += 1 }
                } else {
                    try SharedCredentialVault.importEncryptedItem(envelope)
                }
            }

            local = try SharedCredentialVault.encryptedItems()
            for envelope in local where !remoteIDs.contains(envelope.clientItemID) {
                _ = try await api.saveVaultItem(envelope, accessToken: currentAccessToken)
            }

            if conflicts > 0 {
                status = "Synchronization completed with \(conflicts) unresolved item conflict(s). Neither copy was overwritten. Version-aware conflict resolution is still required."
            } else {
                status = "Encrypted vault synchronization completed. Remote tombstones were applied."
            }
        } catch {
            status = "Vault synchronization failed safely: \(error.localizedDescription)"
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
}
