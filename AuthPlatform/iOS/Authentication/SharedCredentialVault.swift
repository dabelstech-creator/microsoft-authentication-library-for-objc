import AuthenticationServices
import Foundation
import Security

public struct StoredPasswordCredential: Codable, Equatable, Sendable {
    public let service: String
    public let username: String
    public let password: String

    public init(service: String, username: String, password: String) {
        self.service = service.lowercased()
        self.username = username
        self.password = password
    }
}

public struct StoredCredentialIdentity: Identifiable, Hashable, Sendable {
    public var id: String { service + "|" + username.lowercased() }
    public let service: String
    public let username: String

    public init(service: String, username: String) {
        self.service = service
        self.username = username
    }
}

/// Shared encrypted Keychain storage used by the host app and Credential Provider Extension.
/// The item metadata (domain and username) is searchable; credential secrets are AES-GCM ciphertext.
public enum SharedCredentialVault {
    private static let keychainService = "com.dabelstech.authplatform.encrypted-credential"

    private static var accessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "CredentialKeychainAccessGroup") as? String
    }

    /// Encrypt and store a credential. Existing records retain their stable item ID.
    @discardableResult
    public static func save(_ credential: StoredPasswordCredential) throws -> Bool {
        _ = try saveEncrypted(credential)
        refreshSystemCredentialIdentities { _ in }
        return true
    }

    /// Encrypt and persist a credential, returning the exact envelope for remote synchronization.
    @discardableResult
    static func saveEncrypted(_ credential: StoredPasswordCredential) throws -> EncryptedVaultItemEnvelope {
        let account = accountKey(service: credential.service, username: credential.username)
        let existing = try readEnvelope(account: account)
        let itemID = existing?.clientItemID ?? UUID()
        let envelope = try VaultCryptography.seal(credential, clientItemID: itemID)
        try store(envelope, account: account, username: credential.username)
        return envelope
    }

    public static func credential(service: String, username: String) throws -> StoredPasswordCredential? {
        let account = accountKey(service: service, username: username)
        if let envelope = try readEnvelope(account: account) {
            return try VaultCryptography.open(envelope, as: StoredPasswordCredential.self)
        }

        // One-time migration path for credentials written by the earlier plaintext Keychain format.
        guard let legacy = try readLegacyCredential(service: service, username: username) else { return nil }
        _ = try saveEncrypted(legacy)
        try deleteLegacyCredential(service: service, username: username)
        return legacy
    }

    public static func delete(service: String, username: String) throws {
        let status = SecItemDelete(query(account: accountKey(service: service, username: username)) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.keychain(status) }
        try deleteLegacyCredential(service: service, username: username)
        removeCredentialIdentity(service: service, username: username)
    }

    /// Delete the local record matching a server tombstone without needing plaintext from the caller.
    static func delete(clientItemID: UUID) throws {
        for envelope in try encryptedItems() where envelope.clientItemID == clientItemID {
            let credential = try VaultCryptography.open(envelope, as: StoredPasswordCredential.self)
            try delete(service: credential.service, username: credential.username)
        }
    }

    /// Encrypted local records used by the sync coordinator. No plaintext is returned.
    static func encryptedItems() throws -> [EncryptedVaultItemEnvelope] {
        try readEnvelopes(service: nil)
    }

    /// Import only after authenticating and decrypting the envelope locally.
    static func importEncryptedItem(_ envelope: EncryptedVaultItemEnvelope) throws {
        let credential = try VaultCryptography.open(envelope, as: StoredPasswordCredential.self)
        try store(envelope, account: accountKey(service: credential.service, username: credential.username), username: credential.username)
    }

    /// Returns searchable identity metadata only. Password ciphertext is not decrypted
    /// until after the user completes device-owner authentication in the extension.
    public static func credentialIdentities(for service: String) throws -> [StoredCredentialIdentity] {
        let normalized = service.lowercased()
        let encrypted = try readIdentityAttributes(service: keychainService)
            .compactMap { identity(from: $0, expectedService: normalized, legacy: false) }
        let legacy = try readIdentityAttributes(service: normalized)
            .compactMap { identity(from: $0, expectedService: normalized, legacy: true) }
        return Array(Set(encrypted + legacy)).sorted {
            ($0.username.localizedCaseInsensitiveCompare($1.username) == .orderedAscending)
        }
    }

    private static func allCredentialIdentities() throws -> [StoredCredentialIdentity] {
        let encrypted = try readIdentityAttributes(service: keychainService)
            .compactMap { identity(from: $0, expectedService: nil, legacy: false) }
        let legacyAttributes = try readIdentityAttributes(service: nil)
        let legacy = legacyAttributes.compactMap { attributes -> StoredCredentialIdentity? in
            guard let service = attributes[kSecAttrService as String] as? String,
                  service != keychainService,
                  service.contains(".") else { return nil }
            return identity(from: attributes, expectedService: service.lowercased(), legacy: true)
        }
        return Array(Set(encrypted + legacy)).sorted {
            ($0.service + $0.username).localizedCaseInsensitiveCompare($1.service + $1.username) == .orderedAscending
        }
    }

    private static func readIdentityAttributes(service: String?) throws -> [[String: Any]] {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: false,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        if let service { attributes[kSecAttrService as String] = service }
        if let accessGroup { attributes[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let values = result as? [[String: Any]] else {
            throw VaultError.keychain(status)
        }
        return values
    }

    private static func identity(
        from attributes: [String: Any],
        expectedService: String?,
        legacy: Bool
    ) -> StoredCredentialIdentity? {
        guard let service = attributes[kSecAttrService as String] as? String,
              let account = attributes[kSecAttrAccount as String] as? String else { return nil }
        let components = account.split(separator: "|", maxSplits: 1).map(String.init)
        guard components.count == 2 else { return nil }
        let domain = legacy ? service.lowercased() : components[0].lowercased()
        guard expectedService == nil || expectedService == domain else { return nil }
        let username = (attributes[kSecAttrLabel as String] as? String) ?? components[1]
        return StoredCredentialIdentity(service: domain, username: username)
    }

    /// Rebuild the system's local identity index from the unlocked local vault.
    /// The index contains usernames/domains only; passwords remain encrypted in Keychain.
    public static func refreshSystemCredentialIdentities(completion: @escaping (Result<Void, Error>) -> Void) {
        do {
            let items = try allCredentialIdentities()
            let identities = items.map { item in
                ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: item.service, type: .domain),
                    user: item.username,
                    recordIdentifier: nil
                )
            }
            let store = ASCredentialIdentityStore.shared
            store.getState { state in
                guard state.isEnabled else {
                    completion(.success(()))
                    return
                }
                store.saveCredentialIdentities(identities) { success, error in
                    if let error { completion(.failure(error)) }
                    else if success { completion(.success(())) }
                    else { completion(.failure(VaultError.identityStoreUpdateFailed)) }
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    private static func encryptedItems(for service: String) throws -> [EncryptedVaultItemEnvelope] {
        try readEnvelopes(service: nil).filter { envelope in
            let credential = try VaultCryptography.open(envelope, as: StoredPasswordCredential.self)
            return credential.service == service
        }
    }

    private static func readEnvelope(account: String) throws -> EncryptedVaultItemEnvelope? {
        var attributes = query(account: account)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw VaultError.keychain(status) }
        return try JSONDecoder().decode(EncryptedVaultItemEnvelope.self, from: data)
    }

    private static func readEnvelopes(service: String?) throws -> [EncryptedVaultItemEnvelope] {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        if let accessGroup { attributes[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let values = result as? [Data] else { throw VaultError.keychain(status) }
        let envelopes = try values.map { try JSONDecoder().decode(EncryptedVaultItemEnvelope.self, from: $0) }
        guard let service else { return envelopes }
        return try envelopes.filter {
            try VaultCryptography.open($0, as: StoredPasswordCredential.self).service == service
        }
    }

    private static func store(_ envelope: EncryptedVaultItemEnvelope, account: String, username: String) throws {
        let data = try JSONEncoder().encode(envelope)
        let base = query(account: account)
        let updateAttributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrLabel as String: username
        ]
        let status = SecItemUpdate(base as CFDictionary, updateAttributes as CFDictionary)
        if status == errSecItemNotFound {
            var insert = base
            insert[kSecValueData as String] = data
            insert[kSecAttrLabel as String] = username
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            if addStatus == errSecDuplicateItem {
                let retryStatus = SecItemUpdate(base as CFDictionary, updateAttributes as CFDictionary)
                guard retryStatus == errSecSuccess else { throw VaultError.keychain(retryStatus) }
            } else if addStatus != errSecSuccess {
                throw VaultError.keychain(addStatus)
            }
        } else if status != errSecSuccess {
            throw VaultError.keychain(status)
        }
    }

    private static func query(account: String) -> [String: Any] {
        var value: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false
        ]
        if let accessGroup { value[kSecAttrAccessGroup as String] = accessGroup }
        return value
    }

    private static func accountKey(service: String, username: String) -> String {
        service.lowercased() + "|" + username.lowercased()
    }

    private static func legacyQuery(account: String, service: String) -> [String: Any] {
        var value: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service.lowercased(),
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false
        ]
        if let accessGroup { value[kSecAttrAccessGroup as String] = accessGroup }
        return value
    }

    private static func readLegacyCredential(service: String, username: String) throws -> StoredPasswordCredential? {
        let account = accountKey(service: service, username: username)
        var attributes = legacyQuery(account: account, service: service)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw VaultError.keychain(status) }
        return try JSONDecoder().decode(StoredPasswordCredential.self, from: data)
    }

    private static func readLegacyCredentials(for service: String) throws -> [StoredPasswordCredential] {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        if let accessGroup { attributes[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let values = result as? [Data] else { throw VaultError.keychain(status) }
        return try values.compactMap { try? JSONDecoder().decode(StoredPasswordCredential.self, from: $0) }
    }

    private static func deleteLegacyCredential(service: String, username: String) throws {
        let status = SecItemDelete(legacyQuery(account: accountKey(service: service, username: username), service: service) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.keychain(status) }
    }

    private static func removeCredentialIdentity(service: String, username: String) {
        let identity = ASPasswordCredentialIdentity(
            serviceIdentifier: ASCredentialServiceIdentifier(identifier: service.lowercased(), type: .domain),
            user: username,
            recordIdentifier: nil
        )
        ASCredentialIdentityStore.shared.removeCredentialIdentities([identity]) { _, _ in }
    }

    public enum VaultError: Error {
        case keychain(OSStatus)
        case identityStoreUpdateFailed
    }
}
