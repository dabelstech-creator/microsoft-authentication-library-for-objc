import Foundation
import Security

struct AuthTokenResponse: Decodable {
    let userID: UUID
    let accessToken: String
    let refreshToken: String
    let tokenType: String
    let accessTokenExpiresIn: Int
    let emailVerified: Bool

    enum CodingKeys: String, CodingKey {
        case userID, accessToken, refreshToken, tokenType, accessTokenExpiresIn, emailVerified
    }
}


/// A versioned server record. Tombstones remain visible to every sync client.
struct EncryptedVaultItemRecord: Decodable, Sendable {
    let clientItemID: UUID
    let ciphertext: String
    let nonce: String
    let authenticationTag: String
    let formatVersion: Int
    let version: Int
    let isDeleted: Bool

    private enum CodingKeys: String, CodingKey {
        case clientItemID, ciphertext, nonce, authenticationTag, formatVersion, version, isDeleted
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        clientItemID = try values.decode(UUID.self, forKey: .clientItemID)
        ciphertext = try values.decode(String.self, forKey: .ciphertext)
        nonce = try values.decode(String.self, forKey: .nonce)
        authenticationTag = try values.decode(String.self, forKey: .authenticationTag)
        formatVersion = try values.decode(Int.self, forKey: .formatVersion)
        version = try values.decodeIfPresent(Int.self, forKey: .version) ?? 1
        isDeleted = try values.decode(Bool.self, forKey: .isDeleted)
    }
}

private struct EncryptedVaultItemPage: Decodable {
    let items: [EncryptedVaultItemRecord]
    let nextOffset: Int?
    let snapshot: String
}

private struct VaultWriteRequest: Encodable {
    let clientItemID: UUID
    let ciphertext: String
    let nonce: String
    let authenticationTag: String
    let formatVersion: Int
    let expectedVersion: Int?
}

enum AuthPlatformAPIError: LocalizedError {
    case missingBaseURL
    case invalidResponse
    case rejected(Int, String)

    var errorDescription: String? {
        switch self {
        case .missingBaseURL: return "Set AUTH_API_BASE_URL in the app Info.plist to your HTTPS AuthPlatform server URL."
        case .invalidResponse: return "The authentication server returned an invalid response."
        case let .rejected(code, message): return "Authentication failed (HTTP \(code)): \(message)"
        }
    }
}

final class AuthPlatformAPI {
    private let baseURL: URL
    private let session: URLSession

    init(bundle: Bundle = .main, session: URLSession = .shared) throws {
        guard let raw = bundle.object(forInfoDictionaryKey: "AUTH_API_BASE_URL") as? String,
              let url = URL(string: raw),
              url.scheme == "https" || url.host == "127.0.0.1" || url.host == "localhost"
        else { throw AuthPlatformAPIError.missingBaseURL }
        baseURL = url
        self.session = session
    }

    func login(email: String, password: String) async throws -> AuthTokenResponse {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1").appendingPathComponent("auth").appendingPathComponent("login"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(LoginRequest(email: email, password: password))
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
        return try JSONDecoder().decode(AuthTokenResponse.self, from: data)
    }

    func refresh(refreshToken: String) async throws -> AuthTokenResponse {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1").appendingPathComponent("auth").appendingPathComponent("refresh"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(RefreshRequest(refreshToken: refreshToken))
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
        return try JSONDecoder().decode(AuthTokenResponse.self, from: data)
    }


    func register(email: String, password: String) async throws -> RegistrationResponse {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1").appendingPathComponent("auth").appendingPathComponent("register"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(LoginRequest(email: email, password: password))
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
        return try JSONDecoder().decode(RegistrationResponse.self, from: data)
    }

    func requestEmailVerification(email: String) async throws {
        try await postMessage(path: ["v1", "auth", "verification", "request"], body: EmailRequest(email: email))
    }

    func verifyEmail(token: String) async throws {
        try await postMessage(path: ["v1", "auth", "verify-email"], body: TokenRequest(token: token))
    }

    func requestPasswordReset(email: String) async throws {
        try await postMessage(path: ["v1", "auth", "password", "forgot"], body: EmailRequest(email: email))
    }

    func resetPassword(token: String, newPassword: String) async throws {
        try await postMessage(
            path: ["v1", "auth", "password", "reset"],
            body: PasswordResetRequest(token: token, newPassword: newPassword)
        )
    }

    private func postMessage<Body: Encodable>(path: [String], body: Body) async throws {
        var url = baseURL
        for component in path { url.appendPathComponent(component) }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
    }

    func logout(refreshToken: String) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1").appendingPathComponent("auth").appendingPathComponent("logout"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(RefreshRequest(refreshToken: refreshToken))
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
    }

    /// Fetches all pages from one stable server snapshot.
    func listVaultItems(accessToken: String) async throws -> [EncryptedVaultItemRecord] {
        let endpoint = baseURL
            .appendingPathComponent("v1")
            .appendingPathComponent("vault")
            .appendingPathComponent("items")
        var offset = 0
        var snapshot: String?
        var result: [EncryptedVaultItemRecord] = []

        while true {
            guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else {
                throw AuthPlatformAPIError.invalidResponse
            }
            var query = [
                URLQueryItem(name: "limit", value: "100"),
                URLQueryItem(name: "offset", value: String(offset))
            ]
            if let snapshot {
                query.append(URLQueryItem(name: "snapshot", value: snapshot))
            }
            components.queryItems = query
            guard let url = components.url else { throw AuthPlatformAPIError.invalidResponse }

            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            let (data, response) = try await session.data(for: request)
            try Self.validate(response: response, data: data)
            if let page = try? JSONDecoder().decode(EncryptedVaultItemPage.self, from: data) {
                result.append(contentsOf: page.items)
                guard let nextOffset = page.nextOffset else { break }
                guard nextOffset > offset else { throw AuthPlatformAPIError.invalidResponse }
                offset = nextOffset
                snapshot = page.snapshot
            } else if offset == 0 {
                // Backward-compatible read path for servers before versioned pagination.
                result.append(contentsOf: try JSONDecoder().decode([EncryptedVaultItemRecord].self, from: data))
                break
            } else {
                throw AuthPlatformAPIError.invalidResponse
            }
        }
        return result
    }

    /// Uploads a locally encrypted envelope with compare-and-swap version semantics.
    func saveVaultItem(
        _ item: EncryptedVaultItemEnvelope,
        expectedVersion: Int? = nil,
        accessToken: String
    ) async throws -> EncryptedVaultItemRecord {
        var request = URLRequest(url: baseURL
            .appendingPathComponent("v1")
            .appendingPathComponent("vault")
            .appendingPathComponent("items"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONEncoder().encode(VaultWriteRequest(
            clientItemID: item.clientItemID,
            ciphertext: item.ciphertext,
            nonce: item.nonce,
            authenticationTag: item.authenticationTag,
            formatVersion: item.formatVersion,
            expectedVersion: expectedVersion
        ))
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
        return try JSONDecoder().decode(EncryptedVaultItemRecord.self, from: data)
    }

    func deleteVaultItem(clientItemID: UUID, expectedVersion: Int, accessToken: String) async throws {
        var request = URLRequest(url: baseURL
            .appendingPathComponent("v1")
            .appendingPathComponent("vault")
            .appendingPathComponent("items")
            .appendingPathComponent(clientItemID.uuidString))
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(String(expectedVersion), forHTTPHeaderField: "If-Match")
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
    }

    /// Exchanges a verified WorkOS access token for this API's own session.
    /// The WorkOS token is sent only over TLS and is never stored as an AuthPlatform token.
    func exchangeWorkOS(accessToken: String) async throws -> AuthTokenResponse {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1").appendingPathComponent("auth").appendingPathComponent("workos").appendingPathComponent("exchange"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
        return try JSONDecoder().decode(AuthTokenResponse.self, from: data)
    }

    /// Links a separately authenticated WorkOS identity to an already-authenticated local account.
    func linkWorkOS(localAccessToken: String, workOSAccessToken: String) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1").appendingPathComponent("auth").appendingPathComponent("workos").appendingPathComponent("link"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(localAccessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("Bearer \(workOSAccessToken)", forHTTPHeaderField: "X-WorkOS-Authorization")
        let (data, response) = try await session.data(for: request)
        try Self.validate(response: response, data: data)
    }

    private static func validate(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else { throw AuthPlatformAPIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["reason"] as? String
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw AuthPlatformAPIError.rejected(http.statusCode, message)
        }
    }
}

struct RegistrationResponse: Decodable, Sendable {
    let userID: UUID
    let emailVerificationRequired: Bool
}

private struct EmailRequest: Encodable {
    let email: String
}

private struct TokenRequest: Encodable {
    let token: String
}

private struct PasswordResetRequest: Encodable {
    let token: String
    let newPassword: String
}

private struct LoginRequest: Encodable {
    let email: String
    let password: String
}

private struct RefreshRequest: Encodable {
    let refreshToken: String
}

/// Keeps refresh tokens in the app/extension shared Keychain group; never UserDefaults.
enum AuthSessionVault {
    private static let service = "com.example.authplatform.session"
    private static let account = "refresh-token"

    static func save(refreshToken: String) throws {
        let data = Data(refreshToken.utf8)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let group = Bundle.main.object(forInfoDictionaryKey: "CredentialKeychainAccessGroup") as? String {
            query[kSecAttrAccessGroup as String] = group
        }
        let update: [String: Any] = [kSecValueData as String: data,
                                     kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add.merge(update) { _, new in new }
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw AuthSessionVaultError.keychain(addStatus) }
        } else if status != errSecSuccess {
            throw AuthSessionVaultError.keychain(status)
        }
    }

    static func deleteRefreshToken() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let group = Bundle.main.object(forInfoDictionaryKey: "CredentialKeychainAccessGroup") as? String {
            query[kSecAttrAccessGroup as String] = group
        }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AuthSessionVaultError.keychain(status)
        }
    }

    static func refreshToken() throws -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let group = Bundle.main.object(forInfoDictionaryKey: "CredentialKeychainAccessGroup") as? String {
            query[kSecAttrAccessGroup as String] = group
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            throw AuthSessionVaultError.keychain(status)
        }
        return value
    }

    enum AuthSessionVaultError: Error {
        case keychain(OSStatus)
    }
}
