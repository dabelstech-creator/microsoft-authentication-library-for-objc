import Foundation

struct EntraDeviceCodePrompt: Sendable {
    let userCode: String
    let verificationURL: URL
    let message: String
    let expiresAt: Date
}

private struct DeviceCodeStartResponse: Decodable {
    let deviceCode: String
    let userCode: String
    let verificationURI: String
    let expiresIn: Int
    let interval: Int?
    let message: String?

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationURI = "verification_uri"
        case expiresIn = "expires_in"
        case interval
        case message
    }
}

private struct DeviceCodeTokenResponse: Decodable {
    let accessToken: String?
    let tokenType: String?
    let scope: String?
    let expiresIn: Int?
    let error: String?
    let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case scope
        case expiresIn = "expires_in"
        case error
        case errorDescription = "error_description"
    }
}

enum EntraDeviceCodeError: LocalizedError {
    case missingConfiguration
    case invalidEndpoint
    case invalidResponse
    case serverRejected(String)
    case declined
    case expired
    case unexpected(String)

    var errorDescription: String? {
        switch self {
        case .missingConfiguration:
            return "Configure ENTRA_TENANT_SUBDOMAIN, ENTRA_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_API_SCOPE in the iOS app."
        case .invalidEndpoint:
            return "The Microsoft External ID endpoint was not valid."
        case .invalidResponse:
            return "Microsoft returned an invalid device authorization response."
        case .serverRejected(let message):
            return message
        case .declined:
            return "The sign-in request was declined."
        case .expired:
            return "The device code expired. Start a new sign-in request."
        case .unexpected(let code):
            return "Microsoft device authorization failed: \(code)."
        }
    }
}

/// OAuth 2.0 device authorization grant for External ID customer tenants.
/// The device code and access token remain in memory and are never logged or persisted.
@MainActor
final class EntraDeviceCodeAuthService {
    private let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    func signIn(
        onDeviceCode: @MainActor (EntraDeviceCodePrompt) -> Void
    ) async throws -> String {
        let configuration = try Self.loadConfiguration()
        let start = try await requestDeviceCode(configuration: configuration)
        guard
            let verificationURL = URL(string: start.verificationURI),
            verificationURL.scheme == "https",
            Self.isMicrosoftVerificationHost(verificationURL.host)
        else {
            throw EntraDeviceCodeError.invalidEndpoint
        }

        let expiresAt = Date().addingTimeInterval(TimeInterval(start.expiresIn))
        let prompt = EntraDeviceCodePrompt(
            userCode: start.userCode,
            verificationURL: verificationURL,
            message: start.message ?? "Open the verification page and enter the code shown below.",
            expiresAt: expiresAt
        )
        onDeviceCode(prompt)

        var interval = max(start.interval ?? 5, 5)
        while Date() < expiresAt {
            try Task.checkCancellation()
            try await Task.sleep(for: .seconds(interval))
            try Task.checkCancellation()

            let response = try await pollForToken(
                configuration: configuration,
                deviceCode: start.deviceCode
            )

            if let accessToken = response.accessToken, !accessToken.isEmpty {
                guard response.tokenType?.lowercased() == "bearer" else {
                    throw EntraDeviceCodeError.invalidResponse
                }
                return accessToken
            }

            switch response.error {
            case "authorization_pending":
                continue
            case "slow_down":
                interval += 5
            case "authorization_declined":
                throw EntraDeviceCodeError.declined
            case "expired_token":
                throw EntraDeviceCodeError.expired
            case "bad_verification_code":
                throw EntraDeviceCodeError.invalidResponse
            case let error?:
                throw EntraDeviceCodeError.unexpected(error)
            case nil:
                throw EntraDeviceCodeError.invalidResponse
            }
        }

        throw EntraDeviceCodeError.expired
    }

    private struct Configuration {
        let clientID: String
        let apiScope: String
        let deviceCodeURL: URL
        let tokenURL: URL
    }

    private static func loadConfiguration(bundle: Bundle = .main) throws -> Configuration {
        guard
            let tenant = bundle.object(forInfoDictionaryKey: "ENTRA_TENANT_SUBDOMAIN") as? String,
            tenant.range(of: #"^[a-zA-Z0-9-]+$"#, options: .regularExpression) != nil,
            let tenantID = bundle.object(forInfoDictionaryKey: "ENTRA_TENANT_ID") as? String,
            UUID(uuidString: tenantID) != nil,
            let clientID = bundle.object(forInfoDictionaryKey: "ENTRA_CLIENT_ID") as? String,
            UUID(uuidString: clientID) != nil,
            let apiScope = bundle.object(forInfoDictionaryKey: "ENTRA_API_SCOPE") as? String,
            apiScope.hasPrefix("api://"),
            apiScope.contains("/")
        else {
            throw EntraDeviceCodeError.missingConfiguration
        }

        let authority = "https://\(tenant.lowercased()).ciamlogin.com/\(tenantID)"
        guard
            let deviceCodeURL = URL(string: authority + "/oauth2/v2.0/devicecode"),
            let tokenURL = URL(string: authority + "/oauth2/v2.0/token")
        else {
            throw EntraDeviceCodeError.invalidEndpoint
        }

        return Configuration(
            clientID: clientID,
            apiScope: apiScope,
            deviceCodeURL: deviceCodeURL,
            tokenURL: tokenURL
        )
    }

    private func requestDeviceCode(configuration: Configuration) async throws -> DeviceCodeStartResponse {
        var request = URLRequest(url: configuration.deviceCodeURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = Self.formBody([
            ("client_id", configuration.clientID),
            ("scope", "openid profile email \(configuration.apiScope)")
        ])

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw EntraDeviceCodeError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let failure = try? JSONDecoder().decode(DeviceCodeTokenResponse.self, from: data)
            throw EntraDeviceCodeError.serverRejected(
                failure?.errorDescription ?? "Microsoft rejected the device authorization request (HTTP \(http.statusCode))."
            )
        }
        return try JSONDecoder().decode(DeviceCodeStartResponse.self, from: data)
    }

    private func pollForToken(
        configuration: Configuration,
        deviceCode: String
    ) async throws -> DeviceCodeTokenResponse {
        var request = URLRequest(url: configuration.tokenURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = Self.formBody([
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", configuration.clientID),
            ("device_code", deviceCode)
        ])

        let (data, response) = try await session.data(for: request)
        guard response is HTTPURLResponse else {
            throw EntraDeviceCodeError.invalidResponse
        }
        return try JSONDecoder().decode(DeviceCodeTokenResponse.self, from: data)
    }

    private static func formBody(_ fields: [(String, String)]) -> Data {
        var components = URLComponents()
        components.queryItems = fields.map { URLQueryItem(name: $0.0, value: $0.1) }
        return Data((components.percentEncodedQuery ?? "").utf8)
    }

    private static func isMicrosoftVerificationHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased() else { return false }
        return host == "microsoft.com"
            || host.hasSuffix(".microsoft.com")
            || host.hasSuffix(".ciamlogin.com")
    }
}
