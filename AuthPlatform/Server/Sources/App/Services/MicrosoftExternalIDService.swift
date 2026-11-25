import Foundation
import JWTKit
import Vapor

struct VerifiedMicrosoftExternalIDIdentity {
    let issuer: String
    let subject: String
    let email: String
    let displayName: String?
}

private struct MicrosoftExternalIDAccessToken: JWTPayload {
    let issuer: IssuerClaim
    let subject: SubjectClaim
    let audience: AudienceClaim
    let expiration: ExpirationClaim
    let issuedAt: IssuedAtClaim
    let notBefore: NotBeforeClaim?
    let tenantID: String
    let objectID: String?
    let scopes: String?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case issuedAt = "iat"
        case notBefore = "nbf"
        case tenantID = "tid"
        case objectID = "oid"
        case scopes = "scp"
    }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
        try notBefore?.verifyNotBefore(currentDate: Date().addingTimeInterval(-60))
        guard issuedAt.value <= Date().addingTimeInterval(60),
              !subject.value.isEmpty,
              UUID(uuidString: tenantID) != nil
        else {
            throw JWTError.claimVerificationFailure(
                failedClaim: subject,
                reason: "Microsoft External ID access token is missing a valid subject, tenant, or issued-at time."
            )
        }
    }
}

private struct MicrosoftExternalIDIdentityToken: JWTPayload {
    let issuer: IssuerClaim
    let subject: SubjectClaim
    let audience: AudienceClaim
    let expiration: ExpirationClaim
    let issuedAt: IssuedAtClaim
    let notBefore: NotBeforeClaim?
    let tenantID: String
    let objectID: String?
    let email: String?
    let emailVerified: Bool?
    let name: String?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case issuedAt = "iat"
        case notBefore = "nbf"
        case tenantID = "tid"
        case objectID = "oid"
        case email
        case emailVerified = "email_verified"
        case name
    }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
        try notBefore?.verifyNotBefore(currentDate: Date().addingTimeInterval(-60))
        guard issuedAt.value <= Date().addingTimeInterval(60),
              !subject.value.isEmpty,
              UUID(uuidString: tenantID) != nil
        else {
            throw JWTError.claimVerificationFailure(
                failedClaim: subject,
                reason: "Microsoft External ID ID token is missing a valid subject, tenant, or issued-at time."
            )
        }
    }
}

/// Validates both tokens issued by one External ID device-code authorization:
/// API access token: API audience + delegated scope.
/// ID token: iOS client audience + verified email.
/// The stable oid claim must match between them before a local session is issued.
func verifyMicrosoftExternalIDTokens(
    accessToken: String,
    idToken: String,
    on request: Request
) async throws -> VerifiedMicrosoftExternalIDIdentity {
    guard accessToken.count <= 32_768,
          idToken.count <= 32_768,
          let tenantSubdomain = Environment.get("MICROSOFT_TENANT_SUBDOMAIN"),
          tenantSubdomain.range(of: #"^[A-Za-z0-9-]+$"#, options: .regularExpression) != nil,
          let tenantID = Environment.get("MICROSOFT_TENANT_ID"),
          UUID(uuidString: tenantID) != nil,
          let clientID = Environment.get("MICROSOFT_CLIENT_ID"),
          UUID(uuidString: clientID) != nil,
          let expectedAudience = Environment.get("MICROSOFT_API_AUDIENCE"),
          !expectedAudience.isEmpty
    else {
        throw Abort(.serviceUnavailable, reason: "Microsoft External ID API validation is not configured.")
    }

    let requiredScope = Environment.get("MICROSOFT_API_SCOPE_NAME") ?? "access_as_user"
    guard requiredScope.range(of: #"^[A-Za-z0-9._-]+$"#, options: .regularExpression) != nil else {
        throw Abort(.internalServerError, reason: "MICROSOFT_API_SCOPE_NAME is invalid.")
    }

    let normalizedTenantID = tenantID.lowercased()
    let authenticationHost = "\(tenantSubdomain.lowercased()).ciamlogin.com"
    let issuerHost = "\(normalizedTenantID).ciamlogin.com"
    let expectedIssuer = "https://\(issuerHost)/\(normalizedTenantID)/v2.0"
    let discoveryURL = "https://\(authenticationHost)/\(normalizedTenantID)/v2.0/.well-known/openid-configuration"
    let discoveryResponse = try await request.client.get(URI(string: discoveryURL))
    guard discoveryResponse.status == .ok else {
        request.logger.warning("Microsoft External ID discovery returned HTTP \(discoveryResponse.status.code).")
        throw Abort(.badGateway, reason: "Microsoft External ID discovery is temporarily unavailable.")
    }

    let discovery = try discoveryResponse.content.decode(OIDCDiscoveryDocument.self)
    guard discovery.issuer == expectedIssuer,
          let jwksURL = URL(string: discovery.jwksURI),
          jwksURL.scheme == "https",
          jwksURL.host == issuerHost
    else {
        throw Abort(.badGateway, reason: "Microsoft External ID discovery metadata did not match the configured tenant.")
    }

    let jwksResponse = try await request.client.get(URI(string: discovery.jwksURI))
    guard jwksResponse.status == .ok else {
        request.logger.warning("Microsoft External ID JWKS returned HTTP \(jwksResponse.status.code).")
        throw Abort(.badGateway, reason: "Microsoft External ID signing keys are temporarily unavailable.")
    }

    let jwks = try jwksResponse.content.decode(JWKS.self)
    let keys = try await JWTKeyCollection().add(jwks: jwks)
    let apiClaims = try await keys.verify(accessToken, as: MicrosoftExternalIDAccessToken.self)
    let identityClaims = try await keys.verify(idToken, as: MicrosoftExternalIDIdentityToken.self)

    guard apiClaims.issuer.value == expectedIssuer,
          identityClaims.issuer.value == expectedIssuer,
          apiClaims.tenantID.lowercased() == tenantID.lowercased(),
          identityClaims.tenantID.lowercased() == tenantID.lowercased(),
          apiClaims.audience.value.contains(expectedAudience),
          identityClaims.audience.value.contains(clientID),
          apiClaims.scopes?.split(whereSeparator: \.isWhitespace).contains(Substring(requiredScope)) == true,
          let apiObjectID = apiClaims.objectID,
          let identityObjectID = identityClaims.objectID,
          !apiObjectID.isEmpty,
          apiObjectID == identityObjectID,
          identityClaims.emailVerified == true,
          let rawEmail = identityClaims.email,
          let email = normalizedEmail(rawEmail)
    else {
        throw Abort(.unauthorized, reason: "Microsoft External ID tokens failed issuer, tenant, audience, scope, subject-binding, or verified-email validation.")
    }

    return VerifiedMicrosoftExternalIDIdentity(
        issuer: identityClaims.issuer.value,
        subject: identityClaims.subject.value,
        email: email,
        displayName: identityClaims.name
    )
}
