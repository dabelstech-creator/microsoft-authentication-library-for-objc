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
    let scopes: String?
    let email: String?
    let preferredUsername: String?
    let name: String?
    let emailVerified: Bool?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case issuedAt = "iat"
        case notBefore = "nbf"
        case tenantID = "tid"
        case scopes = "scp"
        case email
        case preferredUsername = "preferred_username"
        case name
        case emailVerified = "email_verified"
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
                reason: "Microsoft External ID token is missing a valid subject, tenant, or issued-at time."
            )
        }
    }
}

/// Validates a delegated External ID access token for the AuthPlatform API.
/// No client secret is used: the iOS application is a public client.
func verifyMicrosoftExternalIDAccessToken(
    _ token: String,
    on request: Request
) async throws -> VerifiedMicrosoftExternalIDIdentity {
    guard token.count <= 32_768,
          let tenantSubdomain = Environment.get("MICROSOFT_TENANT_SUBDOMAIN"),
          tenantSubdomain.range(of: #"^[A-Za-z0-9-]+$"#, options: .regularExpression) != nil,
          let tenantID = Environment.get("MICROSOFT_TENANT_ID"),
          UUID(uuidString: tenantID) != nil,
          let expectedAudience = Environment.get("MICROSOFT_API_AUDIENCE"),
          !expectedAudience.isEmpty
    else {
        throw Abort(.serviceUnavailable, reason: "Microsoft External ID API validation is not configured.")
    }

    let requiredScope = Environment.get("MICROSOFT_API_SCOPE_NAME") ?? "access_as_user"
    guard requiredScope.range(of: #"^[A-Za-z0-9._-]+$"#, options: .regularExpression) != nil else {
        throw Abort(.internalServerError, reason: "MICROSOFT_API_SCOPE_NAME is invalid.")
    }

    let expectedIssuer = "https://\(tenantSubdomain.lowercased()).ciamlogin.com/\(tenantID)/v2.0"
    let discoveryURL = expectedIssuer + "/.well-known/openid-configuration"
    let discoveryResponse = try await request.client.get(URI(string: discoveryURL))
    guard discoveryResponse.status == .ok else {
        request.logger.warning("Microsoft External ID discovery returned HTTP \(discoveryResponse.status.code).")
        throw Abort(.badGateway, reason: "Microsoft External ID discovery is temporarily unavailable.")
    }

    let discovery = try discoveryResponse.content.decode(OIDCDiscoveryDocument.self)
    guard discovery.issuer == expectedIssuer,
          let jwksURL = URL(string: discovery.jwksURI),
          jwksURL.scheme == "https",
          jwksURL.host == "\(tenantSubdomain.lowercased()).ciamlogin.com"
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
    let claims = try await keys.verify(token, as: MicrosoftExternalIDAccessToken.self)

    guard claims.issuer.value == expectedIssuer,
          claims.tenantID.lowercased() == tenantID.lowercased(),
          claims.audience.value.contains(expectedAudience),
          claims.scopes?.split(whereSeparator: \.isWhitespace).contains(Substring(requiredScope)) == true,
          claims.emailVerified == true,
          let rawEmail = claims.email ?? claims.preferredUsername,
          let email = normalizedEmail(rawEmail)
    else {
        throw Abort(.unauthorized, reason: "Microsoft External ID access token claims, API audience, delegated scope, or verified email are invalid.")
    }

    return VerifiedMicrosoftExternalIDIdentity(
        issuer: claims.issuer.value,
        subject: claims.subject.value,
        email: email,
        displayName: claims.name
    )
}
