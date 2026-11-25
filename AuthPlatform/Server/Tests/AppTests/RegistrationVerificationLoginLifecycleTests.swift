import XCTest
import Vapor
import Fluent
import XCTVapor
@testable import App

private struct LifecycleCredentials: Content {
    let email: String
    let password: String
}

private struct LifecycleTokenPayload: Content {
    let token: String
}

private struct LifecycleRefreshPayload: Content {
    let refreshToken: String
}

private struct LifecycleAuthResponse: Content {
    let userID: UUID
    let accessToken: String
    let refreshToken: String
    let tokenType: String
    let accessTokenExpiresIn: Int
    let emailVerified: Bool
}

private actor LifecycleMockEmailProvider {
    private(set) var deliveries: [(email: String, subject: String, path: String, token: String)] = []

    func deliver(email: String, subject: String, path: String, token: String) {
        deliveries.append((email, subject, path, token))
    }

    func verificationToken(for email: String) -> String? {
        deliveries.last(where: { $0.email == email && $0.path == "/verify-email" })?.token
    }

    var deliveryCount: Int { deliveries.count }
}

final class RegistrationVerificationLoginLifecycleTests: XCTestCase {
    func testRegistrationVerificationLoginAndRefreshUseMockEmailProvider() async throws {
        guard Environment.get("DATABASE_URL") != nil else {
            throw XCTSkip("Set DATABASE_URL to a disposable PostgreSQL test database.")
        }

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }

        let provider = LifecycleMockEmailProvider()
        try await configure(app, emailSender: { email, subject, actionPath, token, _ in
            await provider.deliver(email: email, subject: subject, path: actionPath, token: token)
        })
        try await app.autoMigrate()

        let email = "auth-lifecycle-\(UUID().uuidString.lowercased())@example.test"
        let password = "LifecyclePassword123"
        let credentials = LifecycleCredentials(email: email, password: password)

        // Registration persists only a disposable .example.test identity and
        // routes verification delivery to the in-process mock provider.
        try await app.test(.POST, "v1/auth/register", beforeRequest: { request in
            try request.content.encode(credentials)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
        })

        let firstDeliveryCount = await provider.deliveryCount
        XCTAssertEqual(firstDeliveryCount, 1)
        let capturedVerificationToken = await provider.verificationToken(for: email)
        let verificationToken = try XCTUnwrap(capturedVerificationToken)

        // Unverified accounts must not be able to obtain a session.
        try await app.test(.POST, "v1/auth/login", beforeRequest: { request in
            try request.content.encode(credentials)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .unauthorized)
        })

        try await app.test(.POST, "v1/auth/verify-email", beforeRequest: { request in
            try request.content.encode(LifecycleTokenPayload(token: verificationToken))
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
        })

        let verifiedUser = try await User.query(on: app.db)
            .filter(\.$emailNormalized == email).first()
        XCTAssertNotNil(verifiedUser?.emailVerifiedAt)

        // Verification is one-time; replaying the same link must be rejected.
        try await app.test(.POST, "v1/auth/verify-email", beforeRequest: { request in
            try request.content.encode(LifecycleTokenPayload(token: verificationToken))
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .unprocessableEntity)
        })

        var initialAuth: LifecycleAuthResponse?
        try await app.test(.POST, "v1/auth/login", beforeRequest: { request in
            try request.content.encode(credentials)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            initialAuth = try response.content.decode(LifecycleAuthResponse.self)
        })
        let issued = try XCTUnwrap(initialAuth)
        XCTAssertTrue(issued.emailVerified)
        XCTAssertEqual(issued.tokenType, "Bearer")
        XCTAssertEqual(issued.accessTokenExpiresIn, 900)
        XCTAssertFalse(issued.accessToken.isEmpty)
        XCTAssertFalse(issued.refreshToken.isEmpty)

        var rotatedAuth: LifecycleAuthResponse?
        try await app.test(.POST, "v1/auth/refresh", beforeRequest: { request in
            try request.content.encode(LifecycleRefreshPayload(refreshToken: issued.refreshToken))
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            rotatedAuth = try response.content.decode(LifecycleAuthResponse.self)
        })
        let rotated = try XCTUnwrap(rotatedAuth)
        XCTAssertEqual(rotated.userID, issued.userID)
        XCTAssertTrue(rotated.emailVerified)
        XCTAssertNotEqual(rotated.accessToken, issued.accessToken)
        XCTAssertNotEqual(rotated.refreshToken, issued.refreshToken)

        // The rotated refresh token must itself be usable for the next rotation.
        var secondRotation: LifecycleAuthResponse?
        try await app.test(.POST, "v1/auth/refresh", beforeRequest: { request in
            try request.content.encode(LifecycleRefreshPayload(refreshToken: rotated.refreshToken))
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            secondRotation = try response.content.decode(LifecycleAuthResponse.self)
        })
        XCTAssertNotEqual(try XCTUnwrap(secondRotation).refreshToken, rotated.refreshToken)

        // Only the initial registration sends email; login and refresh never
        // invoke the email provider.
        let finalDeliveryCount = await provider.deliveryCount
        XCTAssertEqual(finalDeliveryCount, 1)
    }
}
