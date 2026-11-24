import XCTest
import Vapor
import Fluent
import XCTVapor
@testable import App

private struct EncryptedVaultItemPayload: Content {
    let clientItemID: UUID
    let ciphertext: String
    let nonce: String
    let authenticationTag: String
    let formatVersion: Int
    let expectedVersion: Int? = nil
}

private struct EncryptedVaultItemResponse: Content {
    let clientItemID: UUID
    let ciphertext: String
    let nonce: String
    let authenticationTag: String
    let formatVersion: Int
    let version: Int
    let deletedAt: Date?
    let isDeleted: Bool
}

private struct EncryptedVaultItemPage: Content {
    let items: [EncryptedVaultItemResponse]
    let nextOffset: Int?
    let snapshot: String
}

final class EncryptedVaultAPITests: XCTestCase {
    func testVaultRejectsRequestsWithoutBearerSession() async throws {
        guard Environment.get("DATABASE_URL") != nil else {
            throw XCTSkip("Set DATABASE_URL to a disposable PostgreSQL test database.")
        }

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        try await configure(app)
        try await app.autoMigrate()

        try await app.test(.GET, "v2/vault/items", afterResponse: { response async in
            XCTAssertEqual(response.status, .unauthorized)
        })
    }

    func testAuthenticatedUserCanCreateReadAndDeleteEncryptedItem() async throws {
        guard Environment.get("DATABASE_URL") != nil else {
            throw XCTSkip("Set DATABASE_URL to a disposable PostgreSQL test database.")
        }

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        try await configure(app)
        try await app.autoMigrate()

        let user = User()
        user.emailNormalized = "vault-\(UUID().uuidString.lowercased())@example.test"
        user.emailVerifiedAt = Date()
        user.passwordHash = "unused-by-vault-test"
        try await user.save(on: app.db)
        let userID = try XCTUnwrap(user.id)

        let accessToken = secureToken()
        let session = AuthSession()
        session.userID = userID
        session.familyID = UUID()
        session.accessTokenHash = tokenDigest(accessToken)
        session.accessExpiresAt = Date().addingTimeInterval(900)
        session.refreshTokenHash = tokenDigest(secureToken())
        session.expiresAt = Date().addingTimeInterval(86_400)
        try await session.save(on: app.db)

        let itemID = UUID()
        let payload = EncryptedVaultItemPayload(
            clientItemID: itemID,
            ciphertext: Data("ciphertext-only-test".utf8).base64EncodedString(),
            nonce: Data(repeating: 7, count: 12).base64EncodedString(),
            authenticationTag: Data(repeating: 9, count: 16).base64EncodedString(),
            formatVersion: 1
        )

        try await app.test(.POST, "v1/vault/items", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
            try request.content.encode(payload)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .upgradeRequired)
        })
        try await app.test(.DELETE, "v1/vault/items/\(itemID.uuidString)", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .upgradeRequired)
        })

        try await app.test(.POST, "v2/vault/items", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
            try request.content.encode(payload)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .created)
            do {
                let saved = try response.content.decode(EncryptedVaultItemResponse.self)
                XCTAssertEqual(saved.clientItemID, itemID)
                XCTAssertEqual(saved.ciphertext, payload.ciphertext)
                XCTAssertEqual(saved.nonce, payload.nonce)
                XCTAssertEqual(saved.authenticationTag, payload.authenticationTag)
            } catch {
                XCTFail("Could not decode created vault item response: \(error)")
            }
        })

        try await app.test(.GET, "v2/vault/items/\(itemID)", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            do {
                let fetched = try response.content.decode(EncryptedVaultItemResponse.self)
                XCTAssertEqual(fetched.clientItemID, itemID)
                XCTAssertEqual(fetched.ciphertext, payload.ciphertext)
            } catch {
                XCTFail("Could not decode fetched vault item response: \(error)")
            }
        })

        let staleUpdate = EncryptedVaultItemPayload(
            clientItemID: itemID,
            ciphertext: Data("stale-ciphertext".utf8).base64EncodedString(),
            nonce: Data(repeating: 3, count: 12).base64EncodedString(),
            authenticationTag: Data(repeating: 4, count: 16).base64EncodedString(),
            formatVersion: 1,
            expectedVersion: 0
        )
        try await app.test(.POST, "v2/vault/items", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
            try request.content.encode(staleUpdate)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .conflict, "Stale writes must not overwrite a newer vault version.")
        })

        let validUpdate = EncryptedVaultItemPayload(
            clientItemID: itemID,
            ciphertext: Data("updated-ciphertext".utf8).base64EncodedString(),
            nonce: Data(repeating: 5, count: 12).base64EncodedString(),
            authenticationTag: Data(repeating: 6, count: 16).base64EncodedString(),
            formatVersion: 1,
            expectedVersion: 1
        )
        try await app.test(.POST, "v2/vault/items", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
            try request.content.encode(validUpdate)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            do {
                let updated = try response.content.decode(EncryptedVaultItemResponse.self)
                XCTAssertEqual(updated.version, 2)
                XCTAssertEqual(updated.ciphertext, validUpdate.ciphertext)
            } catch {
                XCTFail("Could not decode updated vault item response: \(error)")
            }
        })

        let otherUser = User()
        otherUser.emailNormalized = "other-\(UUID().uuidString.lowercased())@example.test"
        otherUser.emailVerifiedAt = Date()
        otherUser.passwordHash = "unused-by-vault-test"
        try await otherUser.save(on: app.db)
        let otherToken = secureToken()
        let otherSession = AuthSession()
        otherSession.userID = try XCTUnwrap(otherUser.id)
        otherSession.familyID = UUID()
        otherSession.accessTokenHash = tokenDigest(otherToken)
        otherSession.accessExpiresAt = Date().addingTimeInterval(900)
        otherSession.refreshTokenHash = tokenDigest(secureToken())
        otherSession.expiresAt = Date().addingTimeInterval(86_400)
        try await otherSession.save(on: app.db)

        try await app.test(.GET, "v2/vault/items/\(itemID)", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: otherToken)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .notFound, "A different user must not be able to read this vault item.")
        })

        try await app.test(.DELETE, "v2/vault/items/\(itemID)", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
            request.headers.replaceOrAdd(name: "If-Match", value: "2")
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .noContent)
        })

        try await app.test(.POST, "v2/vault/items", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
            try request.content.encode(payload)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .conflict, "A stale client must not resurrect a tombstoned item ID.")
        })

        try await app.test(.GET, "v1/vault/items", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: accessToken)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            do {
                let items = try response.content.decode([EncryptedVaultItemResponse].self)
                XCTAssertEqual(items.count, 1)
                XCTAssertTrue(items[0].isDeleted, "Deletion must leave a tombstone so another device cannot resurrect the item.")
                XCTAssertEqual(items[0].version, 3)
            } catch {
                XCTFail("Could not decode vault item list response: \(error)")
            }
        })
    }
    func testVaultListUsesStableSnapshotPagination() async throws {
        guard Environment.get("DATABASE_URL") != nil else {
            throw XCTSkip("Set DATABASE_URL to a disposable PostgreSQL test database.")
        }

        let app = try await Application.make(.testing)
        addTeardownBlock { try await app.asyncShutdown() }
        try await configure(app)
        try await app.autoMigrate()

        let user = User()
        user.emailNormalized = "vault-pages-\(UUID().uuidString.lowercased())@example.test"
        user.emailVerifiedAt = Date()
        user.passwordHash = "unused-by-vault-test"
        try await user.save(on: app.db)

        let token = secureToken()
        let session = AuthSession()
        session.userID = try XCTUnwrap(user.id)
        session.familyID = UUID()
        session.accessTokenHash = tokenDigest(token)
        session.accessExpiresAt = Date().addingTimeInterval(900)
        session.refreshTokenHash = tokenDigest(secureToken())
        session.expiresAt = Date().addingTimeInterval(86_400)
        try await session.save(on: app.db)

        for index in 0..<2 {
            let payload = EncryptedVaultItemPayload(
                clientItemID: UUID(),
                ciphertext: Data("ciphertext-\(index)".utf8).base64EncodedString(),
                nonce: Data(repeating: UInt8(index + 1), count: 12).base64EncodedString(),
                authenticationTag: Data(repeating: UInt8(index + 2), count: 16).base64EncodedString(),
                formatVersion: 1
            )
            try await app.test(.POST, "v2/vault/items", beforeRequest: { request in
                request.headers.bearerAuthorization = BearerAuthorization(token: token)
                try request.content.encode(payload)
            }, afterResponse: { response async in
                XCTAssertEqual(response.status, .created)
            })
        }

        var firstPage: EncryptedVaultItemPage?
        try await app.test(.GET, "v2/vault/items?limit=1&offset=0", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: token)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            do {
                firstPage = try response.content.decode(EncryptedVaultItemPage.self)
            } catch {
                XCTFail("Could not decode first vault page: \(error)")
            }
        })
        let first = try XCTUnwrap(firstPage)
        XCTAssertEqual(first.items.count, 1)
        XCTAssertEqual(first.nextOffset, 1)

        var secondPage: EncryptedVaultItemPage?
        try await app.test(.GET, "v2/vault/items?limit=1&offset=1&snapshot=\(first.snapshot)", beforeRequest: { request in
            request.headers.bearerAuthorization = BearerAuthorization(token: token)
        }, afterResponse: { response async in
            XCTAssertEqual(response.status, .ok)
            do {
                secondPage = try response.content.decode(EncryptedVaultItemPage.self)
            } catch {
                XCTFail("Could not decode second vault page: \(error)")
            }
        })
        let second = try XCTUnwrap(secondPage)
        XCTAssertEqual(second.items.count, 1)
        XCTAssertNil(second.nextOffset)
        XCTAssertEqual(second.snapshot, first.snapshot)
        XCTAssertNotEqual(first.items[0].clientItemID, second.items[0].clientItemID)
    }

}
