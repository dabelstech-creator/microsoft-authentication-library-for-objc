import XCTest
@testable import AuthPlatform

final class VaultCryptographyTests: XCTestCase {
    override func setUpWithError() throws {
        try VaultCryptography.deleteVaultKey()
    }

    override func tearDownWithError() throws {
        try VaultCryptography.deleteVaultKey()
    }

    func testEncryptedCredentialRoundTripsAndRecoveryRestoresSameKey() throws {
        let kit = try VaultCryptography.createVaultKey()
        let credential = StoredPasswordCredential(
            service: "login.example.com",
            username: "alice@example.com",
            password: "correct horse battery staple"
        )

        let envelope = try VaultCryptography.seal(credential, clientItemID: UUID())
        XCTAssertNotEqual(envelope.ciphertext, Data(try JSONEncoder().encode(credential)).base64EncodedString())
        XCTAssertEqual(try VaultCryptography.open(envelope, as: StoredPasswordCredential.self), credential)

        try VaultCryptography.deleteVaultKey()
        try VaultCryptography.restoreVaultKey(recoveryCode: kit.recoveryCode, package: kit.recoveryPackage)

        XCTAssertEqual(try VaultCryptography.open(envelope, as: StoredPasswordCredential.self), credential)
    }

    func testRecoveryKitCanBeExportedAgainWithoutRotatingVaultKey() throws {
        _ = try VaultCryptography.createVaultKey()
        let credential = StoredPasswordCredential(
            service: "example.com",
            username: "alice",
            password: "secret"
        )
        let envelope = try VaultCryptography.seal(credential, clientItemID: UUID())

        let kit = try VaultCryptography.createRecoveryKit()
        try VaultCryptography.deleteVaultKey()
        try VaultCryptography.restoreVaultKey(recoveryCode: kit.recoveryCode, package: kit.recoveryPackage)

        XCTAssertEqual(try VaultCryptography.open(envelope, as: StoredPasswordCredential.self), credential)
    }

    func testWrongRecoveryCodeDoesNotInstallAKey() throws {
        let kit = try VaultCryptography.createVaultKey()
        try VaultCryptography.deleteVaultKey()

        XCTAssertThrowsError(
            try VaultCryptography.restoreVaultKey(
                recoveryCode: "incorrect-recovery-code",
                package: kit.recoveryPackage
            )
        )
        XCTAssertFalse(VaultCryptography.hasVaultKey())
    }

    func testTamperedAuthenticationTagIsRejected() throws {
        _ = try VaultCryptography.createVaultKey()
        let credential = StoredPasswordCredential(
            service: "example.com",
            username: "alice",
            password: "secret"
        )
        let envelope = try VaultCryptography.seal(credential, clientItemID: UUID())
        let tampered = EncryptedVaultItemEnvelope(
            clientItemID: envelope.clientItemID,
            ciphertext: envelope.ciphertext,
            nonce: envelope.nonce,
            authenticationTag: Data(repeating: 0, count: 16).base64EncodedString(),
            formatVersion: envelope.formatVersion
        )

        XCTAssertThrowsError(try VaultCryptography.open(tampered, as: StoredPasswordCredential.self))
    }
}
