import Fluent
import SQLKit
import Vapor

/// Adds optimistic concurrency metadata without rewriting the original table-creation migration.
struct AddEncryptedVaultItemVersion: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else {
            throw Abort(.internalServerError, reason: "Vault version migration requires PostgreSQL.")
        }
        try await sql.raw("""
            ALTER TABLE encrypted_vault_items
            ADD COLUMN version INTEGER NOT NULL DEFAULT 1
            """).run()
    }

    func revert(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else {
            throw Abort(.internalServerError, reason: "Vault version rollback requires PostgreSQL.")
        }
        try await sql.raw("ALTER TABLE encrypted_vault_items DROP COLUMN version").run()
    }
}
