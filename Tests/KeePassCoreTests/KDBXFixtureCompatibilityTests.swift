import Foundation
import XCTest
@testable import KeePassCore

final class KDBXFixtureCompatibilityTests: XCTestCase {
    func testOpensKDBX3PasswordOnlyFixture() async throws {
        let vault = try await openFixture(
            name: "password-only",
            credentials: KDBXCredentials(password: "openkeepass")
        )

        let entry = try XCTUnwrap(vault.root.entries.first)
        XCTAssertEqual(entry.title, "GitHub")
        XCTAssertEqual(entry.username, "fixture-user")
        XCTAssertEqual(entry.password, "fixture-secret")
        XCTAssertEqual(entry.url, "https://example.com/login")
        XCTAssertEqual(entry.notes, "fixture notes")
    }

    func testOpensKDBX3PasswordAndKeyFileFixture() async throws {
        let keyFileData = try Self.fixtureData(name: "password-keyfile", ext: "key")
        let vault = try await openFixture(
            name: "password-keyfile",
            credentials: KDBXCredentials(password: "openkeepass", keyFileData: keyFileData)
        )

        let entry = try XCTUnwrap(vault.root.entries.first)
        XCTAssertEqual(entry.title, "KeyFile")
        XCTAssertEqual(entry.username, "key-user")
        XCTAssertEqual(entry.password, "keyfile-secret")
        XCTAssertEqual(entry.url, "https://key.example.com")
        XCTAssertEqual(entry.notes, "key fixture notes")
    }

    func testOpensKeePassXCGeneratedPasswordFixture() async throws {
        #if os(Windows)
        throw XCTSkip("KeePassXC fixture uses high AES-KDF rounds and needs the Apple CommonCrypto fast path.")
        #else
        let vault = try await openFixture(
            name: "keepassxc-password",
            credentials: KDBXCredentials(password: "openkeepass")
        )

        let entry = try XCTUnwrap(vault.root.entries.first)
        XCTAssertEqual(entry.title, "GitHub")
        XCTAssertEqual(entry.username, "keepassxc-user")
        XCTAssertEqual(entry.password, "keepassxc-secret")
        XCTAssertEqual(entry.url, "https://keepassxc.example.com/login")
        XCTAssertEqual(entry.notes, "created by KeePassXC CLI")
        #endif
    }

    func testEditsKDBX3FixtureAndReopensSavedData() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "openkeepass")
        var vault = try await openFixture(name: "password-only", credentials: credentials)
        var entry = try XCTUnwrap(vault.root.entries.first)
        entry.username = "edited-user"
        vault.root.entries[0] = entry

        let saved = try await engine.save(vault: vault, credentials: credentials)
        let reopened = try await engine.open(data: saved, credentials: credentials)

        XCTAssertEqual(reopened.root.entries.first?.title, "GitHub")
        XCTAssertEqual(reopened.root.entries.first?.username, "edited-user")
        XCTAssertEqual(reopened.root.entries.first?.password, "fixture-secret")
    }

    private func openFixture(name: String, credentials: KDBXCredentials) async throws -> KeePassVault {
        let data = try Self.fixtureData(name: name, ext: "kdbx")
        return try await KDBX4Engine().open(data: data, credentials: credentials)
    }

    private static func fixtureData(name: String, ext fileExtension: String) throws -> Data {
        let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures")
            .appendingPathComponent("KDBX")
            .appendingPathComponent("\(name).\(fileExtension)")
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "Missing fixture at \(url.path)")
        return try Data(contentsOf: url)
    }
}
