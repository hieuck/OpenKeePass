import Foundation
import XCTest
@testable import SecurityKit

final class AutoFillCredentialCacheTests: XCTestCase {
    func testWritesAndReadsCredentialRecords() throws {
        let directory = try temporaryDirectory()
        let cache = AutoFillCredentialCache(directory: directory)
        let records = [
            AutoFillCredentialRecord(
                id: "1",
                title: "Example",
                username: "user@example.com",
                password: "secret",
                url: "https://example.com/login"
            )
        ]

        try cache.write(records)

        XCTAssertEqual(try cache.read(), records)
        XCTAssertEqual(records[0].serviceHost, "example.com")
    }

    func testFiltersCredentialsByDomainServiceIdentifier() throws {
        let directory = try temporaryDirectory()
        let cache = AutoFillCredentialCache(directory: directory)
        try cache.write([
            AutoFillCredentialRecord(
                id: "1",
                title: "Example",
                username: "user@example.com",
                password: "secret",
                url: "https://login.example.com/path"
            ),
            AutoFillCredentialRecord(
                id: "2",
                title: "Other",
                username: "user@other.com",
                password: "secret",
                url: "https://other.com"
            )
        ])

        let matches = try cache.credentials(matchingServiceIdentifiers: ["example.com"])

        XCTAssertEqual(matches.map(\.id), ["1"])
    }

    func testFindsCredentialByIdentifier() throws {
        let directory = try temporaryDirectory()
        let cache = AutoFillCredentialCache(directory: directory)
        try cache.write([
            AutoFillCredentialRecord(
                id: "1",
                title: "Example",
                username: "user@example.com",
                password: "secret",
                url: "https://example.com/login"
            )
        ])

        XCTAssertEqual(try cache.credential(id: "1")?.username, "user@example.com")
        XCTAssertNil(try cache.credential(id: "missing"))
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
