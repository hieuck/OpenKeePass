import KeePassCore
import SecurityKit
import XCTest
@testable import VaultStore

final class AutoFillCredentialExporterTests: XCTestCase {
    func testExportsEligibleEntriesUsingNormalizedURLs() {
        let eligibleID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let vault = KeePassVault(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            name: "Personal",
            root: KeePassGroup(
                id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
                title: "Root",
                groups: [
                    KeePassGroup(
                        id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
                        title: "Nested",
                        groups: [],
                        entries: [
                            KeePassEntry.fixture(
                                id: eligibleID,
                                title: "Example",
                                username: " user@example.com ",
                                password: " secret ",
                                url: "example.com/login"
                            )
                        ]
                    )
                ],
                entries: [
                    KeePassEntry.fixture(title: "No Username", username: "", password: "secret", url: "https://example.com"),
                    KeePassEntry.fixture(title: "No Password", username: "user", password: "", url: "https://example.com"),
                    KeePassEntry.fixture(title: "Bad URL", username: "user", password: "secret", url: "not a url")
                ]
            )
        )

        let records = AutoFillCredentialExporter.records(from: vault)

        XCTAssertEqual(records, [
            AutoFillCredentialRecord(
                id: eligibleID.uuidString,
                title: "Example",
                username: " user@example.com ",
                password: " secret ",
                url: "https://example.com/login"
            )
        ])
    }
}

private extension KeePassEntry {
    static func fixture(
        id: UUID = UUID(),
        title: String,
        username: String,
        password: String,
        url: String
    ) -> KeePassEntry {
        KeePassEntry(
            id: id,
            title: title,
            username: username,
            password: password,
            url: url,
            notes: "",
            customFields: []
        )
    }
}
