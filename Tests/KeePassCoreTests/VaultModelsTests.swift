import XCTest
@testable import KeePassCore

final class VaultModelsTests: XCTestCase {
    func testEntryKeepsCommonKeePassFields() {
        let entryID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!

        let entry = KeePassEntry(
            id: entryID,
            title: "GitHub",
            username: "octo",
            password: "secret",
            url: "https://github.com",
            notes: "Recovery codes stored elsewhere",
            customFields: [.init(name: "email", value: "octo@example.com", isProtected: false)]
        )

        XCTAssertEqual(entry.id, entryID)
        XCTAssertEqual(entry.title, "GitHub")
        XCTAssertEqual(entry.username, "octo")
        XCTAssertEqual(entry.password, "secret")
        XCTAssertEqual(entry.url, "https://github.com")
        XCTAssertEqual(entry.notes, "Recovery codes stored elsewhere")
        XCTAssertEqual(entry.customFields.first?.name, "email")
    }

    func testUpdatingEditableFieldsPreservesEntryMetadata() {
        let entry = KeePassEntry(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            title: "Old",
            username: "old-user",
            password: "old-pass",
            url: "https://old.example.com",
            notes: "old notes",
            customFields: [
                KeePassField(name: "otp", value: "otpauth://totp/example?secret=GEZDGNBVGY3TQOJQ", isProtected: true)
            ],
            attachments: [
                KeePassAttachment(name: "recovery.txt", data: Data("recovery".utf8), isProtected: false)
            ],
            history: [
                KeePassEntry(
                    id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
                    title: "History",
                    username: "history-user",
                    password: "history-pass",
                    url: "",
                    notes: "",
                    customFields: []
                )
            ]
        )

        let updated = entry.updatingEditableFields(
            title: "New",
            username: "new-user",
            password: "new-pass",
            url: "https://new.example.com",
            notes: "new notes"
        )

        XCTAssertEqual(updated.id, entry.id)
        XCTAssertEqual(updated.title, "New")
        XCTAssertEqual(updated.username, "new-user")
        XCTAssertEqual(updated.password, "new-pass")
        XCTAssertEqual(updated.url, "https://new.example.com")
        XCTAssertEqual(updated.notes, "new notes")
        XCTAssertEqual(updated.customFields, entry.customFields)
        XCTAssertEqual(updated.attachments, entry.attachments)
        XCTAssertEqual(updated.history, entry.history)
    }

    func testUpdatingEditableFieldsCanReplaceCustomFieldsWhilePreservingAttachmentsAndHistory() {
        let entry = KeePassEntry(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            title: "Old",
            username: "old-user",
            password: "old-pass",
            url: "",
            notes: "",
            customFields: [
                KeePassField(name: "Environment", value: "dev", isProtected: false)
            ],
            attachments: [
                KeePassAttachment(name: "recovery.txt", data: Data("recovery".utf8), isProtected: false)
            ],
            history: [
                KeePassEntry.fixture(title: "History")
            ]
        )
        let replacementFields = [
            KeePassField(name: "Environment", value: "prod", isProtected: false),
            KeePassField(name: "API Token", value: "secret", isProtected: true)
        ]

        let updated = entry.updatingEditableFields(
            title: "New",
            username: "new-user",
            password: "new-pass",
            url: "https://example.com",
            notes: "new notes",
            customFields: replacementFields
        )

        XCTAssertEqual(updated.customFields, replacementFields)
        XCTAssertEqual(updated.attachments, entry.attachments)
        XCTAssertEqual(updated.history, entry.history)
    }

    func testAttachmentDisplayMetadata() {
        XCTAssertEqual(
            KeePassAttachment(name: "recovery.txt", data: Data(repeating: 0, count: 512), isProtected: false).byteCountDescription,
            "512 bytes"
        )
        XCTAssertEqual(
            KeePassAttachment(name: "photo.jpg", data: Data(repeating: 0, count: 1_536), isProtected: false).byteCountDescription,
            "1.5 KB"
        )
        XCTAssertEqual(
            KeePassAttachment(name: "../secrets/recovery.txt", data: Data(), isProtected: false).safeExportFileName,
            "recovery.txt"
        )
        XCTAssertEqual(
            KeePassAttachment(name: "", data: Data(), isProtected: false).safeExportFileName,
            "attachment"
        )
    }

    func testDisplayableCustomFieldsExcludeTOTPSecrets() {
        let entry = KeePassEntry.fixture(title: "GitHub", customFields: [
            KeePassField(name: "email", value: "octo@example.com", isProtected: false),
            KeePassField(name: "otp", value: "otpauth://totp/GitHub:octo?secret=GEZDGNBVGY3TQOJQ", isProtected: true),
            KeePassField(name: "TimeOtp-Secret", value: "GEZDGNBVGY3TQOJQ", isProtected: true),
            KeePassField(name: "Recovery Hint", value: "safe", isProtected: false)
        ])

        XCTAssertEqual(entry.displayableCustomFields.map(\.name), ["email", "Recovery Hint"])
    }

    func testProtectedCustomFieldDisplayValueIsMaskedButCopyValueIsRaw() {
        let field = KeePassField(name: "API Token", value: "token-secret", isProtected: true)

        XCTAssertEqual(field.displayValue, "••••••••")
        XCTAssertEqual(field.copyValue, "token-secret")
    }

    func testSearchMatchesNestedEntriesByCommonFields() {
        let matchingByURL = KeePassEntry.fixture(title: "Source", url: "https://github.com/openkeepass")
        let matchingByCustomField = KeePassEntry.fixture(title: "Server", customFields: [.init(name: "host", value: "vault.internal", isProtected: false)])
        let unrelated = KeePassEntry.fixture(title: "Bank")
        let vault = KeePassVault(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            name: "Personal",
            root: KeePassGroup(
                id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
                title: "Root",
                groups: [
                    KeePassGroup(
                        id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
                        title: "Development",
                        groups: [],
                        entries: [matchingByCustomField]
                    )
                ],
                entries: [matchingByURL, unrelated]
            )
        )

        XCTAssertEqual(vault.searchEntries(matching: "github").map(\.id), [matchingByURL.id])
        XCTAssertEqual(vault.searchEntries(matching: "vault.internal").map(\.id), [matchingByCustomField.id])
        XCTAssertEqual(vault.searchEntries(matching: "missing"), [])
    }

    func testEmptySearchReturnsAllEntriesInTraversalOrder() {
        let first = KeePassEntry.fixture(title: "First")
        let second = KeePassEntry.fixture(title: "Second")
        let vault = KeePassVault(
            id: UUID(),
            name: "Personal",
            root: KeePassGroup(
                id: UUID(),
                title: "Root",
                groups: [.init(id: UUID(), title: "Nested", groups: [], entries: [second])],
                entries: [first]
            )
        )

        XCTAssertEqual(vault.searchEntries(matching: "").map(\.title), ["First", "Second"])
    }
}

private extension KeePassEntry {
    static func fixture(
        title: String,
        username: String = "",
        password: String = "",
        url: String = "",
        notes: String = "",
        customFields: [KeePassField] = []
    ) -> KeePassEntry {
        KeePassEntry(
            id: UUID(),
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes,
            customFields: customFields
        )
    }
}
