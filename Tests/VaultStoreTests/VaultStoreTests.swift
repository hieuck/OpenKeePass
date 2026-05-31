import Foundation
import XCTest
@testable import KeePassCore
@testable import VaultStore

@MainActor
final class VaultStoreTests: XCTestCase {
    func testInitialStateIsLocked() {
        let store = VaultStore(engine: FakeKDBXEngine())

        XCTAssertEqual(store.state, .locked)
    }

    func testUnlockLoadsVault() async throws {
        let vault = KeePassVault.fixture(name: "Personal")
        let store = VaultStore(engine: FakeKDBXEngine(openResult: .success(vault)))

        try await store.unlock(data: Data([1, 2, 3]), credentials: .init(password: "pw"))

        XCTAssertEqual(store.state, .unlocked(vault: vault, isDirty: false))
    }

    func testEditingEntryMarksVaultDirty() async throws {
        let entry = KeePassEntry.fixture(title: "GitHub", username: "old")
        let vault = KeePassVault.fixture(entries: [entry])
        let store = VaultStore(engine: FakeKDBXEngine(openResult: .success(vault)))
        try await store.unlock(data: Data([1]), credentials: .init(password: "pw"))

        try store.updateEntry(id: entry.id) { updated in
            updated.username = "new"
        }

        let unlocked = try XCTUnwrap(store.unlockedVault)
        XCTAssertEqual(unlocked.root.entries.first?.username, "new")
        XCTAssertEqual(store.state, .unlocked(vault: unlocked, isDirty: true))
    }

    func testSaveClearsDirtyState() async throws {
        let entry = KeePassEntry.fixture(title: "GitHub")
        let vault = KeePassVault.fixture(entries: [entry])
        let engine = FakeKDBXEngine(openResult: .success(vault), saveResult: .success(Data([9])))
        let store = VaultStore(engine: engine)
        try await store.unlock(data: Data([1]), credentials: .init(password: "pw"))
        try store.updateEntry(id: entry.id) { $0.title = "GitHub Updated" }

        let saved = try await store.save(credentials: .init(password: "pw"))

        XCTAssertEqual(saved, Data([9]))
        XCTAssertEqual(store.isDirty, false)
    }

    func testFailedSaveKeepsDirtyState() async throws {
        let entry = KeePassEntry.fixture(title: "GitHub")
        let vault = KeePassVault.fixture(entries: [entry])
        let engine = FakeKDBXEngine(openResult: .success(vault), saveResult: .failure(KDBXError.corruptDatabase))
        let store = VaultStore(engine: engine)
        try await store.unlock(data: Data([1]), credentials: .init(password: "pw"))
        try store.updateEntry(id: entry.id) { $0.title = "GitHub Updated" }

        do {
            _ = try await store.save(credentials: .init(password: "pw"))
            XCTFail("Expected save to throw")
        } catch {
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
            XCTAssertEqual(store.isDirty, true)
        }
    }
}

private struct FakeKDBXEngine: KDBXEngine {
    var openResult: Result<KeePassVault, Error> = .success(.fixture())
    var createResult: Result<KeePassVault, Error> = .success(.fixture())
    var saveResult: Result<Data, Error> = .success(Data())

    func open(data: Data, credentials: KDBXCredentials) async throws -> KeePassVault {
        try openResult.get()
    }

    func create(name: String, credentials: KDBXCredentials) async throws -> KeePassVault {
        try createResult.get()
    }

    func save(vault: KeePassVault, credentials: KDBXCredentials) async throws -> Data {
        try saveResult.get()
    }
}

private extension KeePassVault {
    static func fixture(name: String = "Test", entries: [KeePassEntry] = []) -> KeePassVault {
        KeePassVault(
            id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
            name: name,
            root: KeePassGroup(
                id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
                title: "Root",
                groups: [],
                entries: entries
            )
        )
    }
}

private extension KeePassEntry {
    static func fixture(title: String, username: String = "") -> KeePassEntry {
        KeePassEntry(
            id: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
            title: title,
            username: username,
            password: "",
            url: "",
            notes: "",
            customFields: []
        )
    }
}
