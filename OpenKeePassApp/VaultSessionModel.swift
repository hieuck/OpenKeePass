import Combine
import Foundation
import KeePassCore
import VaultStore

@MainActor
final class VaultSessionModel: ObservableObject {
    @Published var isUnlocking = false
    @Published var vault: KeePassVault?
    @Published var errorMessage: String?

    private let store = VaultStore(engine: KDBX4Engine())

    func unlock(data: Data, password: String) async throws {
        isUnlocking = true
        vault = nil
        errorMessage = nil
        defer {
            isUnlocking = false
        }

        do {
            try await store.unlock(data: data, credentials: KDBXCredentials(password: password))
            vault = store.unlockedVault
        } catch {
            errorMessage = UnlockErrorMessage.describe(error)
            throw error
        }
    }

    func addEntry(_ entry: KeePassEntry, toGroup groupID: UUID) {
        do {
            try store.addEntry(entry, toGroup: groupID)
            vault = store.unlockedVault
        } catch {
            errorMessage = "Could not add this entry."
        }
    }

    func updateEntry(_ entry: KeePassEntry) {
        do {
            try store.updateEntry(id: entry.id) { current in
                current = entry
            }
            vault = store.unlockedVault
        } catch {
            errorMessage = "Could not update this entry."
        }
    }

    func group(id groupID: UUID) -> KeePassGroup? {
        vault?.root.group(id: groupID)
    }

    func entry(id entryID: UUID) -> KeePassEntry? {
        vault?.root.entry(id: entryID)
    }
}

private extension KeePassGroup {
    func group(id groupID: UUID) -> KeePassGroup? {
        if id == groupID {
            return self
        }
        for child in groups {
            if let match = child.group(id: groupID) {
                return match
            }
        }
        return nil
    }

    func entry(id entryID: UUID) -> KeePassEntry? {
        if let entry = entries.first(where: { $0.id == entryID }) {
            return entry
        }
        for child in groups {
            if let match = child.entry(id: entryID) {
                return match
            }
        }
        return nil
    }
}
