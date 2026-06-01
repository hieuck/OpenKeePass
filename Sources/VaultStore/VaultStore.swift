import Foundation
import KeePassCore

public enum VaultState: Equatable, Sendable {
    case locked
    case unlocked(vault: KeePassVault, isDirty: Bool)
}

public enum VaultStoreError: Error, Equatable, Sendable {
    case noUnlockedVault
    case entryNotFound(UUID)
    case groupNotFound(UUID)
}

@MainActor
public final class VaultStore {
    public private(set) var state: VaultState = .locked
    private let engine: any KDBXEngine

    public init(engine: any KDBXEngine) {
        self.engine = engine
    }

    public var unlockedVault: KeePassVault? {
        guard case .unlocked(let vault, _) = state else {
            return nil
        }
        return vault
    }

    public var isDirty: Bool {
        guard case .unlocked(_, let isDirty) = state else {
            return false
        }
        return isDirty
    }

    public func unlock(data: Data, credentials: KDBXCredentials) async throws {
        let vault = try await engine.open(data: data, credentials: credentials)
        state = .unlocked(vault: vault, isDirty: false)
    }

    public func create(name: String, credentials: KDBXCredentials) async throws {
        let vault = try await engine.create(name: name, credentials: credentials)
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func lock() {
        state = .locked
    }

    public func updateEntry(id: UUID, mutate: (inout KeePassEntry) -> Void) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.updateEntry(id: id, mutate: mutate) else {
            throw VaultStoreError.entryNotFound(id)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func addEntry(_ entry: KeePassEntry, toGroup groupID: UUID) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.addEntry(entry, toGroup: groupID) else {
            throw VaultStoreError.groupNotFound(groupID)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func deleteEntry(id: UUID) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.deleteEntry(id: id) else {
            throw VaultStoreError.entryNotFound(id)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func moveEntry(id entryID: UUID, toGroup groupID: UUID) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.containsGroup(id: groupID) else {
            throw VaultStoreError.groupNotFound(groupID)
        }
        guard let entry = vault.root.removeEntry(id: entryID) else {
            throw VaultStoreError.entryNotFound(entryID)
        }
        guard vault.root.addEntry(entry, toGroup: groupID) else {
            throw VaultStoreError.groupNotFound(groupID)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func addGroup(_ group: KeePassGroup, toParent parentID: UUID) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.addGroup(group, toParent: parentID) else {
            throw VaultStoreError.groupNotFound(parentID)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func updateGroup(id groupID: UUID, mutate: (inout KeePassGroup) -> Void) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.updateGroup(id: groupID, mutate: mutate) else {
            throw VaultStoreError.groupNotFound(groupID)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func deleteGroup(id: UUID) throws {
        guard case .unlocked(var vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        guard vault.root.deleteGroup(id: id) else {
            throw VaultStoreError.groupNotFound(id)
        }
        state = .unlocked(vault: vault, isDirty: true)
    }

    public func save(credentials: KDBXCredentials) async throws -> Data {
        guard case .unlocked(let vault, _) = state else {
            throw VaultStoreError.noUnlockedVault
        }
        let data = try await engine.save(vault: vault, credentials: credentials)
        state = .unlocked(vault: vault, isDirty: false)
        return data
    }
}

private extension KeePassGroup {
    mutating func addEntry(_ entry: KeePassEntry, toGroup groupID: UUID) -> Bool {
        if id == groupID {
            entries.append(entry)
            return true
        }

        for groupIndex in groups.indices {
            if groups[groupIndex].addEntry(entry, toGroup: groupID) {
                return true
            }
        }

        return false
    }

    mutating func updateEntry(id: UUID, mutate: (inout KeePassEntry) -> Void) -> Bool {
        if let entryIndex = entries.firstIndex(where: { $0.id == id }) {
            mutate(&entries[entryIndex])
            return true
        }

        for groupIndex in groups.indices {
            if groups[groupIndex].updateEntry(id: id, mutate: mutate) {
                return true
            }
        }

        return false
    }

    mutating func deleteEntry(id: UUID) -> Bool {
        if let entryIndex = entries.firstIndex(where: { $0.id == id }) {
            entries.remove(at: entryIndex)
            return true
        }

        for groupIndex in groups.indices {
            if groups[groupIndex].deleteEntry(id: id) {
                return true
            }
        }

        return false
    }

    mutating func removeEntry(id: UUID) -> KeePassEntry? {
        if let entryIndex = entries.firstIndex(where: { $0.id == id }) {
            return entries.remove(at: entryIndex)
        }

        for groupIndex in groups.indices {
            if let entry = groups[groupIndex].removeEntry(id: id) {
                return entry
            }
        }

        return nil
    }

    mutating func addGroup(_ group: KeePassGroup, toParent parentID: UUID) -> Bool {
        if id == parentID {
            groups.append(group)
            return true
        }

        for groupIndex in groups.indices {
            if groups[groupIndex].addGroup(group, toParent: parentID) {
                return true
            }
        }

        return false
    }

    func containsGroup(id groupID: UUID) -> Bool {
        if id == groupID {
            return true
        }

        return groups.contains { $0.containsGroup(id: groupID) }
    }

    mutating func updateGroup(id groupID: UUID, mutate: (inout KeePassGroup) -> Void) -> Bool {
        if id == groupID {
            mutate(&self)
            return true
        }

        for groupIndex in groups.indices {
            if groups[groupIndex].updateGroup(id: groupID, mutate: mutate) {
                return true
            }
        }

        return false
    }

    mutating func deleteGroup(id groupID: UUID) -> Bool {
        if let groupIndex = groups.firstIndex(where: { $0.id == groupID }) {
            groups.remove(at: groupIndex)
            return true
        }

        for groupIndex in groups.indices {
            if groups[groupIndex].deleteGroup(id: groupID) {
                return true
            }
        }

        return false
    }
}
