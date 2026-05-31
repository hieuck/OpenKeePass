import Foundation
import KeePassCore

public enum VaultState: Equatable, Sendable {
    case locked
    case unlocked(vault: KeePassVault, isDirty: Bool)
}

public enum VaultStoreError: Error, Equatable, Sendable {
    case noUnlockedVault
    case entryNotFound(UUID)
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
}
