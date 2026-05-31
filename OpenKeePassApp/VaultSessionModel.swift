import AuthenticationServices
import Combine
import Foundation
import KeePassCore
import SecurityKit
import VaultStore

@MainActor
final class VaultSessionModel: ObservableObject {
    @Published var isUnlocking = false
    @Published var isSaving = false
    @Published var isDirty = false
    @Published var vault: KeePassVault?
    @Published var errorMessage: String?

    private let fileURL: URL
    private let store = VaultStore(engine: KDBX4Engine())
    private var credentials: KDBXCredentials?

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    func unlock(data: Data, password: String, keyFileData: Data? = nil) async throws {
        isUnlocking = true
        vault = nil
        isDirty = false
        errorMessage = nil
        defer {
            isUnlocking = false
        }

        do {
            let credentials = KDBXCredentials(password: password, keyFileData: keyFileData)
            try await store.unlock(data: data, credentials: credentials)
            self.credentials = credentials
            vault = store.unlockedVault
            isDirty = store.isDirty
            exportAutoFillCredentials()
        } catch {
            errorMessage = UnlockErrorMessage.describe(error)
            throw error
        }
    }

    func save() async {
        guard let credentials else {
            errorMessage = "Unlock this vault before saving."
            return
        }

        isSaving = true
        errorMessage = nil
        defer {
            isSaving = false
        }

        let didStartAccess = fileURL.startAccessingSecurityScopedResource()
        defer {
            if didStartAccess {
                fileURL.stopAccessingSecurityScopedResource()
            }
        }

        do {
            let data = try await store.save(credentials: credentials)
            try data.write(to: fileURL, options: .atomic)
            vault = store.unlockedVault
            isDirty = store.isDirty
            exportAutoFillCredentials()
        } catch {
            errorMessage = "Could not save this vault."
        }
    }

    func addEntry(_ entry: KeePassEntry, toGroup groupID: UUID) {
        do {
            try store.addEntry(entry, toGroup: groupID)
            vault = store.unlockedVault
            isDirty = store.isDirty
            exportAutoFillCredentials()
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
            isDirty = store.isDirty
            exportAutoFillCredentials()
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

    private func exportAutoFillCredentials() {
        guard let vault, let directory = AppGroupContainer().url() else {
            return
        }

        let records = vault.root.flattenedEntries().compactMap { entry -> AutoFillCredentialRecord? in
            let username = entry.username.trimmingCharacters(in: .whitespacesAndNewlines)
            let password = entry.password.trimmingCharacters(in: .whitespacesAndNewlines)
            let url = entry.url.trimmingCharacters(in: .whitespacesAndNewlines)

            guard !username.isEmpty, !password.isEmpty, URL(string: url)?.host != nil else {
                return nil
            }

            return AutoFillCredentialRecord(
                id: entry.id.uuidString,
                title: entry.title,
                username: entry.username,
                password: entry.password,
                url: entry.url
            )
        }

        do {
            try AutoFillCredentialCache(directory: directory).write(records)
            replaceAutoFillIdentities(with: records)
        } catch {
            errorMessage = "Could not update AutoFill credentials."
        }
    }

    private func replaceAutoFillIdentities(with records: [AutoFillCredentialRecord]) {
        let identities = records.compactMap { record -> ASPasswordCredentialIdentity? in
            guard let host = record.serviceHost else {
                return nil
            }
            let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
            return ASPasswordCredentialIdentity(
                serviceIdentifier: service,
                user: record.username,
                recordIdentifier: record.id
            )
        }

        ASCredentialIdentityStore.shared.replaceCredentialIdentities(with: identities) { [weak self] success, _ in
            guard !success else {
                return
            }
            DispatchQueue.main.async {
                self?.errorMessage = "Could not update AutoFill suggestions."
            }
        }
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
