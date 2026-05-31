import KeePassCore
import SwiftUI
import VaultStore

struct UnlockView: View {
    let vault: VaultReference
    @State private var password = ""
    @State private var errorMessage: String?
    @StateObject private var model = UnlockModel()

    var body: some View {
        Form {
            Section("Vault") {
                Text(vault.url.lastPathComponent)
            }

            Section("Unlock") {
                SecureField("Master Password", text: $password)
                Button {
                    Task {
                        await unlock()
                    }
                } label: {
                    if model.isUnlocking {
                        ProgressView()
                    } else {
                        Label("Unlock", systemImage: "lock.open")
                    }
                }
                .disabled(password.isEmpty || model.isUnlocking)
            }

            if let errorMessage = errorMessage ?? model.errorMessage {
                Section {
                    Text(errorMessage)
                        .foregroundColor(.red)
                }
            }

            if model.isUnlocked {
                Section {
                    NavigationLink("Open Vault", destination: GroupListView(vaultName: vault.url.deletingPathExtension().lastPathComponent))
                }
            }
        }
        .navigationTitle("Unlock")
    }

    private func unlock() async {
        errorMessage = nil
        guard vault.url.startAccessingSecurityScopedResource() else {
            errorMessage = "OpenKeePass could not access this file. Re-select it from Files."
            return
        }
        defer {
            vault.url.stopAccessingSecurityScopedResource()
        }

        do {
            let data = try Data(contentsOf: vault.url)
            try await model.unlock(data: data, password: password)
        } catch {
            errorMessage = UnlockErrorMessage.describe(error)
        }
    }
}

@MainActor
private final class UnlockModel: ObservableObject {
    @Published var isUnlocking = false
    @Published var isUnlocked = false
    @Published var errorMessage: String?

    private let store = VaultStore(engine: KDBX4Engine())

    func unlock(data: Data, password: String) async throws {
        isUnlocking = true
        isUnlocked = false
        errorMessage = nil
        defer {
            isUnlocking = false
        }

        do {
            try await store.unlock(data: data, credentials: KDBXCredentials(password: password))
            isUnlocked = true
        } catch {
            errorMessage = UnlockErrorMessage.describe(error)
            throw error
        }
    }
}

private enum UnlockErrorMessage {
    static func describe(_ error: Error) -> String {
        guard let kdbxError = error as? KDBXError else {
            return "Could not unlock this vault."
        }

        switch kdbxError {
        case .notKeePassDatabase:
            return "This file is not a KeePass .kdbx database."
        case .truncatedHeader:
            return "This database file is incomplete or corrupted."
        case .wrongCredentials:
            return "The master password or key file is incorrect."
        case .unsupportedFeature(let feature):
            return feature
        case .corruptDatabase:
            return "This database could not be read."
        }
    }
}
