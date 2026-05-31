import KeePassCore
import SwiftUI
import UniformTypeIdentifiers
import VaultStore

struct UnlockView: View {
    let vault: VaultReference
    @State private var password = ""
    @State private var keyFileURL: URL?
    @State private var keyFileData: Data?
    @State private var isImportingKeyFile = false
    @State private var errorMessage: String?
    @StateObject private var model: VaultSessionModel

    init(vault: VaultReference) {
        self.vault = vault
        _model = StateObject(wrappedValue: VaultSessionModel(fileURL: vault.url))
    }

    var body: some View {
        Form {
            Section("Vault") {
                Text(vault.url.lastPathComponent)
            }

            Section("Unlock") {
                SecureField("Master Password", text: $password)
                Button {
                    isImportingKeyFile = true
                } label: {
                    Label(keyFileURL?.lastPathComponent ?? "Select Key File", systemImage: "key")
                }
                if keyFileData != nil {
                    Button(role: .destructive) {
                        keyFileURL = nil
                        keyFileData = nil
                    } label: {
                        Label("Remove Key File", systemImage: "xmark.circle")
                    }
                }
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
                .disabled((password.isEmpty && keyFileData == nil) || model.isUnlocking)
            }

            if let errorMessage = errorMessage ?? model.errorMessage {
                Section {
                    Text(errorMessage)
                        .foregroundColor(.red)
                }
            }

            if let unlockedVault = model.vault {
                Section {
                    NavigationLink(
                        "Open Vault",
                        destination: GroupListView(model: model, groupID: unlockedVault.root.id)
                    )
                }
            }
        }
        .navigationTitle("Unlock")
        .sheet(isPresented: $isImportingKeyFile) {
            DocumentPicker(contentTypes: keyFileContentTypes) { url in
                loadKeyFile(from: url)
            }
        }
    }

    private var keyFileContentTypes: [UTType] {
        [
            UTType(filenameExtension: "key") ?? .data,
            UTType(filenameExtension: "keyx") ?? .data,
            .xml,
            .data
        ]
    }

    private func unlock() async {
        errorMessage = nil
        let didStartAccess = vault.url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccess {
                vault.url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            let data = try Data(contentsOf: vault.url)
            try await model.unlock(data: data, password: password, keyFileData: keyFileData)
        } catch {
            errorMessage = UnlockErrorMessage.describe(error)
        }
    }

    private func loadKeyFile(from url: URL) {
        errorMessage = nil
        let didStartAccess = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            keyFileData = try Data(contentsOf: url)
            keyFileURL = url
        } catch {
            errorMessage = "OpenKeePass could not read this key file."
        }
    }
}

enum UnlockErrorMessage {
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
