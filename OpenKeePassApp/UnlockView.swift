import SwiftUI

struct UnlockView: View {
    let vault: VaultReference
    @State private var password = ""
    @State private var isUnlocked = false
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section("Vault") {
                Text(vault.url.lastPathComponent)
            }

            Section("Unlock") {
                SecureField("Master Password", text: $password)
                Button {
                    unlock()
                } label: {
                    Label("Unlock", systemImage: "lock.open")
                }
                .disabled(password.isEmpty)
            }

            if let errorMessage {
                Section {
                    Text(errorMessage)
                        .foregroundColor(.red)
                }
            }

            if isUnlocked {
                Section {
                    NavigationLink("Open Vault", destination: GroupListView(vaultName: vault.url.deletingPathExtension().lastPathComponent))
                }
            }
        }
        .navigationTitle("Unlock")
    }

    private func unlock() {
        errorMessage = nil
        isUnlocked = true
    }
}
