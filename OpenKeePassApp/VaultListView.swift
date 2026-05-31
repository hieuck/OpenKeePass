import SwiftUI

struct VaultListView: View {
    @Binding var selectedVault: VaultReference?
    @Binding var isImportingVault: Bool
    @Binding var isCreatingVault: Bool
    @Binding var isShowingSettings: Bool

    var body: some View {
        List {
            Section {
                Button {
                    isImportingVault = true
                } label: {
                    Label("Open KDBX Vault", systemImage: "folder")
                }

                Button {
                    isCreatingVault = true
                } label: {
                    Label("Create New Vault", systemImage: "plus.circle")
                }
            }

            if let selectedVault {
                Section("Recent") {
                    NavigationLink(destination: UnlockView(vault: selectedVault)) {
                        Label(selectedVault.url.lastPathComponent, systemImage: "lock.doc")
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("OpenKeePass")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    isShowingSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Settings")
            }
        }
    }
}
