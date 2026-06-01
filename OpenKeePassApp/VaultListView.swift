import SwiftUI

struct VaultListView: View {
    @Binding var selectedVault: VaultReference?
    @Binding var isImportingVault: Bool
    @Binding var isCreatingVault: Bool
    @Binding var isShowingSettings: Bool
    var forgetSelectedVault: () -> Void = {}
    var lockNow: (() -> Void)?

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
                    Button(role: .destructive) {
                        forgetSelectedVault()
                    } label: {
                        Label("Forget Recent Vault", systemImage: "trash")
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("OpenKeePass")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if let lockNow {
                    Button {
                        lockNow()
                    } label: {
                        Image(systemName: "lock")
                    }
                    .accessibilityLabel("Lock Now")
                }

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
