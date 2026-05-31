import SwiftUI

struct AppRootView: View {
    @State private var selectedVault: VaultReference?
    @State private var isImportingVault = false
    @State private var isCreatingVault = false
    @State private var isShowingSettings = false

    var body: some View {
        NavigationView {
            VaultListView(
                selectedVault: $selectedVault,
                isImportingVault: $isImportingVault,
                isCreatingVault: $isCreatingVault,
                isShowingSettings: $isShowingSettings
            )
            Text("Select a vault")
                .foregroundColor(.secondary)
        }
        .sheet(isPresented: $isImportingVault) {
            DocumentPicker { url in
                selectedVault = VaultReference(url: url)
            }
        }
        .sheet(isPresented: $isCreatingVault) {
            NavigationView {
                CreateVaultView { vault in
                    selectedVault = vault
                }
            }
        }
        .sheet(isPresented: $isShowingSettings) {
            NavigationView {
                SettingsView()
            }
        }
        .navigationViewStyle(DoubleColumnNavigationViewStyle())
    }
}

struct VaultReference: Identifiable, Equatable {
    let id = UUID()
    var url: URL
}
