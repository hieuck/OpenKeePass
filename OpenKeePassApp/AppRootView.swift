import SecurityKit
import SwiftUI

struct AppRootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("security.biometricUnlock") private var biometricUnlock = true
    @AppStorage("security.autoLockMinutes") private var autoLockMinutes = 5.0
    @State private var selectedVault: VaultReference?
    @State private var isImportingVault = false
    @State private var isCreatingVault = false
    @State private var isShowingSettings = false
    @State private var lastInactiveAt: Date?
    @State private var isLocked = false
    @State private var isAuthenticating = false
    @State private var lockMessage: String?

    private let biometricGate = LocalBiometricGate()

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
        .overlay {
            if isLocked {
                AppLockView(
                    isAuthenticating: isAuthenticating,
                    message: lockMessage,
                    unlock: authenticateAndUnlock
                )
            }
        }
        .onChange(of: scenePhase) { phase in
            handleScenePhaseChange(phase)
        }
        .navigationViewStyle(DoubleColumnNavigationViewStyle())
    }

    private func handleScenePhaseChange(_ phase: ScenePhase) {
        switch phase {
        case .active:
            let policy = AutoLockPolicy(isEnabled: biometricUnlock, timeout: autoLockMinutes * 60)
            if policy.shouldLock(now: Date(), lastInactiveAt: lastInactiveAt) {
                isLocked = true
                lockMessage = nil
            }
        case .inactive, .background:
            lastInactiveAt = Date()
        @unknown default:
            break
        }
    }

    private func authenticateAndUnlock() {
        guard !isAuthenticating else {
            return
        }

        isAuthenticating = true
        lockMessage = nil

        Task {
            do {
                let success = try await biometricGate.authenticate(reason: "Unlock OpenKeePass")
                await MainActor.run {
                    isLocked = !success
                    lockMessage = success ? nil : "Biometric authentication is unavailable."
                    isAuthenticating = false
                    if success {
                        lastInactiveAt = nil
                    }
                }
            } catch {
                await MainActor.run {
                    lockMessage = "Could not unlock OpenKeePass."
                    isAuthenticating = false
                }
            }
        }
    }
}

private struct AppLockView: View {
    var isAuthenticating: Bool
    var message: String?
    var unlock: () -> Void

    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()

            VStack(spacing: 16) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 42, weight: .semibold))
                    .foregroundColor(.accentColor)

                Text("OpenKeePass Locked")
                    .font(.title2.weight(.semibold))

                if let message {
                    Text(message)
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }

                Button {
                    unlock()
                } label: {
                    if isAuthenticating {
                        ProgressView()
                    } else {
                        Label("Unlock", systemImage: "faceid")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isAuthenticating)
            }
            .padding()
        }
    }
}

struct VaultReference: Identifiable, Equatable {
    let id = UUID()
    var url: URL
}
