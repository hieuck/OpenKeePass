import SwiftUI

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var biometricUnlock = true
    @State private var autoLockMinutes = 5.0
    @State private var clipboardSeconds = 30.0

    var body: some View {
        Form {
            Section("Security") {
                Toggle("Face ID / Touch ID", isOn: $biometricUnlock)
                Stepper("Auto-lock: \(Int(autoLockMinutes)) min", value: $autoLockMinutes, in: 1...60, step: 1)
                Stepper("Clipboard: \(Int(clipboardSeconds)) sec", value: $clipboardSeconds, in: 5...120, step: 5)
            }

            Section("AutoFill") {
                Text("Enable OpenKeePass in iOS Password AutoFill settings.")
                    .foregroundColor(.secondary)
            }

            Section("About") {
                HStack {
                    Text("Version")
                    Spacer()
                    Text("0.1.0")
                        .foregroundColor(.secondary)
                }
                Text("All shipped features are free. No paid tiers.")
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("Settings")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") {
                    dismiss()
                }
            }
        }
    }
}
