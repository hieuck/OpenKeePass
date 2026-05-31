import KeePassCore
import SwiftUI

struct CreateVaultView: View {
    @Environment(\.dismiss) private var dismiss

    var onCreate: (VaultReference) -> Void

    @State private var vaultName = "New Vault"
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var isCreating = false
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section("Vault") {
                TextField("Name", text: $vaultName)
                    .textInputAutocapitalization(.words)
            }

            Section("Master Password") {
                SecureField("Password", text: $password)
                SecureField("Confirm Password", text: $confirmPassword)
            }

            if let errorMessage {
                Section {
                    Text(errorMessage)
                        .foregroundColor(.red)
                }
            }
        }
        .navigationTitle("Create Vault")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    dismiss()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button {
                    Task {
                        await createVault()
                    }
                } label: {
                    if isCreating {
                        ProgressView()
                    } else {
                        Text("Create")
                    }
                }
                .disabled(!canCreate || isCreating)
            }
        }
    }

    private var canCreate: Bool {
        !vaultName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !password.isEmpty
            && password == confirmPassword
    }

    private func createVault() async {
        let trimmedName = vaultName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard canCreate else {
            errorMessage = "Enter a name and matching master password."
            return
        }

        isCreating = true
        errorMessage = nil
        defer {
            isCreating = false
        }

        do {
            let engine = KDBX4Engine()
            let credentials = KDBXCredentials(password: password)
            let vault = try await engine.create(name: trimmedName, credentials: credentials)
            let data = try await engine.save(vault: vault, credentials: credentials)
            let url = try nextVaultURL(named: trimmedName)
            try data.write(to: url, options: .atomic)
            onCreate(VaultReference(url: url))
            dismiss()
        } catch {
            errorMessage = "Could not create this vault."
        }
    }

    private func nextVaultURL(named name: String) throws -> URL {
        let directory = try FileManager.default.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let baseName = sanitizedFileName(name)
        var candidate = directory.appendingPathComponent(baseName).appendingPathExtension("kdbx")
        var suffix = 1
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = directory.appendingPathComponent("\(baseName)-\(suffix)").appendingPathExtension("kdbx")
            suffix += 1
        }
        return candidate
    }

    private func sanitizedFileName(_ name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: " -_"))
        let scalars = name.unicodeScalars.map { scalar in
            allowed.contains(scalar) ? Character(String(scalar)) : "-"
        }
        let value = String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? "Vault" : value
    }
}
