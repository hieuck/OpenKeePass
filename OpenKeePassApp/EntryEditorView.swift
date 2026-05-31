import KeePassCore
import PasswordTools
import SwiftUI

struct EntryEditorView: View {
    @Environment(\.dismiss) private var dismiss

    let entry: KeePassEntry?
    let onSave: (KeePassEntry) -> Void
    @State private var title: String
    @State private var username: String
    @State private var password: String
    @State private var url: String
    @State private var notes: String

    init(entry: KeePassEntry?, onSave: @escaping (KeePassEntry) -> Void) {
        self.entry = entry
        self.onSave = onSave
        _title = State(initialValue: entry?.title ?? "")
        _username = State(initialValue: entry?.username ?? "")
        _password = State(initialValue: entry?.password ?? "")
        _url = State(initialValue: entry?.url ?? "")
        _notes = State(initialValue: entry?.notes ?? "")
    }

    var body: some View {
        Form {
            Section("Entry") {
                TextField("Title", text: $title)
                TextField("Username", text: $username)
                TextField("URL", text: $url)
                    .keyboardType(.URL)
                    .textContentType(.URL)
            }

            Section("Password") {
                SecureField("Password", text: $password)
                Button {
                    password = PasswordGenerator().generate(options: .init(length: 24, includeSymbols: true))
                } label: {
                    Label("Generate", systemImage: "wand.and.stars")
                }
            }

            Section("Notes") {
                TextEditor(text: $notes)
                    .frame(minHeight: 120)
            }
        }
        .navigationTitle(entry == nil ? "New Entry" : "Edit Entry")
        .toolbar {
            Button("Save") {
                onSave(
                    editedEntry()
                )
                dismiss()
            }
                .disabled(title.isEmpty)
        }
    }

    private func editedEntry() -> KeePassEntry {
        if let entry {
            return entry.updatingEditableFields(
                title: title,
                username: username,
                password: password,
                url: url,
                notes: notes
            )
        }

        return KeePassEntry(
            id: UUID(),
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes,
            customFields: []
        )
    }
}
