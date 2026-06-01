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
    @State private var customFields: [EditableCustomField]

    init(entry: KeePassEntry?, onSave: @escaping (KeePassEntry) -> Void) {
        self.entry = entry
        self.onSave = onSave
        _title = State(initialValue: entry?.title ?? "")
        _username = State(initialValue: entry?.username ?? "")
        _password = State(initialValue: entry?.password ?? "")
        _url = State(initialValue: entry?.url ?? "")
        _notes = State(initialValue: entry?.notes ?? "")
        _customFields = State(initialValue: (entry?.customFields ?? []).map(EditableCustomField.init(field:)))
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

            Section("Custom Fields") {
                ForEach($customFields) { $field in
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("Name", text: $field.name)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)

                        if field.isProtected {
                            SecureField("Value", text: $field.value)
                                .textInputAutocapitalization(.never)
                                .disableAutocorrection(true)
                        } else {
                            TextField("Value", text: $field.value)
                                .textInputAutocapitalization(.never)
                                .disableAutocorrection(true)
                        }

                        HStack {
                            Toggle("Protected", isOn: $field.isProtected)

                            Spacer()

                            Button(role: .destructive) {
                                removeCustomField(id: field.id)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Button {
                    customFields.append(EditableCustomField())
                } label: {
                    Label("Add Field", systemImage: "plus")
                }
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
                notes: notes,
                customFields: sanitizedCustomFields()
            )
        }

        return KeePassEntry(
            id: UUID(),
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes,
            customFields: sanitizedCustomFields()
        )
    }

    private func removeCustomField(id: UUID) {
        customFields.removeAll { $0.id == id }
    }

    private func sanitizedCustomFields() -> [KeePassField] {
        customFields.compactMap { field in
            let name = field.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else { return nil }
            return KeePassField(name: name, value: field.value, isProtected: field.isProtected)
        }
    }
}

private struct EditableCustomField: Identifiable, Equatable {
    let id: UUID
    var name: String
    var value: String
    var isProtected: Bool

    init(id: UUID = UUID(), name: String = "", value: String = "", isProtected: Bool = false) {
        self.id = id
        self.name = name
        self.value = value
        self.isProtected = isProtected
    }

    init(field: KeePassField) {
        self.init(name: field.name, value: field.value, isProtected: field.isProtected)
    }
}
