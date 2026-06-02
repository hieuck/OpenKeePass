import KeePassCore
import PasswordTools
import SwiftUI
import UniformTypeIdentifiers

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
    @State private var attachments: [EditableAttachment]
    @State private var isImportingAttachment = false
    @State private var attachmentErrorMessage: String?
    @State private var generatorLength = 24
    @State private var generatorIncludesUppercase = true
    @State private var generatorIncludesLowercase = true
    @State private var generatorIncludesDigits = true
    @State private var generatorIncludesSymbols = true
    @State private var generatorExcludesAmbiguousCharacters = false
    @State private var generatorErrorMessage: String?

    init(entry: KeePassEntry?, onSave: @escaping (KeePassEntry) -> Void) {
        self.entry = entry
        self.onSave = onSave
        _title = State(initialValue: entry?.title ?? "")
        _username = State(initialValue: entry?.username ?? "")
        _password = State(initialValue: entry?.password ?? "")
        _url = State(initialValue: entry?.url ?? "")
        _notes = State(initialValue: entry?.notes ?? "")
        _customFields = State(initialValue: (entry?.customFields ?? []).map(EditableCustomField.init(field:)))
        _attachments = State(initialValue: (entry?.attachments ?? []).map(EditableAttachment.init(attachment:)))
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
                Stepper("Length: \(generatorLength)", value: $generatorLength, in: 8...128)
                Toggle("Uppercase", isOn: $generatorIncludesUppercase)
                Toggle("Lowercase", isOn: $generatorIncludesLowercase)
                Toggle("Digits", isOn: $generatorIncludesDigits)
                Toggle("Symbols", isOn: $generatorIncludesSymbols)
                Toggle("Exclude Ambiguous", isOn: $generatorExcludesAmbiguousCharacters)
                Button {
                    generatePassword()
                } label: {
                    Label("Generate", systemImage: "wand.and.stars")
                }
                if let generatorErrorMessage {
                    Text(generatorErrorMessage)
                        .font(.caption)
                        .foregroundColor(.red)
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

            Section("Attachments") {
                ForEach($attachments) { $attachment in
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("File Name", text: $attachment.name)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)

                        HStack {
                            Text(attachment.byteCountDescription)
                                .foregroundColor(.secondary)

                            Spacer()

                            Toggle("Protected", isOn: $attachment.isProtected)
                        }

                        Button(role: .destructive) {
                            removeAttachment(id: attachment.id)
                        } label: {
                            Label("Delete Attachment", systemImage: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                    .padding(.vertical, 4)
                }

                Button {
                    isImportingAttachment = true
                } label: {
                    Label("Add Attachment", systemImage: "paperclip")
                }

                if let attachmentErrorMessage {
                    Text(attachmentErrorMessage)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
        }
        .navigationTitle(entry == nil ? "New Entry" : "Edit Entry")
        .fileImporter(isPresented: $isImportingAttachment, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            importAttachments(result)
        }
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
                customFields: sanitizedCustomFields(),
                attachments: sanitizedAttachments()
            )
        }

        return KeePassEntry(
            id: UUID(),
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes,
            customFields: sanitizedCustomFields(),
            attachments: sanitizedAttachments()
        )
    }

    private func removeCustomField(id: UUID) {
        customFields.removeAll { $0.id == id }
    }

    private func generatePassword() {
        do {
            password = try PasswordGenerator().generateStrict(
                options: PasswordGeneratorOptions(
                    length: generatorLength,
                    includeUppercase: generatorIncludesUppercase,
                    includeLowercase: generatorIncludesLowercase,
                    includeDigits: generatorIncludesDigits,
                    includeSymbols: generatorIncludesSymbols,
                    excludeAmbiguousCharacters: generatorExcludesAmbiguousCharacters
                )
            )
            generatorErrorMessage = nil
        } catch PasswordGeneratorError.emptyCharacterSet {
            generatorErrorMessage = "Select at least one character type."
        } catch PasswordGeneratorError.lengthTooShortForRequiredClasses {
            generatorErrorMessage = "Length is too short for the selected character types."
        } catch {
            generatorErrorMessage = "Could not generate a password."
        }
    }

    private func sanitizedCustomFields() -> [KeePassField] {
        customFields.compactMap { field in
            let name = field.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else { return nil }
            return KeePassField(name: name, value: field.value, isProtected: field.isProtected)
        }
    }

    private func removeAttachment(id: UUID) {
        attachments.removeAll { $0.id == id }
    }

    private func sanitizedAttachments() -> [KeePassAttachment] {
        attachments.compactMap { attachment in
            let name = attachment.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else { return nil }
            return KeePassAttachment(name: name, data: attachment.data, isProtected: attachment.isProtected)
        }
    }

    private func importAttachments(_ result: Result<[URL], Error>) {
        do {
            for url in try result.get() {
                let didStartAccess = url.startAccessingSecurityScopedResource()
                defer {
                    if didStartAccess {
                        url.stopAccessingSecurityScopedResource()
                    }
                }

                let data = try Data(contentsOf: url)
                attachments.append(
                    EditableAttachment(
                        name: url.lastPathComponent,
                        data: data,
                        isProtected: false
                    )
                )
            }
            attachmentErrorMessage = nil
        } catch {
            attachmentErrorMessage = "Could not import selected attachment."
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

private struct EditableAttachment: Identifiable, Equatable {
    let id: UUID
    var name: String
    var data: Data
    var isProtected: Bool

    var byteCountDescription: String {
        ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file)
    }

    init(id: UUID = UUID(), name: String, data: Data, isProtected: Bool) {
        self.id = id
        self.name = name
        self.data = data
        self.isProtected = isProtected
    }

    init(attachment: KeePassAttachment) {
        self.init(name: attachment.name, data: attachment.data, isProtected: attachment.isProtected)
    }
}
