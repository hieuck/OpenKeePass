import KeePassCore
import PasswordTools
import SwiftUI

struct EntryEditorView: View {
    let entry: KeePassEntry?
    @State private var title: String
    @State private var username: String
    @State private var password: String
    @State private var url: String
    @State private var notes: String

    init(entry: KeePassEntry?) {
        self.entry = entry
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
            Button("Save") {}
                .disabled(title.isEmpty)
        }
    }
}
