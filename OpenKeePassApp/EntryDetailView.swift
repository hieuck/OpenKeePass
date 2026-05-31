import KeePassCore
import SwiftUI
import UIKit

struct EntryDetailView: View {
    let entry: KeePassEntry

    var body: some View {
        Form {
            Section("Account") {
                DetailRow(label: "Title", value: entry.title)
                DetailRow(label: "Username", value: entry.username)
                DetailRow(label: "URL", value: entry.url)
            }

            Section("Password") {
                HStack {
                    Text("••••••••")
                    Spacer()
                    Button {
                        UIPasteboard.general.string = entry.password
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .accessibilityLabel("Copy Password")
                }
            }

            if !entry.notes.isEmpty {
                Section("Notes") {
                    Text(entry.notes)
                }
            }

            Section {
                NavigationLink("Edit", destination: EntryEditorView(entry: entry))
            }
        }
        .navigationTitle(entry.title)
    }
}

private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}
