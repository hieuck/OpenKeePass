import KeePassCore
import SwiftUI

struct GroupListView: View {
    let vaultName: String
    @State private var searchText = ""
    @State private var entries = SampleVault.entries

    var filteredEntries: [KeePassEntry] {
        guard !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return entries
        }
        return entries.filter { entry in
            entry.matches(searchText.lowercased())
        }
    }

    var body: some View {
        List {
            Section(vaultName) {
                ForEach(filteredEntries) { entry in
                    NavigationLink(destination: EntryDetailView(entry: entry)) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.title)
                                .font(.headline)
                            if !entry.username.isEmpty {
                                Text(entry.username)
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .searchable(text: $searchText)
        .navigationTitle(vaultName)
        .toolbar {
            NavigationLink(destination: EntryEditorView(entry: nil)) {
                Image(systemName: "plus")
            }
            .accessibilityLabel("Add Entry")
        }
    }
}

private enum SampleVault {
    static let entries: [KeePassEntry] = [
        KeePassEntry(
            id: UUID(),
            title: "Example",
            username: "user@example.com",
            password: "password",
            url: "https://example.com",
            notes: "Sample entry until KDBX engine is connected.",
            customFields: []
        )
    ]
}
