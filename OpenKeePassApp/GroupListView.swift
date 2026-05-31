import KeePassCore
import SwiftUI

struct GroupListView: View {
    let vault: KeePassVault

    var body: some View {
        GroupContentView(vaultName: vault.name, group: vault.root)
    }
}

private struct GroupContentView: View {
    let vaultName: String
    let group: KeePassGroup
    @State private var searchText = ""

    var filteredEntries: [KeePassEntry] {
        guard !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return group.entries
        }
        return group.flattenedEntries().filter { entry in
            entry.matches(searchText.lowercased())
        }
    }

    var body: some View {
        List {
            if searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !group.groups.isEmpty {
                Section("Groups") {
                    ForEach(group.groups) { child in
                        NavigationLink(destination: GroupContentView(vaultName: vaultName, group: child)) {
                            Label(child.title, systemImage: "folder")
                        }
                    }
                }
            }

            Section("Entries") {
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
        .navigationTitle(group.title.isEmpty ? vaultName : group.title)
        .toolbar {
            NavigationLink(destination: EntryEditorView(entry: nil)) {
                Image(systemName: "plus")
            }
            .accessibilityLabel("Add Entry")
        }
    }
}
