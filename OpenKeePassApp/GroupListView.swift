import KeePassCore
import SwiftUI

struct GroupListView: View {
    @ObservedObject var model: VaultSessionModel
    let groupID: UUID

    var body: some View {
        if let vaultName = model.vault?.name, let group = model.group(id: groupID) {
            GroupContentView(model: model, vaultName: vaultName, group: group)
        } else {
            Text("This group is no longer available.")
                .foregroundColor(.secondary)
        }
    }
}

private struct GroupContentView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: VaultSessionModel
    let vaultName: String
    let group: KeePassGroup
    @State private var searchText = ""
    @State private var isConfirmingDelete = false

    var filteredEntries: [KeePassEntry] {
        guard !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return group.entries
        }
        return group.flattenedEntries().filter { entry in
            entry.matches(searchText.lowercased())
        }
    }

    private var isRootGroup: Bool {
        model.vault?.root.id == group.id
    }

    var body: some View {
        List {
            if let errorMessage = model.errorMessage {
                Section {
                    Text(errorMessage)
                        .foregroundColor(.red)
                }
            }

            if searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !group.groups.isEmpty {
                Section("Groups") {
                    ForEach(group.groups) { child in
                        NavigationLink(destination: GroupListView(model: model, groupID: child.id)) {
                            Label(child.title, systemImage: "folder")
                        }
                    }
                }
            }

            Section("Entries") {
                ForEach(filteredEntries) { entry in
                    NavigationLink(destination: EntryDetailView(model: model, entryID: entry.id)) {
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
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button {
                    Task {
                        await model.save()
                    }
                } label: {
                    if model.isSaving {
                        ProgressView()
                    } else {
                        Image(systemName: "square.and.arrow.down")
                    }
                }
                .disabled(!model.isDirty || model.isSaving)
                .accessibilityLabel("Save Vault")

                Menu {
                    NavigationLink(destination: EntryEditorView(entry: nil) { entry in
                        model.addEntry(entry, toGroup: group.id)
                    }) {
                        Label("New Entry", systemImage: "person.crop.circle.badge.plus")
                    }

                    NavigationLink(destination: GroupEditorView(navigationTitle: "New Group", actionTitle: "Add") { title in
                        model.addGroup(title: title, toParent: group.id)
                    }) {
                        Label("New Group", systemImage: "folder.badge.plus")
                    }

                    NavigationLink(destination: GroupEditorView(title: group.title, navigationTitle: "Rename Group", actionTitle: "Save") { title in
                        model.renameGroup(id: group.id, title: title)
                    }) {
                        Label("Rename Group", systemImage: "pencil")
                    }
                    .disabled(isRootGroup)

                    Button(role: .destructive) {
                        isConfirmingDelete = true
                    } label: {
                        Label("Delete Group", systemImage: "trash")
                    }
                    .disabled(isRootGroup)

                    Button {
                        model.lock()
                        dismiss()
                    } label: {
                        Label("Lock Vault", systemImage: "lock.fill")
                    }
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Vault Actions")
            }
        }
        .confirmationDialog("Delete this group?", isPresented: $isConfirmingDelete, titleVisibility: .visible) {
            Button("Delete Group", role: .destructive) {
                model.deleteGroup(id: group.id)
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the group and its entries from the unlocked vault. Save the vault to write the deletion to the .kdbx file.")
        }
    }
}
