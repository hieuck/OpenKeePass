import SwiftUI

struct EntryMoveView: View {
    @Environment(\.dismiss) private var dismiss

    @ObservedObject var model: VaultSessionModel
    let entryID: UUID

    var body: some View {
        List(model.groupChoices()) { group in
            Button {
                model.moveEntry(id: entryID, toGroup: group.id)
                dismiss()
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(group.title.isEmpty ? "Root" : group.title)
                    Text(group.path)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .navigationTitle("Move Entry")
    }
}
