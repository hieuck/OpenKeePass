import SwiftUI

struct GroupEditorView: View {
    @Environment(\.dismiss) private var dismiss

    let navigationTitle: String
    let actionTitle: String
    let onSave: (String) -> Void
    @State private var title: String

    init(title: String = "", navigationTitle: String, actionTitle: String, onSave: @escaping (String) -> Void) {
        self.navigationTitle = navigationTitle
        self.actionTitle = actionTitle
        self.onSave = onSave
        _title = State(initialValue: title)
    }

    var body: some View {
        Form {
            Section("Group") {
                TextField("Name", text: $title)
            }
        }
        .navigationTitle(navigationTitle)
        .toolbar {
            Button(actionTitle) {
                onSave(title)
                dismiss()
            }
            .disabled(title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }
}
