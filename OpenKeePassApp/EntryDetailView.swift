import KeePassCore
import PasswordTools
import SecurityKit
import SwiftUI
import UIKit

struct EntryDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @AppStorage("security.clipboardSeconds") private var clipboardSeconds = 30.0
    @ObservedObject var model: VaultSessionModel
    let entryID: UUID
    @State private var isConfirmingDelete = false
    @State private var isPasswordVisible = false

    var body: some View {
        if let entry = model.entry(id: entryID) {
            Form {
                Section("Account") {
                    DetailRow(label: "Title", value: entry.title)
                    DetailRow(label: "Username", value: entry.username) {
                        if !entry.username.isEmpty {
                            CopyButton(label: "Copy Username") {
                                copyToClipboard(entry.username)
                            }
                        }
                    }
                    DetailRow(label: "URL", value: entry.url) {
                        if let url = entry.openURL {
                            Button {
                                openURL(url)
                            } label: {
                                Image(systemName: "safari")
                            }
                            .accessibilityLabel("Open URL")
                        }
                        if !entry.url.isEmpty {
                            CopyButton(label: "Copy URL") {
                                copyToClipboard(entry.url)
                            }
                        }
                    }
                }

                Section("Password") {
                    HStack {
                        if isPasswordVisible {
                            Text(entry.password)
                                .font(.body.monospaced())
                                .textSelection(.enabled)
                        } else {
                            Text("••••••••")
                        }
                        Spacer()
                        Button {
                            isPasswordVisible.toggle()
                        } label: {
                            Image(systemName: isPasswordVisible ? "eye.slash" : "eye")
                        }
                        .accessibilityLabel(isPasswordVisible ? "Hide Password" : "Show Password")
                        CopyButton(label: "Copy Password") {
                            copyToClipboard(entry.password)
                        }
                    }
                }

                if !entry.notes.isEmpty {
                    Section("Notes") {
                        Text(entry.notes)
                    }
                }

                if let otpConfiguration = try? TOTPConfiguration(keePassFields: entry.customFields.map { (name: $0.name, value: $0.value) }) {
                    OneTimePasswordSection(configuration: otpConfiguration, copyToClipboard: copyToClipboard)
                }

                if !entry.displayableCustomFields.isEmpty {
                    CustomFieldsSection(fields: entry.displayableCustomFields, copyToClipboard: copyToClipboard)
                }

                if !entry.attachments.isEmpty {
                    AttachmentSection(attachments: entry.attachments)
                }

                Section {
                    NavigationLink("Edit", destination: EntryEditorView(entry: entry) { updatedEntry in
                        model.updateEntry(updatedEntry)
                    })
                    NavigationLink("Move", destination: EntryMoveView(model: model, entryID: entry.id))
                }

                Section {
                    Button(role: .destructive) {
                        isConfirmingDelete = true
                    } label: {
                        Label("Delete Entry", systemImage: "trash")
                    }
                }
            }
            .navigationTitle(entry.title)
            .confirmationDialog("Delete this entry?", isPresented: $isConfirmingDelete, titleVisibility: .visible) {
                Button("Delete Entry", role: .destructive) {
                    model.deleteEntry(id: entry.id)
                    dismiss()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes the entry from the unlocked vault. Save the vault to write the deletion to the .kdbx file.")
            }
        } else {
            Text("This entry is no longer available.")
                .foregroundColor(.secondary)
                .navigationTitle("Entry")
        }
    }

    private func copyToClipboard(_ value: String) {
        ClipboardService(
            pasteboard: SystemPasteboard(),
            scheduler: DispatchClipboardScheduler()
        )
        .copy(value, expiration: clipboardSeconds)
    }
}

private struct CopyButton: View {
    let label: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "doc.on.doc")
        }
        .accessibilityLabel(label)
    }
}

private struct CustomFieldsSection: View {
    let fields: [KeePassField]
    let copyToClipboard: (String) -> Void

    var body: some View {
        Section("Custom Fields") {
            ForEach(Array(fields.enumerated()), id: \.offset) { _, field in
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(field.name)
                        CustomFieldValueText(field: field)
                    }
                    Spacer()
                    CopyButton(label: "Copy \(field.name)") {
                        copyToClipboard(field.copyValue)
                    }
                }
            }
        }
    }
}

private struct CustomFieldValueText: View {
    let field: KeePassField

    var body: some View {
        if field.isProtected {
            Text(field.displayValue)
                .font(.body.monospaced())
                .foregroundColor(.secondary)
        } else {
            Text(field.displayValue)
                .foregroundColor(.secondary)
                .textSelection(.enabled)
        }
    }
}

private struct AttachmentSection: View {
    let attachments: [KeePassAttachment]
    @State private var shareItem: AttachmentShareItem?
    @State private var errorMessage: String?

    var body: some View {
        Section("Attachments") {
            ForEach(Array(attachments.enumerated()), id: \.offset) { _, attachment in
                HStack {
                    Image(systemName: "paperclip")
                        .foregroundColor(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(attachment.safeExportFileName)
                        HStack(spacing: 6) {
                            Text(attachment.byteCountDescription)
                            if attachment.isProtected {
                                Text("Protected")
                            }
                        }
                        .font(.caption)
                        .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button {
                        share(attachment)
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .accessibilityLabel("Share \(attachment.safeExportFileName)")
                }
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
        .sheet(item: $shareItem) { item in
            ActivityView(activityItems: [item.url])
        }
    }

    private func share(_ attachment: KeePassAttachment) {
        do {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("OpenKeePassAttachments", isDirectory: true)
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let url = directory.appendingPathComponent(attachment.safeExportFileName)
            try attachment.data.write(to: url, options: .atomic)
            errorMessage = nil
            shareItem = AttachmentShareItem(url: url)
        } catch {
            errorMessage = "Could not prepare attachment for sharing."
        }
    }
}

private struct AttachmentShareItem: Identifiable {
    let id = UUID()
    let url: URL
}

private struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

private struct OneTimePasswordSection: View {
    let configuration: TOTPConfiguration
    let copyToClipboard: (String) -> Void
    private let generator = TOTPGenerator()

    var body: some View {
        Section("One-Time Password") {
            TimelineView(.periodic(from: Date(), by: 1)) { context in
                let code = (try? generator.code(configuration: configuration, timeInterval: context.date.timeIntervalSince1970)) ?? "------"
                let remaining = secondsRemaining(at: context.date)

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(code)
                            .font(.title2.monospacedDigit())
                            .textSelection(.enabled)
                        Spacer()
                        Button {
                            copyToClipboard(code)
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .accessibilityLabel("Copy One-Time Password")
                    }

                    HStack {
                        ProgressView(value: Double(remaining), total: Double(configuration.period))
                        Text("\(remaining)s")
                            .font(.caption.monospacedDigit())
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
    }

    private func secondsRemaining(at date: Date) -> Int {
        let elapsed = Int(date.timeIntervalSince1970) % configuration.period
        return configuration.period - elapsed
    }
}

private struct DetailRow<Actions: View>: View {
    let label: String
    let value: String
    let actions: Actions

    init(label: String, value: String, @ViewBuilder actions: () -> Actions) {
        self.label = label
        self.value = value
        self.actions = actions()
    }

    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
            actions
        }
    }
}

private extension DetailRow where Actions == EmptyView {
    init(label: String, value: String) {
        self.label = label
        self.value = value
        self.actions = EmptyView()
    }
}
