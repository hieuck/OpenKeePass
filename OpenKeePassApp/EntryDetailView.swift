import KeePassCore
import PasswordTools
import SwiftUI
import UIKit

struct EntryDetailView: View {
    @ObservedObject var model: VaultSessionModel
    let entryID: UUID

    var body: some View {
        if let entry = model.entry(id: entryID) {
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

                if let otpConfiguration = try? TOTPConfiguration(keePassFields: entry.customFields.map { (name: $0.name, value: $0.value) }) {
                    OneTimePasswordSection(configuration: otpConfiguration)
                }

                if !entry.attachments.isEmpty {
                    AttachmentSection(attachments: entry.attachments)
                }

                Section {
                    NavigationLink("Edit", destination: EntryEditorView(entry: entry) { updatedEntry in
                        model.updateEntry(updatedEntry)
                    })
                }
            }
            .navigationTitle(entry.title)
        } else {
            Text("This entry is no longer available.")
                .foregroundColor(.secondary)
                .navigationTitle("Entry")
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
                            UIPasteboard.general.string = code
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
