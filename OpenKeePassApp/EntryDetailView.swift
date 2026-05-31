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
