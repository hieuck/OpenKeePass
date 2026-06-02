import Foundation
import KeePassCore
import SecurityKit

public enum AutoFillCredentialExporter {
    public static func records(from vault: KeePassVault) -> [AutoFillCredentialRecord] {
        vault.root.flattenedEntries().compactMap(record)
    }

    private static func record(from entry: KeePassEntry) -> AutoFillCredentialRecord? {
        let username = entry.username.trimmingCharacters(in: .whitespacesAndNewlines)
        let password = entry.password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty,
              !password.isEmpty,
              let url = entry.openURL else {
            return nil
        }

        return AutoFillCredentialRecord(
            id: entry.id.uuidString,
            title: entry.title,
            username: entry.username,
            password: entry.password,
            url: url.absoluteString
        )
    }
}
