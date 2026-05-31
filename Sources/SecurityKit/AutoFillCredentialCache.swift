import Foundation

public struct AutoFillCredentialRecord: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var title: String
    public var username: String
    public var password: String
    public var url: String

    public init(id: String, title: String, username: String, password: String, url: String) {
        self.id = id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
    }

    public var serviceHost: String? {
        guard let url = URL(string: url), let host = url.host else {
            return nil
        }
        return host.lowercased()
    }
}

public struct AutoFillCredentialCache: Sendable {
    public static let fileName = "autofill-credentials.json"

    private let directory: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL) {
        self.directory = directory
    }

    public func write(_ records: [AutoFillCredentialRecord]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try encoder.encode(records)
        #if os(iOS)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: fileURL, options: .atomic)
        #endif
    }

    public func read() throws -> [AutoFillCredentialRecord] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return []
        }
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode([AutoFillCredentialRecord].self, from: data)
    }

    public func credentials(matchingServiceIdentifiers identifiers: [String]) throws -> [AutoFillCredentialRecord] {
        let normalizedIdentifiers = identifiers.map(Self.normalizedHost)
        guard !normalizedIdentifiers.isEmpty else {
            return try read()
        }

        return try read().filter { record in
            guard let host = record.serviceHost else {
                return false
            }
            return normalizedIdentifiers.contains { identifier in
                host == identifier || host.hasSuffix(".\(identifier)")
            }
        }
    }

    public func credential(id: String) throws -> AutoFillCredentialRecord? {
        try read().first { $0.id == id }
    }

    private var fileURL: URL {
        directory.appendingPathComponent(Self.fileName)
    }

    private static func normalizedHost(_ value: String) -> String {
        value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}
