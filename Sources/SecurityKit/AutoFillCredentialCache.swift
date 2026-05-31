import Foundation
#if canImport(CryptoKit) && canImport(Security) && os(iOS)
import CryptoKit
import Security
#endif

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

public protocol AutoFillCredentialCacheProtection: Sendable {
    func protect(_ data: Data) throws -> Data
    func unprotect(_ data: Data) throws -> Data
}

public struct AutoFillCredentialCache: Sendable {
    public static let fileName = "autofill-credentials.json"

    private let directory: URL
    private let protection: AutoFillCredentialCacheProtection?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, protection: AutoFillCredentialCacheProtection? = AutoFillCredentialCache.defaultProtection()) {
        self.directory = directory
        self.protection = protection
    }

    public func write(_ records: [AutoFillCredentialRecord]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try encoder.encode(cachePayload(for: records))
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
        return try records(from: data)
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

    private func cachePayload(for records: [AutoFillCredentialRecord]) throws -> AutoFillCredentialCachePayload {
        let recordsData = try encoder.encode(records)
        guard let protection else {
            return .records(records)
        }
        return .protected(try protection.protect(recordsData))
    }

    private func records(from data: Data) throws -> [AutoFillCredentialRecord] {
        if let payload = try? decoder.decode(AutoFillCredentialCachePayload.self, from: data) {
            switch payload {
            case .records(let records):
                return records
            case .protected(let protectedData):
                guard let protection else {
                    throw AutoFillCredentialCacheError.missingProtection
                }
                let recordsData = try protection.unprotect(protectedData)
                return try decoder.decode([AutoFillCredentialRecord].self, from: recordsData)
            }
        }

        return try decoder.decode([AutoFillCredentialRecord].self, from: data)
    }

    private static func normalizedHost(_ value: String) -> String {
        value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    public static func defaultProtection() -> AutoFillCredentialCacheProtection? {
        #if canImport(CryptoKit) && canImport(Security) && os(iOS)
        return KeychainAutoFillCredentialCacheProtection()
        #else
        return nil
        #endif
    }
}

public enum AutoFillCredentialCacheError: Error, Equatable {
    case missingProtection
    case keychainReadFailed(Int32)
    case keychainWriteFailed(Int32)
    case invalidKey
}

private enum AutoFillCredentialCachePayload: Codable, Equatable {
    case records([AutoFillCredentialRecord])
    case protected(Data)

    private enum CodingKeys: String, CodingKey {
        case version
        case kind
        case records
        case payload
    }

    private enum Kind: String, Codable {
        case records
        case protected
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .version)
        guard version == 1 else {
            throw DecodingError.dataCorruptedError(forKey: .version, in: container, debugDescription: "Unsupported AutoFill cache payload version")
        }

        switch try container.decode(Kind.self, forKey: .kind) {
        case .records:
            self = .records(try container.decode([AutoFillCredentialRecord].self, forKey: .records))
        case .protected:
            self = .protected(try container.decode(Data.self, forKey: .payload))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(1, forKey: .version)
        switch self {
        case .records(let records):
            try container.encode(Kind.records, forKey: .kind)
            try container.encode(records, forKey: .records)
        case .protected(let payload):
            try container.encode(Kind.protected, forKey: .kind)
            try container.encode(payload, forKey: .payload)
        }
    }
}

#if canImport(CryptoKit) && canImport(Security) && os(iOS)
public struct KeychainAutoFillCredentialCacheProtection: AutoFillCredentialCacheProtection {
    private let service = "dev.openkeepass.autofill-cache"
    private let account = "cache-encryption-key"
    private let accessGroup: String?

    public init(accessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "OpenKeePassKeychainAccessGroup") as? String) {
        self.accessGroup = accessGroup
    }

    public func protect(_ data: Data) throws -> Data {
        let key = SymmetricKey(data: try keyData())
        let sealedBox = try AES.GCM.seal(data, using: key)
        guard let combined = sealedBox.combined else {
            throw AutoFillCredentialCacheError.invalidKey
        }
        return combined
    }

    public func unprotect(_ data: Data) throws -> Data {
        let key = SymmetricKey(data: try keyData())
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    private func keyData() throws -> Data {
        if let existing = try readKey() {
            guard existing.count == 32 else {
                throw AutoFillCredentialCacheError.invalidKey
            }
            return existing
        }

        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.bindMemory(to: UInt8.self).baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
        }
        guard status == errSecSuccess else {
            throw AutoFillCredentialCacheError.keychainWriteFailed(status)
        }

        try writeKey(key)
        return key
    }

    private func readKey() throws -> Data? {
        var query = keychainQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw AutoFillCredentialCacheError.keychainReadFailed(status)
        }
        return result as? Data
    }

    private func writeKey(_ key: Data) throws {
        var query = keychainQuery()
        query[kSecValueData as String] = key
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw AutoFillCredentialCacheError.keychainWriteFailed(status)
        }
    }

    private func keychainQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let accessGroup, !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}
#endif
