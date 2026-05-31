import Foundation

public struct KDBXCredentials: Equatable, Sendable {
    public var password: String
    public var keyFileData: Data?

    public init(password: String, keyFileData: Data? = nil) {
        self.password = password
        self.keyFileData = keyFileData
    }
}

public protocol KDBXEngine: Sendable {
    func open(data: Data, credentials: KDBXCredentials) async throws -> KeePassVault
    func create(name: String, credentials: KDBXCredentials) async throws -> KeePassVault
    func save(vault: KeePassVault, credentials: KDBXCredentials) async throws -> Data
}

public enum KDBXError: Error, Equatable, Sendable {
    case notKeePassDatabase
    case truncatedHeader
    case wrongCredentials
    case unsupportedFeature(String)
    case corruptDatabase
}
