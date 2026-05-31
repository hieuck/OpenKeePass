import Foundation

public struct KDBX4Engine: KDBXEngine {
    public init() {}

    public func open(data: Data, credentials: KDBXCredentials) async throws -> KeePassVault {
        let header = try KDBXHeader.parse(data)
        guard header.majorVersion == 4 else {
            throw KDBXError.unsupportedFeature("KDBX \(header.majorVersion).\(header.minorVersion) is not supported by KDBX4Engine")
        }

        throw KDBXError.unsupportedFeature("KDBX 4 payload decryption is not implemented yet")
    }

    public func create(name: String, credentials: KDBXCredentials) async throws -> KeePassVault {
        KeePassVault(
            id: UUID(),
            name: name,
            root: KeePassGroup(id: UUID(), title: "Root", groups: [], entries: [])
        )
    }

    public func save(vault: KeePassVault, credentials: KDBXCredentials) async throws -> Data {
        throw KDBXError.unsupportedFeature("KDBX 4 payload encryption is not implemented yet")
    }
}
