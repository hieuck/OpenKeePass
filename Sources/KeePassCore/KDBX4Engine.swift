import Foundation

public struct KDBX4Engine: KDBXEngine {
    public init() {}

    public func open(data: Data, credentials: KDBXCredentials) async throws -> KeePassVault {
        let header = try KDBXHeader.parse(data)
        guard header.majorVersion == 4 else {
            throw KDBXError.unsupportedFeature("KDBX \(header.majorVersion).\(header.minorVersion) is not supported by KDBX4Engine")
        }

        var transformedKey: Data?
        var finalKey: Data?
        if let kdfParametersData = header.kdfParameters,
           let masterSeed = header.masterSeed {
            let dictionary = try KDBXVariantDictionary.parse(kdfParametersData)
            let kdfParameters = try KDBXKDFParameters(dictionary: dictionary)
            let compositeKey = try KDBXCompositeKey.material(from: credentials)
            transformedKey = try KDBXKeyDerivation.transform(compositeKey: compositeKey, parameters: kdfParameters)
            if let transformedKey {
                finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformedKey)
            }
        }

        let encryptedPayload = try encryptedPayload(
            in: data,
            header: header,
            masterSeed: header.masterSeed,
            transformedKey: transformedKey
        )
        if !encryptedPayload.isEmpty,
           let cipherID = header.cipherID,
           let encryptionIV = header.encryptionIV,
           let finalKey {
            let decryptedPayload = try KDBXPayloadDecryptor.decrypt(
                ciphertext: encryptedPayload,
                cipherID: cipherID,
                finalKey: finalKey,
                encryptionIV: encryptionIV
            )
            return try KeePassXMLParser.parse(try KDBX4InnerHeader.strip(from: decryptedPayload))
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

    private func encryptedPayload(
        in data: Data,
        header: KDBXHeader,
        masterSeed: Data?,
        transformedKey: Data?
    ) throws -> Data {
        let payload = Data(data.suffix(from: header.headerByteCount))
        guard payload.count >= 64,
              let masterSeed,
              let transformedKey else {
            return payload
        }

        let headerBytes = data.subdata(in: 0..<header.headerByteCount)
        let storedHeaderHash = payload.subdata(in: 0..<32)
        guard storedHeaderHash == SHA256.hash(headerBytes) else {
            return payload
        }

        let storedHeaderHMAC = payload.subdata(in: 32..<64)
        let expectedHeaderHMAC = HMACSHA256.authenticate(
            message: headerBytes,
            key: KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformedKey)
        )
        guard storedHeaderHMAC == expectedHeaderHMAC else {
            throw KDBXError.wrongCredentials
        }

        let blockStream = payload.subdata(in: 64..<payload.count)
        return try KDBX4BlockStream.read(blockStream) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformedKey)
        }
    }
}
