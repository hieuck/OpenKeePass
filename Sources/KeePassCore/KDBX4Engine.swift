import Foundation

public struct KDBX4Engine: KDBXEngine {
    public init() {}

    public func open(data: Data, credentials: KDBXCredentials) async throws -> KeePassVault {
        let header = try KDBXHeader.parse(data)
        if header.majorVersion == 3 {
            return try openKDBX3(data: data, header: header, credentials: credentials)
        }
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
            let innerHeader = try KDBX4InnerHeader.parse(decryptedPayload)
            let xml = try KDBXPayloadCompression.decode(innerHeader.body, compression: header.compression)
            return try KeePassXMLParser.parse(xml, protectedStream: innerHeader.protectedStream)
        }

        throw KDBXError.unsupportedFeature("KDBX 4 payload is incomplete or unsupported")
    }

    private func openKDBX3(data: Data, header: KDBXHeader, credentials: KDBXCredentials) throws -> KeePassVault {
        guard
            let masterSeed = header.masterSeed,
            let transformSeed = header.transformSeed,
            let transformRounds = header.transformRounds,
            let cipherID = header.cipherID,
            let encryptionIV = header.encryptionIV,
            let streamStartBytes = header.streamStartBytes
        else {
            throw KDBXError.corruptDatabase
        }

        let compositeKey = try KDBXCompositeKey.material(from: credentials)
        let transformedKey = try KDBXKeyDerivation.transform(
            compositeKey: compositeKey,
            parameters: .aes(seed: transformSeed, rounds: transformRounds)
        )
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformedKey)
        let encryptedPayload = Data(data.suffix(from: header.headerByteCount))
        let decryptedPayload = try KDBXPayloadDecryptor.decrypt(
            ciphertext: encryptedPayload,
            cipherID: cipherID,
            finalKey: finalKey,
            encryptionIV: encryptionIV
        )

        guard decryptedPayload.starts(with: streamStartBytes) else {
            throw KDBXError.wrongCredentials
        }

        let payload = decryptedPayload.subdata(in: streamStartBytes.count..<decryptedPayload.count)
        let body = KDBX3BlockStream.isLikelyUnwrappedPayload(payload) ? payload : try KDBX3BlockStream.read(payload)
        let xml = try KDBXPayloadCompression.decode(body, compression: header.compression)
        return try KeePassXMLParser.parse(xml, protectedStream: protectedStream(for: header))
    }

    private func protectedStream(for header: KDBXHeader) throws -> KDBX4InnerHeader.ProtectedStream? {
        guard let streamID = header.innerRandomStreamID, streamID != 0 else {
            return nil
        }
        guard let key = header.protectedStreamKey else {
            throw KDBXError.corruptDatabase
        }

        switch streamID {
        case 2:
            return KDBX4InnerHeader.ProtectedStream(algorithm: .salsa20, key: SHA256.hash(key))
        default:
            throw KDBXError.unsupportedFeature("Inner stream algorithm \(streamID) is not supported")
        }
    }

    public func create(name: String, credentials: KDBXCredentials) async throws -> KeePassVault {
        KeePassVault(
            id: UUID(),
            name: name,
            root: KeePassGroup(id: UUID(), title: "Root", groups: [], entries: [])
        )
    }

    public func save(vault: KeePassVault, credentials: KDBXCredentials) async throws -> Data {
        let masterSeed = randomData(count: 32)
        let transformSeed = randomData(count: 32)
        let encryptionIV = randomData(count: 16)
        let innerKey = randomData(count: 64)
        let kdfParameters = KDBXKDFParameters.aes(seed: transformSeed, rounds: 10_000)
        let compositeKey = try KDBXCompositeKey.material(from: credentials)
        let transformedKey = try KDBXKeyDerivation.transform(compositeKey: compositeKey, parameters: kdfParameters)
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformedKey)

        var plaintext = Data()
        var innerAlgorithm = Data()
        innerAlgorithm.appendUInt32LE(3)
        plaintext.appendKDBXField(id: 1, payload: innerAlgorithm)
        plaintext.appendKDBXField(id: 2, payload: innerKey)
        plaintext.appendKDBXField(id: 0, payload: Data())
        plaintext.append(try serializeXML(vault: vault, innerKey: innerKey))

        let paddingLength = 16 - (plaintext.count % 16)
        let paddedPlaintext = plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength)
        let ciphertext = try AES256(key: finalKey).encryptCBC(paddedPlaintext, iv: encryptionIV)

        var data = header(
            masterSeed: masterSeed,
            transformSeed: transformSeed,
            rounds: 10_000,
            encryptionIV: encryptionIV
        )
        let headerBytes = data
        data.append(SHA256.hash(headerBytes))
        data.append(HMACSHA256.authenticate(
            message: headerBytes,
            key: KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformedKey)
        ))
        data.appendKDBX4Block(index: 0, payload: ciphertext) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformedKey)
        }
        data.appendKDBX4Block(index: 1, payload: Data()) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformedKey)
        }
        return data
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

    private func header(masterSeed: Data, transformSeed: Data, rounds: UInt64, encryptionIV: Data) -> Data {
        var data = Data([
            0x03, 0xD9, 0xA2, 0x9A,
            0x67, 0xFB, 0x4B, 0xB5,
            0x00, 0x00,
            0x04, 0x00
        ])
        data.appendKDBXField(id: 2, payload: KDBXCipherID.aes256)
        var compression = Data()
        compression.appendUInt32LE(0)
        data.appendKDBXField(id: 3, payload: compression)
        data.appendKDBXField(id: 4, payload: masterSeed)
        data.appendKDBXField(id: 7, payload: encryptionIV)
        data.appendKDBXField(id: 11, payload: variantDictionary([
            .bytes("$UUID", KDBXKDFUUID.aesKDF),
            .bytes("S", transformSeed),
            .uint64("R", rounds)
        ]))
        data.appendKDBXField(id: 0, payload: Data())
        return data
    }

    private func variantDictionary(_ items: [VariantItem]) -> Data {
        var data = Data([0x00, 0x01])
        for item in items {
            switch item {
            case .bytes(let key, let value):
                data.appendVariantItem(type: 0x42, key: key, value: value)
            case .uint64(let key, let value):
                var payload = Data()
                payload.appendUInt64LE(value)
                data.appendVariantItem(type: 0x05, key: key, value: payload)
            }
        }
        data.append(0x00)
        return data
    }

    private func serializeXML(vault: KeePassVault, innerKey: Data) throws -> Data {
        var stream = try ChaCha20Stream.protectedValueStream(innerKey: innerKey)
        var xml = """
        <KeePassFile>
          <Meta><DatabaseName>\(encodeXML(vault.name))</DatabaseName></Meta>
          <Root>
        """
        xml.append(try serializeGroup(vault.root, indent: "    ", stream: &stream))
        xml.append("""
          </Root>
        </KeePassFile>
        """)
        return Data(xml.utf8)
    }

    private func serializeGroup(_ group: KeePassGroup, indent: String, stream: inout ChaCha20Stream) throws -> String {
        var xml = """
        \(indent)<Group>
        \(indent)  <UUID>\(group.id.kdbxBase64String)</UUID>
        \(indent)  <Name>\(encodeXML(group.title))</Name>
        """
        for child in group.groups {
            xml.append(try serializeGroup(child, indent: indent + "  ", stream: &stream))
        }
        for entry in group.entries {
            xml.append(try serializeEntry(entry, indent: indent + "  ", stream: &stream))
        }
        xml.append("\(indent)</Group>\n")
        return xml
    }

    private func serializeEntry(_ entry: KeePassEntry, indent: String, stream: inout ChaCha20Stream) throws -> String {
        var xml = """
        \(indent)<Entry>
        \(indent)  <UUID>\(entry.id.kdbxBase64String)</UUID>
        """
        xml.append(try serializeField(name: "Title", value: entry.title, isProtected: false, indent: indent + "  ", stream: &stream))
        xml.append(try serializeField(name: "UserName", value: entry.username, isProtected: false, indent: indent + "  ", stream: &stream))
        xml.append(try serializeField(name: "Password", value: entry.password, isProtected: true, indent: indent + "  ", stream: &stream))
        xml.append(try serializeField(name: "URL", value: entry.url, isProtected: false, indent: indent + "  ", stream: &stream))
        xml.append(try serializeField(name: "Notes", value: entry.notes, isProtected: false, indent: indent + "  ", stream: &stream))
        for field in entry.customFields.sorted(by: { $0.name < $1.name }) {
            xml.append(try serializeField(name: field.name, value: field.value, isProtected: field.isProtected, indent: indent + "  ", stream: &stream))
        }
        for attachment in entry.attachments.sorted(by: { $0.name < $1.name }) {
            xml.append(serializeAttachment(attachment, indent: indent + "  "))
        }
        xml.append("\(indent)</Entry>\n")
        return xml
    }

    private func serializeAttachment(_ attachment: KeePassAttachment, indent: String) -> String {
        let protectedAttribute = attachment.isProtected ? " Protected=\"True\"" : ""
        return """
        \(indent)<Binary><Key>\(encodeXML(attachment.name))</Key><Value\(protectedAttribute)>\(attachment.data.base64EncodedString())</Value></Binary>
        """
    }

    private func serializeField(
        name: String,
        value: String,
        isProtected: Bool,
        indent: String,
        stream: inout ChaCha20Stream
    ) throws -> String {
        let encodedValue: String
        let protectedAttribute: String
        if isProtected {
            encodedValue = try stream.apply(to: Data(value.utf8)).base64EncodedString()
            protectedAttribute = " Protected=\"True\""
        } else {
            encodedValue = encodeXML(value)
            protectedAttribute = ""
        }

        return """
        \(indent)<String><Key>\(encodeXML(name))</Key><Value\(protectedAttribute)>\(encodedValue)</Value></String>
        """
    }

    private func encodeXML(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    private func randomData(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
    }
}

private enum VariantItem {
    case bytes(String, Data)
    case uint64(String, UInt64)
}

private extension UUID {
    var kdbxBase64String: String {
        let uuid = uuid
        return Data([
            uuid.0, uuid.1, uuid.2, uuid.3,
            uuid.4, uuid.5,
            uuid.6, uuid.7,
            uuid.8, uuid.9,
            uuid.10, uuid.11, uuid.12, uuid.13, uuid.14, uuid.15
        ]).base64EncodedString()
    }
}

private extension Data {
    mutating func appendKDBXField(id: UInt8, payload: Data) {
        append(id)
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }

    mutating func appendVariantItem(type: UInt8, key: String, value: Data) {
        append(type)
        let keyData = Data(key.utf8)
        appendUInt32LE(UInt32(keyData.count))
        append(keyData)
        appendUInt32LE(UInt32(value.count))
        append(value)
    }

    mutating func appendKDBX4Block(index: UInt64, payload: Data, keyProvider: (UInt64) -> Data) {
        append(HMACSHA256.authenticate(message: hmacMessage(index: index, payload: payload), key: keyProvider(index)))
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }

    private func hmacMessage(index: UInt64, payload: Data) -> Data {
        var message = Data()
        message.appendUInt64LE(index)
        message.appendUInt32LE(UInt32(payload.count))
        message.append(payload)
        return message
    }

    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(value & 0x000000FF))
        append(UInt8((value & 0x0000FF00) >> 8))
        append(UInt8((value & 0x00FF0000) >> 16))
        append(UInt8((value & 0xFF000000) >> 24))
    }

    mutating func appendUInt64LE(_ value: UInt64) {
        append(UInt8(value & 0x00000000000000FF))
        append(UInt8((value & 0x000000000000FF00) >> 8))
        append(UInt8((value & 0x0000000000FF0000) >> 16))
        append(UInt8((value & 0x00000000FF000000) >> 24))
        append(UInt8((value & 0x000000FF00000000) >> 32))
        append(UInt8((value & 0x0000FF0000000000) >> 40))
        append(UInt8((value & 0x00FF000000000000) >> 48))
        append(UInt8((value & 0xFF00000000000000) >> 56))
    }
}
