import Foundation
import XCTest
@testable import KeePassCore

final class KDBX4EngineTests: XCTestCase {
    func testOpenRejectsNonKeePassData() async {
        let engine = KDBX4Engine()

        do {
            _ = try await engine.open(data: Data(repeating: 0, count: 12), credentials: .init(password: "pw"))
            XCTFail("Expected non-KDBX data to throw")
        } catch {
            XCTAssertEqual(error as? KDBXError, .notKeePassDatabase)
        }
    }

    func testOpenClassifiesKDBX3AsUnsupportedForThisEngine() async {
        let engine = KDBX4Engine()

        do {
            _ = try await engine.open(data: .kdbxHeader(major: 3, minor: 1), credentials: .init(password: "pw"))
            XCTFail("Expected KDBX3 data to throw")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 3.1 is not supported by KDBX4Engine"))
        }
    }

    func testOpenReportsIncompleteKDBX4PayloadAsUnsupported() async {
        let engine = KDBX4Engine()

        do {
            _ = try await engine.open(data: .kdbxHeader(major: 4, minor: 0), credentials: .init(password: "pw"))
            XCTFail("Expected incomplete KDBX4 payload to throw")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 4 payload is incomplete or unsupported"))
        }
    }

    func testOpenWithAESKDFHeaderRejectsMissingPayload() async {
        let engine = KDBX4Engine()
        let data = Data.kdbx4AESHeader()

        do {
            _ = try await engine.open(data: data, credentials: .init(password: "pw"))
            XCTFail("Expected missing payload to throw")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 4 payload is incomplete or unsupported"))
        }
    }

    func testOpenWithAESKDFHeaderAndPayloadReturnsParsedVault() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "pw")
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformSeed = Data(repeating: 0x01, count: 32)
        let iv = Data(repeating: 0x02, count: 16)
        let composite = try KDBXCompositeKey.material(from: credentials)
        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: .aes(seed: transformSeed, rounds: 1))
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformed)
        let plaintext = Data("""
        <KeePassFile>
          <Meta><DatabaseName>Fixture</DatabaseName></Meta>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>GitHub</Value></String>
                <String><Key>UserName</Key><Value>octo</Value></String>
                <String><Key>Password</Key><Value>secret</Value></String>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """.utf8)
        let paddingLength = 16 - (plaintext.count % 16)
        let ciphertext = try AES256(key: finalKey).encryptCBC(
            plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength),
            iv: iv
        )
        let data = Data.kdbx4AESHeader(masterSeed: masterSeed, transformSeed: transformSeed, iv: iv, payload: ciphertext)

        let vault = try await engine.open(data: data, credentials: credentials)

        XCTAssertEqual(vault.name, "Fixture")
        XCTAssertEqual(vault.root.entries.first?.title, "GitHub")
        XCTAssertEqual(vault.root.entries.first?.username, "octo")
        XCTAssertEqual(vault.root.entries.first?.password, "secret")
    }

    func testOpenWithKDBX4HMACProtectedBlockStreamReturnsParsedVault() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "pw")
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformSeed = Data(repeating: 0x01, count: 32)
        let iv = Data(repeating: 0x02, count: 16)
        let composite = try KDBXCompositeKey.material(from: credentials)
        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: .aes(seed: transformSeed, rounds: 1))
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformed)
        let xml = Data("""
        <KeePassFile>
          <Meta><DatabaseName>Framed</DatabaseName></Meta>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>Mail</Value></String>
                <String><Key>UserName</Key><Value>user@example.com</Value></String>
                <String><Key>Password</Key><Value>pass</Value></String>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """.utf8)
        var plaintext = Data()
        var innerAlgorithm = Data()
        innerAlgorithm.appendUInt32LE(2)
        plaintext.appendInnerHeaderField(id: 1, payload: innerAlgorithm)
        plaintext.appendInnerHeaderField(id: 2, payload: Data(repeating: 0xA5, count: 32))
        plaintext.appendInnerHeaderField(id: 0, payload: Data())
        plaintext.append(xml)
        let paddingLength = 16 - (plaintext.count % 16)
        let ciphertext = try AES256(key: finalKey).encryptCBC(
            plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength),
            iv: iv
        )

        var framedPayload = Data()
        framedPayload.appendKDBX4Block(index: 0, payload: ciphertext) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }
        framedPayload.appendKDBX4Block(index: 1, payload: Data()) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }

        var data = Data.kdbx4AESHeader(masterSeed: masterSeed, transformSeed: transformSeed, iv: iv)
        let header = data
        data.append(SHA256.hash(header))
        data.append(HMACSHA256.authenticate(
            message: header,
            key: KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformed)
        ))
        data.append(framedPayload)

        let vault = try await engine.open(data: data, credentials: credentials)

        XCTAssertEqual(vault.name, "Framed")
        XCTAssertEqual(vault.root.entries.first?.title, "Mail")
        XCTAssertEqual(vault.root.entries.first?.username, "user@example.com")
        XCTAssertEqual(vault.root.entries.first?.password, "pass")
    }

    func testOpenWithProtectedPasswordValueReturnsDecryptedPassword() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "pw")
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformSeed = Data(repeating: 0x01, count: 32)
        let innerKey = Data(0x00...0x3F)
        var protectedStream = try ChaCha20Stream.protectedValueStream(innerKey: innerKey)
        let encryptedPassword = try protectedStream.apply(to: Data("stream-secret".utf8)).base64EncodedString()
        let iv = Data(repeating: 0x02, count: 16)
        let composite = try KDBXCompositeKey.material(from: credentials)
        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: .aes(seed: transformSeed, rounds: 1))
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformed)
        let xml = Data("""
        <KeePassFile>
          <Meta><DatabaseName>Protected</DatabaseName></Meta>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>Protected Entry</Value></String>
                <String><Key>Password</Key><Value Protected="True">\(encryptedPassword)</Value></String>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """.utf8)
        var plaintext = Data()
        var innerAlgorithm = Data()
        innerAlgorithm.appendUInt32LE(3)
        plaintext.appendInnerHeaderField(id: 1, payload: innerAlgorithm)
        plaintext.appendInnerHeaderField(id: 2, payload: innerKey)
        plaintext.appendInnerHeaderField(id: 0, payload: Data())
        plaintext.append(xml)
        let paddingLength = 16 - (plaintext.count % 16)
        let ciphertext = try AES256(key: finalKey).encryptCBC(
            plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength),
            iv: iv
        )

        var framedPayload = Data()
        framedPayload.appendKDBX4Block(index: 0, payload: ciphertext) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }
        framedPayload.appendKDBX4Block(index: 1, payload: Data()) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }

        var data = Data.kdbx4AESHeader(masterSeed: masterSeed, transformSeed: transformSeed, iv: iv)
        let header = data
        data.append(SHA256.hash(header))
        data.append(HMACSHA256.authenticate(
            message: header,
            key: KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformed)
        ))
        data.append(framedPayload)

        let vault = try await engine.open(data: data, credentials: credentials)

        XCTAssertEqual(vault.name, "Protected")
        XCTAssertEqual(vault.root.entries.first?.title, "Protected Entry")
        XCTAssertEqual(vault.root.entries.first?.password, "stream-secret")
    }

    func testOpenWithGzipCompressedKDBX4PayloadReturnsParsedVault() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "pw")
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformSeed = Data(repeating: 0x01, count: 32)
        let iv = Data(repeating: 0x02, count: 16)
        let composite = try KDBXCompositeKey.material(from: credentials)
        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: .aes(seed: transformSeed, rounds: 1))
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformed)
        let compressedXML = Data([
            0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0x8D, 0x50,
            0x4B, 0x0A, 0xC2, 0x30, 0x14, 0xDC, 0x7B, 0x8A, 0x5E, 0x40, 0xDE, 0x05,
            0x86, 0x6C, 0xFC, 0x2D, 0x8A, 0x22, 0xFE, 0x16, 0xEE, 0x9E, 0xF4, 0x21,
            0x81, 0xD6, 0x84, 0x24, 0x45, 0xEA, 0xE9, 0x4D, 0x5A, 0xAB, 0x16, 0x15,
            0xDC, 0xCD, 0x64, 0x3E, 0x8F, 0x0C, 0x72, 0x91, 0x35, 0x7B, 0x3F, 0xD7,
            0xA5, 0xA8, 0x51, 0x96, 0x61, 0x29, 0x81, 0x15, 0xA6, 0x1C, 0xF8, 0xC4,
            0x5E, 0x56, 0x5C, 0x89, 0x9A, 0x98, 0xCA, 0x3A, 0xF1, 0x5E, 0x0A, 0xD0,
            0x40, 0x00, 0xB5, 0xEE, 0x14, 0xDB, 0x18, 0x13, 0x12, 0x88, 0x70, 0xE1,
            0x4C, 0x6D, 0x3B, 0x1C, 0x59, 0x6B, 0x4C, 0x2A, 0xA8, 0x85, 0xFD, 0xFB,
            0xEC, 0x12, 0x5C, 0xD3, 0xB3, 0xC8, 0xB7, 0xC1, 0xE9, 0xCB, 0x59, 0x21,
            0x97, 0x46, 0xED, 0x74, 0x28, 0x05, 0x94, 0x20, 0x0E, 0x5C, 0xD6, 0xA2,
            0x8E, 0xDA, 0x82, 0x3A, 0x08, 0x7A, 0x58, 0xBF, 0x67, 0xF7, 0x5E, 0x5C,
            0x3A, 0x34, 0x88, 0xDF, 0xB4, 0x1D, 0xD7, 0x51, 0xF8, 0xB3, 0x23, 0x0D,
            0x72, 0x35, 0xAE, 0xF8, 0xE8, 0xB0, 0x51, 0xF8, 0xD5, 0x01, 0x7A, 0xFB,
            0x12, 0xE8, 0xB9, 0x02, 0xA8, 0xDB, 0x26, 0x95, 0xBD, 0xA6, 0xBE, 0x03,
            0xEF, 0xAF, 0xE6, 0x97, 0x78, 0x01, 0x00, 0x00
        ])
        var plaintext = Data()
        var innerAlgorithm = Data()
        innerAlgorithm.appendUInt32LE(2)
        plaintext.appendInnerHeaderField(id: 1, payload: innerAlgorithm)
        plaintext.appendInnerHeaderField(id: 2, payload: Data(repeating: 0xA5, count: 32))
        plaintext.appendInnerHeaderField(id: 0, payload: Data())
        plaintext.append(compressedXML)
        let paddingLength = 16 - (plaintext.count % 16)
        let ciphertext = try AES256(key: finalKey).encryptCBC(
            plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength),
            iv: iv
        )

        var framedPayload = Data()
        framedPayload.appendKDBX4Block(index: 0, payload: ciphertext) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }
        framedPayload.appendKDBX4Block(index: 1, payload: Data()) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }

        var data = Data.kdbx4AESHeader(masterSeed: masterSeed, transformSeed: transformSeed, iv: iv, compression: 1)
        let header = data
        data.append(SHA256.hash(header))
        data.append(HMACSHA256.authenticate(
            message: header,
            key: KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformed)
        ))
        data.append(framedPayload)

        let vault = try await engine.open(data: data, credentials: credentials)

        XCTAssertEqual(vault.name, "Compressed")
        XCTAssertEqual(vault.root.entries.first?.title, "Zip")
        XCTAssertEqual(vault.root.entries.first?.username, "zip-user")
        XCTAssertEqual(vault.root.entries.first?.password, "zip-pass")
    }

    func testOpenWithArgon2HeaderRejectsMissingPayload() async {
        let engine = KDBX4Engine()
        let data = Data.kdbx4Argon2Header()

        do {
            _ = try await engine.open(data: data, credentials: .init(password: "pw"))
            XCTFail("Expected missing payload to throw")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 4 payload is incomplete or unsupported"))
        }
    }

    func testOpenWithArgon2IDHeaderAndFramedPayloadReturnsParsedVault() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "pw")
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let argonSalt = Data(repeating: 0x02, count: 16)
        let iv = Data(repeating: 0x03, count: 16)
        let kdfParameters = KDBXKDFParameters.argon2(
            variant: .argon2id,
            version: 0x13,
            salt: argonSalt,
            iterations: 2,
            memory: 32,
            parallelism: 1
        )
        let composite = try KDBXCompositeKey.material(from: credentials)
        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: kdfParameters)
        let finalKey = KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformed)
        let plaintext = Data("""
        <KeePassFile>
          <Meta><DatabaseName>Argon Vault</DatabaseName></Meta>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>Server</Value></String>
                <String><Key>UserName</Key><Value>root</Value></String>
                <String><Key>Password</Key><Value>toor</Value></String>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """.utf8)
        let paddingLength = 16 - (plaintext.count % 16)
        let ciphertext = try AES256(key: finalKey).encryptCBC(
            plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength),
            iv: iv
        )

        var framedPayload = Data()
        framedPayload.appendKDBX4Block(index: 0, payload: ciphertext) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }
        framedPayload.appendKDBX4Block(index: 1, payload: Data()) { index in
            KDBX4HMACKeyDerivation.blockKey(index: index, masterSeed: masterSeed, transformedKey: transformed)
        }

        var data = Data.kdbx4Argon2Header(masterSeed: masterSeed, salt: argonSalt, iv: iv)
        let header = data
        data.append(SHA256.hash(header))
        data.append(HMACSHA256.authenticate(
            message: header,
            key: KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformed)
        ))
        data.append(framedPayload)

        let vault = try await engine.open(data: data, credentials: credentials)

        XCTAssertEqual(vault.name, "Argon Vault")
        XCTAssertEqual(vault.root.entries.first?.title, "Server")
        XCTAssertEqual(vault.root.entries.first?.username, "root")
        XCTAssertEqual(vault.root.entries.first?.password, "toor")
    }

    func testSaveCreatesKDBX4FileThatCanBeOpenedAgain() async throws {
        let engine = KDBX4Engine()
        let credentials = KDBXCredentials(password: "pw")
        let entryID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let groupID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let vault = KeePassVault(
            id: groupID,
            name: "Round Trip",
            root: KeePassGroup(
                id: groupID,
                title: "Root",
                groups: [
                    KeePassGroup(
                        id: UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!,
                        title: "Nested",
                        groups: [],
                        entries: []
                    )
                ],
                entries: [
                    KeePassEntry(
                        id: entryID,
                        title: "GitHub & GitLab",
                        username: "octo",
                        password: "secret<>&\"'",
                        url: "https://example.com",
                        notes: "line one\nline two",
                        customFields: [
                            KeePassField(name: "TOTP", value: "otpauth://totp/example", isProtected: true),
                            KeePassField(name: "Environment", value: "prod", isProtected: false)
                        ]
                    )
                ]
            )
        )

        let data = try await engine.save(vault: vault, credentials: credentials)
        let header = try KDBXHeader.parse(data)
        let reopened = try await engine.open(data: data, credentials: credentials)

        XCTAssertEqual(header.majorVersion, 4)
        XCTAssertEqual(reopened.name, "Round Trip")
        XCTAssertEqual(reopened.root.title, "Root")
        XCTAssertEqual(reopened.root.groups.first?.title, "Nested")
        XCTAssertEqual(reopened.root.entries.first?.title, "GitHub & GitLab")
        XCTAssertEqual(reopened.root.entries.first?.username, "octo")
        XCTAssertEqual(reopened.root.entries.first?.password, "secret<>&\"'")
        XCTAssertEqual(reopened.root.entries.first?.url, "https://example.com")
        XCTAssertEqual(reopened.root.entries.first?.notes, "line one\nline two")
        XCTAssertEqual(
            reopened.root.entries.first?.customFields,
            [
                KeePassField(name: "Environment", value: "prod", isProtected: false),
                KeePassField(name: "TOTP", value: "otpauth://totp/example", isProtected: true)
            ]
        )
    }
}

private extension Data {
    static func kdbxHeader(major: UInt16, minor: UInt16) -> Data {
        var data = Data([
            0x03, 0xD9, 0xA2, 0x9A,
            0x67, 0xFB, 0x4B, 0xB5
        ])
        data.append(UInt8(minor & 0x00FF))
        data.append(UInt8((minor & 0xFF00) >> 8))
        data.append(UInt8(major & 0x00FF))
        data.append(UInt8((major & 0xFF00) >> 8))
        return data
    }

    static func kdbx4AESHeader(
        masterSeed: Data = Data(repeating: 0xA5, count: 32),
        transformSeed: Data = Data(repeating: 0x01, count: 32),
        iv: Data = Data(repeating: 0x02, count: 16),
        compression: UInt32? = nil,
        payload: Data = Data()
    ) -> Data {
        kdbx4Header(kdfParameters: .variantDictionary([
            .bytes("$UUID", KDBXKDFUUID.aesKDF),
            .bytes("S", transformSeed),
            .uint64("R", 1)
        ]), masterSeed: masterSeed, cipherID: KDBXCipherID.aes256, compression: compression, iv: iv, payload: payload)
    }

    static func kdbx4Argon2Header(
        masterSeed: Data = Data(repeating: 0xA5, count: 32),
        salt: Data = Data(repeating: 0x02, count: 32),
        iv: Data? = nil
    ) -> Data {
        kdbx4Header(kdfParameters: .variantDictionary([
            .bytes("$UUID", KDBXKDFUUID.argon2id),
            .uint32("V", 0x13),
            .bytes("S", salt),
            .uint64("I", 2),
            .uint64("M", 32),
            .uint32("P", 1)
        ]), masterSeed: masterSeed, cipherID: KDBXCipherID.aes256, iv: iv)
    }

    static func kdbx4Header(
        kdfParameters: Data,
        masterSeed: Data = Data(repeating: 0xA5, count: 32),
        cipherID: Data? = nil,
        compression: UInt32? = nil,
        iv: Data? = nil,
        payload: Data = Data()
    ) -> Data {
        var data = kdbxHeader(major: 4, minor: 0)
        if let cipherID {
            data.appendField(id: 2, payload: cipherID)
        }
        if let compression {
            var compressionPayload = Data()
            compressionPayload.appendUInt32LE(compression)
            data.appendField(id: 3, payload: compressionPayload)
        }
        data.appendField(id: 4, payload: masterSeed)
        if let iv {
            data.appendField(id: 7, payload: iv)
        }
        data.appendField(id: 11, payload: kdfParameters)
        data.appendField(id: 0, payload: Data())
        data.append(payload)
        return data
    }

    static func variantDictionary(_ items: [VariantFixture]) -> Data {
        var data = Data([0x00, 0x01])
        for item in items {
            switch item {
            case .bytes(let key, let value):
                data.appendItem(type: 0x42, key: key, value: value)
            case .uint32(let key, let value):
                var payload = Data()
                payload.appendUInt32LE(value)
                data.appendItem(type: 0x04, key: key, value: payload)
            case .uint64(let key, let value):
                var payload = Data()
                payload.appendUInt64LE(value)
                data.appendItem(type: 0x05, key: key, value: payload)
            }
        }
        data.append(0)
        return data
    }

    mutating func appendField(id: UInt8, payload: Data) {
        append(id)
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }

    mutating func appendInnerHeaderField(id: UInt8, payload: Data) {
        append(id)
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }

    mutating func appendItem(type: UInt8, key: String, value: Data) {
        append(type)
        let keyData = Data(key.utf8)
        appendUInt32LE(UInt32(keyData.count))
        append(keyData)
        appendUInt32LE(UInt32(value.count))
        append(value)
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

    mutating func appendKDBX4Block(index: UInt64, payload: Data, keyProvider: (UInt64) -> Data) {
        var message = Data()
        message.appendUInt64LE(index)
        message.appendUInt32LE(UInt32(payload.count))
        message.append(payload)

        append(HMACSHA256.authenticate(message: message, key: keyProvider(index)))
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }
}

private enum VariantFixture {
    case bytes(String, Data)
    case uint32(String, UInt32)
    case uint64(String, UInt64)
}
