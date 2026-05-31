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

    func testOpenReportsKDBX4PayloadParsingAsUnsupportedUntilCryptoIsImplemented() async {
        let engine = KDBX4Engine()

        do {
            _ = try await engine.open(data: .kdbxHeader(major: 4, minor: 0), credentials: .init(password: "pw"))
            XCTFail("Expected KDBX4 payload to throw until crypto is implemented")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 4 payload decryption is not implemented yet"))
        }
    }

    func testOpenWithAESKDFHeaderDerivesKeyBeforePayloadDecrypt() async {
        let engine = KDBX4Engine()
        let data = Data.kdbx4AESHeader()

        do {
            _ = try await engine.open(data: data, credentials: .init(password: "pw"))
            XCTFail("Expected payload decrypt to remain unsupported")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 4 payload decryption is not implemented yet"))
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
        plaintext.appendInnerHeaderField(id: 1, payload: Data([0x02]))
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

    func testOpenWithArgon2HeaderDerivesKeyBeforePayloadDecrypt() async {
        let engine = KDBX4Engine()
        let data = Data.kdbx4Argon2Header()

        do {
            _ = try await engine.open(data: data, credentials: .init(password: "pw"))
            XCTFail("Expected payload decrypt to remain unsupported")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDBX 4 payload decryption is not implemented yet"))
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
        payload: Data = Data()
    ) -> Data {
        kdbx4Header(kdfParameters: .variantDictionary([
            .bytes("$UUID", KDBXKDFUUID.aesKDF),
            .bytes("S", transformSeed),
            .uint64("R", 1)
        ]), masterSeed: masterSeed, cipherID: KDBXCipherID.aes256, iv: iv, payload: payload)
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
        iv: Data? = nil,
        payload: Data = Data()
    ) -> Data {
        var data = kdbxHeader(major: 4, minor: 0)
        if let cipherID {
            data.appendField(id: 2, payload: cipherID)
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
