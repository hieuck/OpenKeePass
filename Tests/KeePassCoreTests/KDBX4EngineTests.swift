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

    func testOpenWithArgon2HeaderReportsKDFUnsupported() async {
        let engine = KDBX4Engine()
        let data = Data.kdbx4Argon2Header()

        do {
            _ = try await engine.open(data: data, credentials: .init(password: "pw"))
            XCTFail("Expected Argon2 KDF to remain unsupported")
        } catch {
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("Argon2 KDF is not implemented yet"))
        }
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

    static func kdbx4AESHeader() -> Data {
        kdbx4Header(kdfParameters: .variantDictionary([
            .bytes("$UUID", KDBXKDFUUID.aesKDF),
            .bytes("S", Data(repeating: 0x01, count: 32)),
            .uint64("R", 1)
        ]))
    }

    static func kdbx4Argon2Header() -> Data {
        kdbx4Header(kdfParameters: .variantDictionary([
            .bytes("$UUID", KDBXKDFUUID.argon2id),
            .uint32("V", 0x13),
            .bytes("S", Data(repeating: 0x02, count: 32)),
            .uint64("I", 2),
            .uint64("M", 1024),
            .uint32("P", 1)
        ]))
    }

    static func kdbx4Header(kdfParameters: Data) -> Data {
        var data = kdbxHeader(major: 4, minor: 0)
        data.appendField(id: 4, payload: Data(repeating: 0xA5, count: 32))
        data.appendField(id: 11, payload: kdfParameters)
        data.appendField(id: 0, payload: Data())
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
}

private enum VariantFixture {
    case bytes(String, Data)
    case uint32(String, UInt32)
    case uint64(String, UInt64)
}
