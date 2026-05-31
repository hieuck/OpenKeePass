import Foundation
import XCTest
@testable import KeePassCore

final class KDBXVariantDictionaryTests: XCTestCase {
    func testParsesCommonVariantTypes() throws {
        let uuid = Data([0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C])
        let seed = Data(repeating: 0x42, count: 32)
        let data = Data.variantDictionary([
            .bytes("$UUID", uuid),
            .uint64("I", 12),
            .uint64("M", UInt64(64 * 1024 * 1024)),
            .uint32("P", 2),
            .bytes("S", seed),
            .bool("B", true),
            .string("Name", "Argon2id")
        ])

        let dictionary = try KDBXVariantDictionary.parse(data)

        XCTAssertEqual(dictionary["$UUID"], KDBXVariantValue.bytes(uuid))
        XCTAssertEqual(dictionary["I"], KDBXVariantValue.uint64(12))
        XCTAssertEqual(dictionary["M"], KDBXVariantValue.uint64(UInt64(64 * 1024 * 1024)))
        XCTAssertEqual(dictionary["P"], KDBXVariantValue.uint32(2))
        XCTAssertEqual(dictionary["S"], KDBXVariantValue.bytes(seed))
        XCTAssertEqual(dictionary["B"], KDBXVariantValue.bool(true))
        XCTAssertEqual(dictionary["Name"], KDBXVariantValue.string("Argon2id"))
    }

    func testRejectsInvalidVersion() {
        XCTAssertThrowsError(try KDBXVariantDictionary.parse(Data([0x00, 0x00]))) { error in
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("Variant dictionary version 0.0 is not supported"))
        }
    }

    func testRejectsTruncatedItem() {
        XCTAssertThrowsError(try KDBXVariantDictionary.parse(Data([0x00, 0x01, 0x42]))) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}

private enum VariantFixture {
    case bytes(String, Data)
    case uint32(String, UInt32)
    case uint64(String, UInt64)
    case bool(String, Bool)
    case string(String, String)
}

private extension Data {
    static func variantDictionary(_ items: [VariantFixture]) -> Data {
        var data = Data([0x00, 0x01])
        for item in items {
            switch item {
            case .bytes(let key, let value):
                data.appendItem(type: 0x42, key: key, value: value)
            case .uint32(let key, let value):
                var payload = Data()
                payload.appendVariantUInt32LE(value)
                data.appendItem(type: 0x04, key: key, value: payload)
            case .uint64(let key, let value):
                var payload = Data()
                payload.appendUInt64LE(value)
                data.appendItem(type: 0x05, key: key, value: payload)
            case .bool(let key, let value):
                data.appendItem(type: 0x08, key: key, value: Data([value ? 1 : 0]))
            case .string(let key, let value):
                data.appendItem(type: 0x0C, key: key, value: Data(value.utf8))
            }
        }
        data.append(0x00)
        return data
    }

    mutating func appendItem(type: UInt8, key: String, value: Data) {
        let keyData = Data(key.utf8)
        append(type)
        appendVariantUInt32LE(UInt32(keyData.count))
        append(keyData)
        appendVariantUInt32LE(UInt32(value.count))
        append(value)
    }

    mutating func appendVariantUInt32LE(_ value: UInt32) {
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
