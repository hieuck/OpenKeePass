import Foundation
import XCTest
@testable import KeePassCore

final class KDBX4BlockStreamTests: XCTestCase {
    func testReadsAndVerifiesMultipleBlocks() throws {
        let key0 = Data("block-0-key".utf8)
        let key1 = Data("block-1-key".utf8)
        let key2 = Data("block-2-key".utf8)
        var stream = Data()
        stream.appendKDBX4Block(index: 0, payload: Data("hello ".utf8), key: key0)
        stream.appendKDBX4Block(index: 1, payload: Data("vault".utf8), key: key1)
        stream.appendKDBX4Block(index: 2, payload: Data(), key: key2)

        let payload = try KDBX4BlockStream.read(stream) { index in
            [key0, key1, key2][Int(index)]
        }

        XCTAssertEqual(String(data: payload, encoding: .utf8), "hello vault")
    }

    func testRejectsInvalidBlockHMAC() throws {
        let key = Data("block-key".utf8)
        var stream = Data()
        stream.appendKDBX4Block(index: 0, payload: Data("payload".utf8), key: key)
        stream[0] ^= 0xFF

        XCTAssertThrowsError(try KDBX4BlockStream.read(stream) { _ in key }) { error in
            XCTAssertEqual(error as? KDBXError, .wrongCredentials)
        }
    }

    func testRejectsTruncatedBlockPayload() {
        let key = Data("block-key".utf8)
        var stream = Data()
        stream.appendKDBX4Block(index: 0, payload: Data("payload".utf8), key: key)
        stream.removeLast()

        XCTAssertThrowsError(try KDBX4BlockStream.read(stream) { _ in key }) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }

    func testRejectsTrailingBytesAfterTerminator() {
        let key = Data("block-key".utf8)
        var stream = Data()
        stream.appendKDBX4Block(index: 0, payload: Data(), key: key)
        stream.append(0xAA)

        XCTAssertThrowsError(try KDBX4BlockStream.read(stream) { _ in key }) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}

private extension Data {
    mutating func appendKDBX4Block(index: UInt64, payload: Data, key: Data) {
        var message = Data()
        message.appendUInt64LE(index)
        message.appendUInt32LE(UInt32(payload.count))
        message.append(payload)

        append(HMACSHA256.authenticate(message: message, key: key))
        appendUInt32LE(UInt32(payload.count))
        append(payload)
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
