import Foundation
import XCTest
@testable import KeePassCore

final class KDBX3BlockStreamTests: XCTestCase {
    func testReadReturnsConcatenatedVerifiedBlocks() throws {
        var stream = Data()
        stream.appendKDBX3Block(id: 0, payload: Data("hello ".utf8))
        stream.appendKDBX3Block(id: 1, payload: Data("world".utf8))
        stream.appendKDBX3Terminator(id: 2)

        let payload = try KDBX3BlockStream.read(stream)

        XCTAssertEqual(String(data: payload, encoding: .utf8), "hello world")
    }

    func testReadRejectsCorruptBlockHash() {
        var stream = Data()
        stream.appendUInt32LE(0)
        stream.append(Data(repeating: 0xA5, count: 32))
        stream.appendUInt32LE(4)
        stream.append(Data("test".utf8))
        stream.appendKDBX3Terminator(id: 1)

        XCTAssertThrowsError(try KDBX3BlockStream.read(stream)) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}

private extension Data {
    mutating func appendKDBX3Block(id: UInt32, payload: Data) {
        appendUInt32LE(id)
        append(SHA256.hash(payload))
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }

    mutating func appendKDBX3Terminator(id: UInt32) {
        appendUInt32LE(id)
        append(Data(repeating: 0, count: 32))
        appendUInt32LE(0)
    }

    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(value & 0x000000FF))
        append(UInt8((value & 0x0000FF00) >> 8))
        append(UInt8((value & 0x00FF0000) >> 16))
        append(UInt8((value & 0xFF000000) >> 24))
    }
}
