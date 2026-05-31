import Foundation
import XCTest
@testable import KeePassCore

final class KDBXHeaderFieldTests: XCTestCase {
    func testParsesKDBX4HeaderFieldsUntilEndMarker() throws {
        let cipherID = Data([0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF])
        let masterSeed = Data(repeating: 0xA1, count: 32)
        let encryptionIV = Data(repeating: 0xB2, count: 16)
        let kdfParameters = Data([0x00, 0x01, 0x02, 0x03])
        let data = Data.kdbx4Header(
            fields: [
                .field(id: 2, payload: cipherID),
                .field(id: 3, payload: Data([0x01, 0x00, 0x00, 0x00])),
                .field(id: 4, payload: masterSeed),
                .field(id: 7, payload: encryptionIV),
                .field(id: 11, payload: kdfParameters),
                .end
            ],
            payload: Data([0xDE, 0xAD])
        )

        let header = try KDBXHeader.parse(data)

        XCTAssertEqual(header.cipherID, cipherID)
        XCTAssertEqual(header.compression, .gzip)
        XCTAssertEqual(header.masterSeed, masterSeed)
        XCTAssertEqual(header.encryptionIV, encryptionIV)
        XCTAssertEqual(header.kdfParameters, kdfParameters)
        XCTAssertEqual(header.headerByteCount, data.count - 2)
    }

    func testRejectsTruncatedFieldLength() {
        var data = Data.kdbx4HeaderPrefix()
        data.append(2)
        data.append(contentsOf: [0x10, 0x00])

        XCTAssertThrowsError(try KDBXHeader.parse(data)) { error in
            XCTAssertEqual(error as? KDBXError, .truncatedHeader)
        }
    }

    func testRejectsFieldPayloadPastEndOfData() {
        var data = Data.kdbx4HeaderPrefix()
        data.append(2)
        data.append(contentsOf: [0x10, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x01, 0x02])

        XCTAssertThrowsError(try KDBXHeader.parse(data)) { error in
            XCTAssertEqual(error as? KDBXError, .truncatedHeader)
        }
    }

    func testRejectsKDBX4HeaderWithoutEndMarker() {
        let data = Data.kdbx4Header(
            fields: [.field(id: 4, payload: Data(repeating: 0x00, count: 32))],
            payload: Data()
        )
        let withoutEnd = data.dropLast(5)

        XCTAssertThrowsError(try KDBXHeader.parse(Data(withoutEnd))) { error in
            XCTAssertEqual(error as? KDBXError, .truncatedHeader)
        }
    }
}

private enum HeaderFieldFixture {
    case field(id: UInt8, payload: Data)
    case end
}

private extension Data {
    static func kdbx4HeaderPrefix() -> Data {
        Data([
            0x03, 0xD9, 0xA2, 0x9A,
            0x67, 0xFB, 0x4B, 0xB5,
            0x00, 0x00, 0x04, 0x00
        ])
    }

    static func kdbx4Header(fields: [HeaderFieldFixture], payload: Data) -> Data {
        var data = kdbx4HeaderPrefix()
        for field in fields {
            switch field {
            case .field(let id, let payload):
                data.append(id)
                data.appendUInt32LE(UInt32(payload.count))
                data.append(payload)
            case .end:
                data.append(0)
                data.appendUInt32LE(0)
            }
        }
        data.append(payload)
        return data
    }

    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(value & 0x000000FF))
        append(UInt8((value & 0x0000FF00) >> 8))
        append(UInt8((value & 0x00FF0000) >> 16))
        append(UInt8((value & 0xFF000000) >> 24))
    }
}
