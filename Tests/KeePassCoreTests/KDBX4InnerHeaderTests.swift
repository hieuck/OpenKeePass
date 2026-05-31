import Foundation
import XCTest
@testable import KeePassCore

final class KDBX4InnerHeaderTests: XCTestCase {
    func testStripsInnerHeaderAndReturnsBody() throws {
        var data = Data()
        data.appendInnerHeaderField(id: 1, payload: Data([0x02]))
        data.appendInnerHeaderField(id: 2, payload: Data(repeating: 0xA5, count: 32))
        data.appendInnerHeaderField(id: 0, payload: Data())
        data.append(Data("<KeePassFile />".utf8))

        let body = try KDBX4InnerHeader.strip(from: data)

        XCTAssertEqual(String(data: body, encoding: .utf8), "<KeePassFile />")
    }

    func testReturnsOriginalDataWhenNoInnerHeaderIsPresent() throws {
        let xml = Data("<KeePassFile />".utf8)

        XCTAssertEqual(try KDBX4InnerHeader.strip(from: xml), xml)
    }

    func testRejectsTruncatedInnerHeader() {
        var data = Data()
        data.append(1)
        data.appendUInt32LE(10)
        data.append(Data([0xAA]))

        XCTAssertThrowsError(try KDBX4InnerHeader.strip(from: data)) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}

private extension Data {
    mutating func appendInnerHeaderField(id: UInt8, payload: Data) {
        append(id)
        appendUInt32LE(UInt32(payload.count))
        append(payload)
    }

    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(value & 0x000000FF))
        append(UInt8((value & 0x0000FF00) >> 8))
        append(UInt8((value & 0x00FF0000) >> 16))
        append(UInt8((value & 0xFF000000) >> 24))
    }
}
