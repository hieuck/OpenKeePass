import Foundation
import XCTest
@testable import KeePassCore

final class KDBXHeaderTests: XCTestCase {
    func testParsesKDBX4SignatureAndVersion() throws {
        let data = Data([
            0x03, 0xD9, 0xA2, 0x9A,
            0x67, 0xFB, 0x4B, 0xB5,
            0x00, 0x00, 0x04, 0x00
        ])

        let header = try KDBXHeader.parse(data)

        XCTAssertEqual(header.fileSignature, .kdbx)
        XCTAssertEqual(header.majorVersion, 4)
        XCTAssertEqual(header.minorVersion, 0)
    }

    func testParsesKDBX3SignatureAndVersion() throws {
        let data = Data([
            0x03, 0xD9, 0xA2, 0x9A,
            0x67, 0xFB, 0x4B, 0xB5,
            0x01, 0x00, 0x03, 0x00
        ])

        let header = try KDBXHeader.parse(data)

        XCTAssertEqual(header.fileSignature, .kdbx)
        XCTAssertEqual(header.majorVersion, 3)
        XCTAssertEqual(header.minorVersion, 1)
    }

    func testRejectsTooShortHeader() {
        XCTAssertThrowsError(try KDBXHeader.parse(Data([0x03, 0xD9]))) { error in
            XCTAssertEqual(error as? KDBXError, .truncatedHeader)
        }
    }

    func testRejectsWrongSignature() {
        let data = Data(repeating: 0x00, count: 12)

        XCTAssertThrowsError(try KDBXHeader.parse(data)) { error in
            XCTAssertEqual(error as? KDBXError, .notKeePassDatabase)
        }
    }
}
