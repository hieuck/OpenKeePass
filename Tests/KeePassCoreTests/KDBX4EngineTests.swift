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
}
