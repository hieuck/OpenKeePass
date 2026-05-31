import Foundation
import XCTest
@testable import KeePassCore

final class KDBXKeyFileTests: XCTestCase {
    func testUsesRaw32ByteKeyFileAsKey() throws {
        let key = Data(repeating: 0x7A, count: 32)

        XCTAssertEqual(try KDBXKeyFile.parse(key).keyData, key)
    }

    func testParses64CharacterHexKeyFile() throws {
        let hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"

        XCTAssertEqual(try KDBXKeyFile.parse(Data(hex.utf8)).keyData, Data(0...31))
    }

    func testParsesXMLV2KeyFileAndValidatesHashPrefix() throws {
        let key = Data(0...31)
        let hashPrefix = SHA256.hash(key).prefix(4).hexEncodedUppercase()
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeyFile>
            <Meta>
                <Version>2.0</Version>
            </Meta>
            <Key>
                <Data Hash="\(hashPrefix)">\(key.base64EncodedString())</Data>
            </Key>
        </KeyFile>
        """

        XCTAssertEqual(try KDBXKeyFile.parse(Data(xml.utf8)).keyData, key)
    }

    func testRejectsXMLV2KeyFileWithWrongHashPrefix() {
        let key = Data(0...31)
        let xml = """
        <KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="00000000">\(key.base64EncodedString())</Data></Key></KeyFile>
        """

        XCTAssertThrowsError(try KDBXKeyFile.parse(Data(xml.utf8))) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }

    func testHashesArbitraryKeyFileContent() throws {
        let content = Data("not a structured key file".utf8)

        XCTAssertEqual(try KDBXKeyFile.parse(content).keyData, SHA256.hash(content))
    }
}

private extension Data {
    func hexEncodedUppercase() -> String {
        map { String(format: "%02X", $0) }.joined()
    }
}
