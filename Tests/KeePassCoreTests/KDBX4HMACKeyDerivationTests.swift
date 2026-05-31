import Foundation
import XCTest
@testable import KeePassCore

final class KDBX4HMACKeyDerivationTests: XCTestCase {
    func testDerivesHeaderHMACKey() {
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformedKey = Data(repeating: 0x11, count: 32)

        XCTAssertEqual(
            KDBX4HMACKeyDerivation.headerKey(masterSeed: masterSeed, transformedKey: transformedKey).hexEncodedLowercase(),
            "a0d040e52efbc113b68d9cb5a38ea4240f1a516706af81d1955ceeb9c5eea47e" +
            "9806a08a903d337e83c24240a3cf4af4fbbe11b6eb7b506ac88016f68bbbbadb"
        )
    }

    func testDerivesDistinctBlockHMACKeys() {
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformedKey = Data(repeating: 0x11, count: 32)

        XCTAssertEqual(
            KDBX4HMACKeyDerivation.blockKey(index: 0, masterSeed: masterSeed, transformedKey: transformedKey).hexEncodedLowercase(),
            "7e5d298a6dede6e073c7ce47877d938dee6e8e630f3bb8487c56ddbb7a51b4a" +
            "1c7a126702f10ca64264721c9ec3f3f75be16eb0da50d67eceed5c3ebd39c7718"
        )
        XCTAssertEqual(
            KDBX4HMACKeyDerivation.blockKey(index: 1, masterSeed: masterSeed, transformedKey: transformedKey).hexEncodedLowercase(),
            "5cd86c3cab522e0b51dfa7cb1791103d9e859e9d5d63dc472ed104137e749578" +
            "c794cdd09c0ba0caf28d4596c897c4a1fa2ea7ad843d69b4d42a9b005a7ec396"
        )
    }
}

private extension Data {
    func hexEncodedLowercase() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
