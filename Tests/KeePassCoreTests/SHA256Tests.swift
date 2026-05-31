import Foundation
import XCTest
@testable import KeePassCore

final class SHA256Tests: XCTestCase {
    func testEmptyDigestMatchesKnownVector() {
        XCTAssertEqual(
            SHA256.hash(Data()).hexEncodedLowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    func testABCDigestMatchesKnownVector() {
        XCTAssertEqual(
            SHA256.hash(Data("abc".utf8)).hexEncodedLowercase(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testLongDigestMatchesKnownVector() {
        let message = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)

        XCTAssertEqual(
            SHA256.hash(message).hexEncodedLowercase(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
    }
}

private extension Data {
    func hexEncodedLowercase() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
