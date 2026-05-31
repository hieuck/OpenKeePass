import Foundation
import XCTest
@testable import KeePassCore

final class HMACTests: XCTestCase {
    func testHMACSHA256RFC4231Case1() {
        let key = Data(repeating: 0x0B, count: 20)
        let message = Data("Hi There".utf8)

        XCTAssertEqual(
            HMACSHA256.authenticate(message: message, key: key).hexEncodedLowercase(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
    }

    func testHMACSHA256RFC4231Case2() {
        let key = Data("Jefe".utf8)
        let message = Data("what do ya want for nothing?".utf8)

        XCTAssertEqual(
            HMACSHA256.authenticate(message: message, key: key).hexEncodedLowercase(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
    }
}

private extension Data {
    func hexEncodedLowercase() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
