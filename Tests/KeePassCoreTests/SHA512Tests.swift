import Foundation
import XCTest
@testable import KeePassCore

final class SHA512Tests: XCTestCase {
    func testEmptyDigestMatchesKnownVector() {
        XCTAssertEqual(
            SHA512.hash(Data()).hexEncodedLowercase(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
    }

    func testABCDigestMatchesKnownVector() {
        XCTAssertEqual(
            SHA512.hash(Data("abc".utf8)).hexEncodedLowercase(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    func testLongDigestMatchesKnownVector() {
        let message = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)

        XCTAssertEqual(
            SHA512.hash(message).hexEncodedLowercase(),
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335" +
            "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        )
    }
}

private extension Data {
    func hexEncodedLowercase() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
