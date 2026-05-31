import Foundation
import XCTest
@testable import KeePassCore

final class ChaCha20Tests: XCTestCase {
    func testRFC8439BlockFunctionVector() throws {
        let key = Data(0x00...0x1F)
        let nonce = Data([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00])
        let stream = try ChaCha20(key: key, nonce: nonce, initialCounter: 1)
            .apply(to: Data(repeating: 0, count: 64))

        XCTAssertEqual(
            stream.hexEncodedLowercase(),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        )
    }

    func testStatefulStreamMatchesOneShotCipher() throws {
        let key = Data(0x00...0x1F)
        let nonce = Data([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00])
        let message = Data("first-second-third".utf8)
        let oneShot = try ChaCha20(key: key, nonce: nonce, initialCounter: 1).apply(to: message)
        var stream = try ChaCha20Stream(key: key, nonce: nonce, initialCounter: 1)
        var chunked = Data()

        chunked.append(try stream.apply(to: message.prefix(5)))
        chunked.append(try stream.apply(to: message.dropFirst(5).prefix(7)))
        chunked.append(try stream.apply(to: message.dropFirst(12)))

        XCTAssertEqual(chunked, oneShot)
    }
}

private extension Data {
    func hexEncodedLowercase() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
