import Foundation
import XCTest
@testable import KeePassCore

final class KDBXCompositeKeyTests: XCTestCase {
    func testPasswordOnlyCompositeKeyIsHashOfPasswordHash() throws {
        let credentials = KDBXCredentials(password: "correct horse battery staple")
        let passwordHash = SHA256.hash(Data(credentials.password.utf8))

        XCTAssertEqual(try KDBXCompositeKey.material(from: credentials), SHA256.hash(passwordHash))
    }

    func testPasswordAndKeyFileCompositeKeyHashesComponentHashesInOrder() throws {
        let keyFile = Data(repeating: 0x44, count: 32)
        let credentials = KDBXCredentials(password: "pw", keyFileData: keyFile)
        var expectedInput = Data()
        expectedInput.append(SHA256.hash(Data("pw".utf8)))
        expectedInput.append(keyFile)

        XCTAssertEqual(try KDBXCompositeKey.material(from: credentials), SHA256.hash(expectedInput))
    }

    func testEmptyPasswordWithoutKeyFileIsRejected() {
        XCTAssertThrowsError(try KDBXCompositeKey.material(from: .init(password: ""))) { error in
            XCTAssertEqual(error as? KDBXError, .wrongCredentials)
        }
    }
}
