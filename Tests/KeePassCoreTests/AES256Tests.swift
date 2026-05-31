import Foundation
import XCTest
@testable import KeePassCore

final class AES256Tests: XCTestCase {
    func testEncryptsNISTAES256BlockVector() throws {
        let key = Data(hex: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        let plaintext = Data(hex: "6bc1bee22e409f96e93d7e117393172a")
        let expected = Data(hex: "f3eed1bdb5d2a03c064b5a7e3db181f8")

        XCTAssertEqual(try AES256(key: key).encryptBlock(plaintext), expected)
    }

    func testDecryptsNISTAES256BlockVector() throws {
        let key = Data(hex: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        let ciphertext = Data(hex: "f3eed1bdb5d2a03c064b5a7e3db181f8")
        let expected = Data(hex: "6bc1bee22e409f96e93d7e117393172a")

        XCTAssertEqual(try AES256(key: key).decryptBlock(ciphertext), expected)
    }

    func testDecryptsCBCPKCS7() throws {
        let key = Data(hex: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        let iv = Data(repeating: 0, count: 16)
        let plaintext = Data("KeePass payload".utf8)
        let paddingLength = 16 - (plaintext.count % 16)
        let padded = plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength)
        let encrypted = try AES256(key: key).encryptCBC(padded, iv: iv)

        XCTAssertEqual(try AES256(key: key).decryptCBCPKCS7(encrypted, iv: iv), plaintext)
    }

    func testRejectsInvalidKeySize() {
        XCTAssertThrowsError(try AES256(key: Data(repeating: 0, count: 16))) { error in
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("AES-256 requires a 32-byte key"))
        }
    }

    func testRejectsInvalidBlockSize() throws {
        let key = Data(repeating: 0, count: 32)

        XCTAssertThrowsError(try AES256(key: key).encryptBlock(Data(repeating: 0, count: 15))) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}

private extension Data {
    init(hex: String) {
        self.init()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
    }
}
