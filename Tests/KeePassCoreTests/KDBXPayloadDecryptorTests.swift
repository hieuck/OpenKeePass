import Foundation
import XCTest
@testable import KeePassCore

final class KDBXPayloadDecryptorTests: XCTestCase {
    func testDecryptsAESCBCPayload() throws {
        let key = Data(hexPayload: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        let iv = Data(repeating: 0, count: 16)
        let plaintext = Data("payload xml".utf8)
        let paddingLength = 16 - (plaintext.count % 16)
        let padded = plaintext + Data(repeating: UInt8(paddingLength), count: paddingLength)
        let ciphertext = try AES256(key: key).encryptCBC(padded, iv: iv)

        let decrypted = try KDBXPayloadDecryptor.decrypt(
            ciphertext: ciphertext,
            cipherID: KDBXCipherID.aes256,
            finalKey: key,
            encryptionIV: iv
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    func testRejectsUnknownCipher() {
        XCTAssertThrowsError(
            try KDBXPayloadDecryptor.decrypt(
                ciphertext: Data(repeating: 0, count: 16),
                cipherID: Data(repeating: 0xFF, count: 16),
                finalKey: Data(repeating: 0, count: 32),
                encryptionIV: Data(repeating: 0, count: 16)
            )
        ) { error in
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("Cipher FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is not supported"))
        }
    }
}

private extension Data {
    init(hexPayload: String) {
        self.init()
        var index = hexPayload.startIndex
        while index < hexPayload.endIndex {
            let next = hexPayload.index(index, offsetBy: 2)
            append(UInt8(hexPayload[index..<next], radix: 16)!)
            index = next
        }
    }
}
