import Foundation

public enum KDBXCipherID {
    public static let aes256 = Data([
        0x31, 0xC1, 0xF2, 0xE6,
        0xBF, 0x71,
        0x43, 0x50,
        0xBE, 0x58,
        0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF
    ])
}

public enum KDBXPayloadDecryptor {
    public static func decrypt(ciphertext: Data, cipherID: Data, finalKey: Data, encryptionIV: Data) throws -> Data {
        switch cipherID {
        case KDBXCipherID.aes256:
            return try AES256(key: finalKey).decryptCBCPKCS7(ciphertext, iv: encryptionIV)
        default:
            throw KDBXError.unsupportedFeature("Cipher \(cipherID.hexEncodedUppercase()) is not supported")
        }
    }
}
