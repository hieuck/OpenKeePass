import Foundation
import XCTest
@testable import KeePassCore

final class KDBXKeyDerivationTests: XCTestCase {
    func testAESKDFZeroRoundsHashesCompositeKeyUnchanged() throws {
        let composite = Data(0..<32)
        let seed = Data(repeating: 0x55, count: 32)
        let parameters = KDBXKDFParameters.aes(seed: seed, rounds: 0)

        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: parameters)

        XCTAssertEqual(transformed, SHA256.hash(composite))
    }

    func testAESKDFOneRoundEncryptsBothCompositeKeyBlocksBeforeHashing() throws {
        let composite = Data(0..<32)
        let seed = Data(repeating: 0x01, count: 32)
        let parameters = KDBXKDFParameters.aes(seed: seed, rounds: 1)
        let aes = try AES256(key: seed)
        var encryptedBlocks = Data()
        encryptedBlocks.append(try aes.encryptBlock(composite.subdata(in: 0..<16)))
        encryptedBlocks.append(try aes.encryptBlock(composite.subdata(in: 16..<32)))

        let transformed = try KDBXKeyDerivation.transform(compositeKey: composite, parameters: parameters)

        XCTAssertEqual(transformed, SHA256.hash(encryptedBlocks))
    }

    func testFinalKeyIsHashOfMasterSeedAndTransformedKey() {
        let masterSeed = Data(repeating: 0xA5, count: 32)
        let transformed = Data(repeating: 0x5A, count: 32)
        var expectedInput = Data()
        expectedInput.append(masterSeed)
        expectedInput.append(transformed)

        XCTAssertEqual(KDBXKeyDerivation.finalKey(masterSeed: masterSeed, transformedKey: transformed), SHA256.hash(expectedInput))
    }

    func testArgon2TransformReportsUnsupportedUntilImplemented() {
        let parameters = KDBXKDFParameters.argon2(
            variant: .argon2id,
            version: 0x13,
            salt: Data(repeating: 0, count: 32),
            iterations: 2,
            memory: 1024,
            parallelism: 1
        )

        XCTAssertThrowsError(try KDBXKeyDerivation.transform(compositeKey: Data(repeating: 0, count: 32), parameters: parameters)) { error in
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("Argon2 KDF is not implemented yet"))
        }
    }
}
