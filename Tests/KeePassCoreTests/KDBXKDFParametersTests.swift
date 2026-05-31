import Foundation
import XCTest
@testable import KeePassCore

final class KDBXKDFParametersTests: XCTestCase {
    func testParsesAESKDFParameters() throws {
        let seed = Data(repeating: 0x11, count: 32)
        let dictionary = KDBXVariantDictionary(values: [
            "$UUID": .bytes(KDBXKDFUUID.aesKDF),
            "S": .bytes(seed),
            "R": .uint64(600_000)
        ])

        let parameters = try KDBXKDFParameters(dictionary: dictionary)

        XCTAssertEqual(parameters, .aes(seed: seed, rounds: 600_000))
    }

    func testParsesArgon2dParameters() throws {
        let salt = Data(repeating: 0x22, count: 32)
        let dictionary = KDBXVariantDictionary(values: [
            "$UUID": .bytes(KDBXKDFUUID.argon2d),
            "V": .uint32(0x13),
            "S": .bytes(salt),
            "I": .uint64(4),
            "M": .uint64(64 * 1024 * 1024),
            "P": .uint32(2)
        ])

        let parameters = try KDBXKDFParameters(dictionary: dictionary)

        XCTAssertEqual(
            parameters,
            .argon2(
                variant: .argon2d,
                version: 0x13,
                salt: salt,
                iterations: 4,
                memory: 64 * 1024 * 1024,
                parallelism: 2
            )
        )
    }

    func testParsesArgon2idParameters() throws {
        let salt = Data(repeating: 0x33, count: 32)
        let dictionary = KDBXVariantDictionary(values: [
            "$UUID": .bytes(KDBXKDFUUID.argon2id),
            "V": .uint32(0x13),
            "S": .bytes(salt),
            "I": .uint64(3),
            "M": .uint64(32 * 1024 * 1024),
            "P": .uint32(1)
        ])

        let parameters = try KDBXKDFParameters(dictionary: dictionary)

        XCTAssertEqual(
            parameters,
            .argon2(
                variant: .argon2id,
                version: 0x13,
                salt: salt,
                iterations: 3,
                memory: 32 * 1024 * 1024,
                parallelism: 1
            )
        )
    }

    func testRejectsMissingUUID() {
        XCTAssertThrowsError(try KDBXKDFParameters(dictionary: KDBXVariantDictionary(values: [:]))) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }

    func testRejectsUnknownKDFUUID() {
        let dictionary = KDBXVariantDictionary(values: [
            "$UUID": .bytes(Data(repeating: 0xFF, count: 16))
        ])

        XCTAssertThrowsError(try KDBXKDFParameters(dictionary: dictionary)) { error in
            XCTAssertEqual(error as? KDBXError, .unsupportedFeature("KDF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is not supported"))
        }
    }
}
