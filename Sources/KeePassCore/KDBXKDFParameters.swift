import Foundation

public enum KDBXArgon2Variant: Equatable, Sendable {
    case argon2d
    case argon2id
}

public enum KDBXKDFParameters: Equatable, Sendable {
    case aes(seed: Data, rounds: UInt64)
    case argon2(
        variant: KDBXArgon2Variant,
        version: UInt32,
        salt: Data,
        iterations: UInt64,
        memory: UInt64,
        parallelism: UInt32
    )

    public init(dictionary: KDBXVariantDictionary) throws {
        guard case .bytes(let uuid)? = dictionary["$UUID"] else {
            throw KDBXError.corruptDatabase
        }

        switch uuid {
        case KDBXKDFUUID.aesKDF:
            guard case .bytes(let seed)? = dictionary["S"],
                  case .uint64(let rounds)? = dictionary["R"] else {
                throw KDBXError.corruptDatabase
            }
            self = .aes(seed: seed, rounds: rounds)
        case KDBXKDFUUID.argon2d:
            self = try KDBXKDFParameters.argon2(variant: .argon2d, dictionary: dictionary)
        case KDBXKDFUUID.argon2id:
            self = try KDBXKDFParameters.argon2(variant: .argon2id, dictionary: dictionary)
        default:
            throw KDBXError.unsupportedFeature("KDF \(uuid.hexEncodedUppercase()) is not supported")
        }
    }

    private static func argon2(variant: KDBXArgon2Variant, dictionary: KDBXVariantDictionary) throws -> KDBXKDFParameters {
        guard case .uint32(let version)? = dictionary["V"],
              case .bytes(let salt)? = dictionary["S"],
              case .uint64(let iterations)? = dictionary["I"],
              case .uint64(let memory)? = dictionary["M"],
              case .uint32(let parallelism)? = dictionary["P"] else {
            throw KDBXError.corruptDatabase
        }

        return .argon2(
            variant: variant,
            version: version,
            salt: salt,
            iterations: iterations,
            memory: memory,
            parallelism: parallelism
        )
    }
}

public enum KDBXKDFUUID {
    public static let aesKDF = Data([
        0xC9, 0xD9, 0xF3, 0x9A,
        0x62, 0x8A,
        0x44, 0x60,
        0xBF, 0x74,
        0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA
    ])

    public static let argon2d = Data([
        0xEF, 0x63, 0x6D, 0xDF,
        0x8C, 0x29,
        0x44, 0x4B,
        0x91, 0xF7,
        0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C
    ])

    public static let argon2id = Data([
        0x9E, 0x29, 0x8B, 0x19,
        0x56, 0xDB,
        0x47, 0x73,
        0xB2, 0x3D,
        0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6
    ])
}
