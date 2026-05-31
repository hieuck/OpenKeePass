import Foundation

public enum KDBXKeyDerivation {
    public static func transform(compositeKey: Data, parameters: KDBXKDFParameters) throws -> Data {
        guard compositeKey.count == 32 else {
            throw KDBXError.corruptDatabase
        }

        switch parameters {
        case .aes(let seed, let rounds):
            return try aesTransform(compositeKey: compositeKey, seed: seed, rounds: rounds)
        case .argon2:
            throw KDBXError.unsupportedFeature("Argon2 KDF is not implemented yet")
        }
    }

    public static func finalKey(masterSeed: Data, transformedKey: Data) -> Data {
        var material = Data()
        material.append(masterSeed)
        material.append(transformedKey)
        return SHA256.hash(material)
    }

    private static func aesTransform(compositeKey: Data, seed: Data, rounds: UInt64) throws -> Data {
        let aes = try AES256(key: seed)
        var transformed = compositeKey

        if rounds > 0 {
            for _ in 0..<rounds {
                let first = try aes.encryptBlock(transformed.subdata(in: 0..<16))
                let second = try aes.encryptBlock(transformed.subdata(in: 16..<32))
                transformed = first + second
            }
        }

        return SHA256.hash(transformed)
    }
}
