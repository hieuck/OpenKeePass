import Foundation
import CArgon2

public enum KDBXKeyDerivation {
    public static func transform(compositeKey: Data, parameters: KDBXKDFParameters) throws -> Data {
        guard compositeKey.count == 32 else {
            throw KDBXError.corruptDatabase
        }

        switch parameters {
        case .aes(let seed, let rounds):
            return try aesTransform(compositeKey: compositeKey, seed: seed, rounds: rounds)
        case .argon2(let variant, let version, let salt, let iterations, let memory, let parallelism):
            return try argon2Transform(
                compositeKey: compositeKey,
                variant: variant,
                version: version,
                salt: salt,
                iterations: iterations,
                memory: memory,
                parallelism: parallelism
            )
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

    private static func argon2Transform(
        compositeKey: Data,
        variant: KDBXArgon2Variant,
        version: UInt32,
        salt: Data,
        iterations: UInt64,
        memory: UInt64,
        parallelism: UInt32
    ) throws -> Data {
        guard iterations <= UInt64(UInt32.max), memory <= UInt64(UInt32.max) else {
            throw KDBXError.unsupportedFeature("Argon2 KDF parameters exceed supported limits")
        }

        let outputCount = 32
        var output = [UInt8](repeating: 0, count: outputCount)
        let type: argon2_type = {
            switch variant {
            case .argon2d:
                return Argon2_d
            case .argon2id:
                return Argon2_id
            }
        }()

        let code = compositeKey.withUnsafeBytes { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                output.withUnsafeMutableBytes { outputBuffer in
                    argon2_hash(
                        UInt32(iterations),
                        UInt32(memory),
                        parallelism,
                        passwordBuffer.baseAddress,
                        compositeKey.count,
                        saltBuffer.baseAddress,
                        salt.count,
                        outputBuffer.baseAddress,
                        outputCount,
                        nil,
                        0,
                        type,
                        version
                    )
                }
            }
        }

        guard code == ARGON2_OK.rawValue else {
            throw KDBXError.corruptDatabase
        }
        return Data(output)
    }
}
