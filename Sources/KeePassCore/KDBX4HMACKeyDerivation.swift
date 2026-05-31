import Foundation

public enum KDBX4HMACKeyDerivation {
    public static func headerKey(masterSeed: Data, transformedKey: Data) -> Data {
        indexedKey(index: UInt64.max, masterSeed: masterSeed, transformedKey: transformedKey)
    }

    public static func blockKey(index: UInt64, masterSeed: Data, transformedKey: Data) -> Data {
        indexedKey(index: index, masterSeed: masterSeed, transformedKey: transformedKey)
    }

    private static func indexedKey(index: UInt64, masterSeed: Data, transformedKey: Data) -> Data {
        var baseInput = Data()
        baseInput.append(masterSeed)
        baseInput.append(transformedKey)
        baseInput.append(0x01)
        let baseKey = SHA512.hash(baseInput)

        var indexedInput = Data()
        indexedInput.appendUInt64LE(index)
        indexedInput.append(baseKey)
        return SHA512.hash(indexedInput)
    }
}

private extension Data {
    mutating func appendUInt64LE(_ value: UInt64) {
        append(UInt8(value & 0x00000000000000FF))
        append(UInt8((value & 0x000000000000FF00) >> 8))
        append(UInt8((value & 0x0000000000FF0000) >> 16))
        append(UInt8((value & 0x00000000FF000000) >> 24))
        append(UInt8((value & 0x000000FF00000000) >> 32))
        append(UInt8((value & 0x0000FF0000000000) >> 40))
        append(UInt8((value & 0x00FF000000000000) >> 48))
        append(UInt8((value & 0xFF00000000000000) >> 56))
    }
}
