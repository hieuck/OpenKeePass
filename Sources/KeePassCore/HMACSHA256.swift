import Foundation

public enum HMACSHA256 {
    private static let blockSize = 64

    public static func authenticate(message: Data, key: Data) -> Data {
        var normalizedKey = key
        if normalizedKey.count > blockSize {
            normalizedKey = SHA256.hash(normalizedKey)
        }
        if normalizedKey.count < blockSize {
            normalizedKey.append(Data(repeating: 0, count: blockSize - normalizedKey.count))
        }

        let outerKeyPad = Data(normalizedKey.map { $0 ^ 0x5C })
        let innerKeyPad = Data(normalizedKey.map { $0 ^ 0x36 })

        var inner = Data()
        inner.append(innerKeyPad)
        inner.append(message)

        var outer = Data()
        outer.append(outerKeyPad)
        outer.append(SHA256.hash(inner))
        return SHA256.hash(outer)
    }
}
