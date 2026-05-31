import Foundation

public enum TOTPError: Error, Equatable, Sendable {
    case invalidURI
    case missingSecret
    case invalidBase32Secret
    case invalidDigits
    case invalidPeriod
}

public struct TOTPConfiguration: Equatable, Sendable {
    public var secret: Data
    public var issuer: String?
    public var accountName: String?
    public var digits: Int
    public var period: Int

    public init(secret: Data, issuer: String? = nil, accountName: String? = nil, digits: Int = 6, period: Int = 30) throws {
        guard (6...8).contains(digits) else {
            throw TOTPError.invalidDigits
        }
        guard period > 0 else {
            throw TOTPError.invalidPeriod
        }

        self.secret = secret
        self.issuer = issuer
        self.accountName = accountName
        self.digits = digits
        self.period = period
    }

    public init(uri: String) throws {
        guard let components = URLComponents(string: uri),
              components.scheme?.lowercased() == "otpauth",
              components.host?.lowercased() == "totp" else {
            throw TOTPError.invalidURI
        }

        let queryItems = components.queryItems ?? []
        guard let encodedSecret = queryItems.firstValue(named: "secret") else {
            throw TOTPError.missingSecret
        }

        let label = components.path
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .removingPercentEncoding ?? ""
        let labelParts = label.split(separator: ":", maxSplits: 1).map(String.init)
        let labelIssuer = labelParts.count == 2 ? labelParts[0] : nil
        let accountName = labelParts.count == 2 ? labelParts[1] : (label.isEmpty ? nil : label)
        let issuer = queryItems.firstValue(named: "issuer") ?? labelIssuer
        let digits = Int(queryItems.firstValue(named: "digits") ?? "") ?? 6
        let period = Int(queryItems.firstValue(named: "period") ?? "") ?? 30

        try self.init(
            secret: Self.decodeBase32(encodedSecret),
            issuer: issuer,
            accountName: accountName,
            digits: digits,
            period: period
        )
    }

    public init?(keePassFields: [(name: String, value: String)]) throws {
        let fields = Dictionary(uniqueKeysWithValues: keePassFields.map { ($0.name.lowercased(), $0.value) })

        if let uriValue = keePassFields.first(where: { field in
            field.name.caseInsensitiveCompare("otp") == .orderedSame
                || field.name.caseInsensitiveCompare("totp") == .orderedSame
                || field.value.lowercased().hasPrefix("otpauth://totp/")
        })?.value {
            self = try TOTPConfiguration(uri: uriValue)
            return
        }

        guard let secret = fields["timeotp-secret"] ?? fields["totp secret"] ?? fields["otp secret"] else {
            return nil
        }

        try self.init(
            secret: Self.decodeBase32(secret),
            digits: Int(fields["timeotp-length"] ?? fields["totp digits"] ?? "") ?? 6,
            period: Int(fields["timeotp-period"] ?? fields["totp period"] ?? "") ?? 30
        )
    }

    private static func decodeBase32(_ value: String) throws -> Data {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        let lookup = Dictionary(uniqueKeysWithValues: alphabet.enumerated().map { ($0.element, UInt8($0.offset)) })
        let normalized = value
            .uppercased()
            .filter { !$0.isWhitespace && $0 != "=" }

        var buffer = 0
        var bitsLeft = 0
        var data = Data()

        for character in normalized {
            guard let value = lookup[character] else {
                throw TOTPError.invalidBase32Secret
            }
            buffer = (buffer << 5) | Int(value)
            bitsLeft += 5

            if bitsLeft >= 8 {
                bitsLeft -= 8
                data.append(UInt8((buffer >> bitsLeft) & 0xFF))
            }
        }

        guard !data.isEmpty else {
            throw TOTPError.invalidBase32Secret
        }
        return data
    }
}

private extension Array where Element == URLQueryItem {
    func firstValue(named name: String) -> String? {
        first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

public struct TOTPGenerator: Sendable {
    public init() {}

    public func code(configuration: TOTPConfiguration, timeInterval: TimeInterval = Date().timeIntervalSince1970) throws -> String {
        try code(
            secret: configuration.secret,
            timeInterval: timeInterval,
            digits: configuration.digits,
            period: configuration.period
        )
    }

    public func code(secret: Data, timeInterval: TimeInterval = Date().timeIntervalSince1970, digits: Int = 6, period: Int = 30) throws -> String {
        guard (6...8).contains(digits) else {
            throw TOTPError.invalidDigits
        }
        guard period > 0 else {
            throw TOTPError.invalidPeriod
        }

        let counter = UInt64(timeInterval / TimeInterval(period))
        let message = Data([
            UInt8((counter >> 56) & 0xFF),
            UInt8((counter >> 48) & 0xFF),
            UInt8((counter >> 40) & 0xFF),
            UInt8((counter >> 32) & 0xFF),
            UInt8((counter >> 24) & 0xFF),
            UInt8((counter >> 16) & 0xFF),
            UInt8((counter >> 8) & 0xFF),
            UInt8(counter & 0xFF)
        ])
        let digest = HMACSHA1.authenticate(message: message, key: secret)
        let offset = Int(digest[digest.count - 1] & 0x0F)
        let binaryCode = (UInt32(digest[offset] & 0x7F) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let divisor = (0..<digits).reduce(1) { value, _ in value * 10 }
        let code = Int(binaryCode) % divisor
        return String(format: "%0\(digits)d", code)
    }
}

private enum HMACSHA1 {
    private static let blockSize = 64

    static func authenticate(message: Data, key: Data) -> Data {
        var normalizedKey = key
        if normalizedKey.count > blockSize {
            normalizedKey = SHA1.hash(normalizedKey)
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
        outer.append(SHA1.hash(inner))
        return SHA1.hash(outer)
    }
}

private enum SHA1 {
    static func hash(_ data: Data) -> Data {
        var message = [UInt8](data)
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)

        while message.count % 64 != 56 {
            message.append(0)
        }

        for shift in stride(from: 56, through: 0, by: -8) {
            message.append(UInt8((bitLength >> UInt64(shift)) & 0xFF))
        }

        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xEFCDAB89
        var h2: UInt32 = 0x98BADCFE
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xC3D2E1F0

        for chunkStart in stride(from: 0, to: message.count, by: 64) {
            var words = [UInt32](repeating: 0, count: 80)

            for index in 0..<16 {
                let offset = chunkStart + index * 4
                words[index] = UInt32(message[offset]) << 24
                    | UInt32(message[offset + 1]) << 16
                    | UInt32(message[offset + 2]) << 8
                    | UInt32(message[offset + 3])
            }

            for index in 16..<80 {
                words[index] = rotateLeft(words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16], by: 1)
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4

            for index in 0..<80 {
                let f: UInt32
                let k: UInt32
                switch index {
                case 0..<20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                case 20..<40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                case 40..<60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                default:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                }

                let temp = rotateLeft(a, by: 5) &+ f &+ e &+ k &+ words[index]
                e = d
                d = c
                c = rotateLeft(b, by: 30)
                b = a
                a = temp
            }

            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
        }

        var digest = Data()
        for value in [h0, h1, h2, h3, h4] {
            digest.append(UInt8((value >> 24) & 0xFF))
            digest.append(UInt8((value >> 16) & 0xFF))
            digest.append(UInt8((value >> 8) & 0xFF))
            digest.append(UInt8(value & 0xFF))
        }
        return digest
    }

    private static func rotateLeft(_ value: UInt32, by shift: UInt32) -> UInt32 {
        (value << shift) | (value >> (32 - shift))
    }
}
