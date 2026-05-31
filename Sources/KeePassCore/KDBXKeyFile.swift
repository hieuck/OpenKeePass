import Foundation

public struct KDBXKeyFile: Equatable, Sendable {
    public var keyData: Data

    public init(keyData: Data) {
        self.keyData = keyData
    }

    public static func parse(_ data: Data) throws -> KDBXKeyFile {
        if data.count == 32 {
            return KDBXKeyFile(keyData: data)
        }

        if let hexKey = parseHexKey(data) {
            return KDBXKeyFile(keyData: hexKey)
        }

        if let xmlKey = try parseXMLKey(data) {
            return KDBXKeyFile(keyData: xmlKey)
        }

        return KDBXKeyFile(keyData: SHA256.hash(data))
    }

    private static func parseHexKey(_ data: Data) -> Data? {
        guard let string = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            string.count == 64,
            string.allSatisfy({ $0.isHexDigit }) else {
            return nil
        }

        var result = Data()
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<next], radix: 16) else {
                return nil
            }
            result.append(byte)
            index = next
        }
        return result
    }

    private static func parseXMLKey(_ data: Data) throws -> Data? {
        guard let xml = String(data: data, encoding: .utf8),
              xml.localizedCaseInsensitiveContains("<KeyFile") else {
            return nil
        }

        guard let dataOpen = xml.range(of: "<Data"),
              let tagClose = xml[dataOpen.upperBound...].firstIndex(of: ">"),
              let dataClose = xml[tagClose...].range(of: "</Data>") else {
            throw KDBXError.corruptDatabase
        }

        let dataTag = String(xml[dataOpen.lowerBound...tagClose])
        let encodedKey = String(xml[xml.index(after: tagClose)..<dataClose.lowerBound])
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let keyData = Data(base64Encoded: encodedKey) ?? parseHexKey(Data(encodedKey.utf8)) else {
            throw KDBXError.corruptDatabase
        }

        if let expectedHash = attribute(named: "Hash", in: dataTag) {
            let actualHash = SHA256.hash(keyData).prefix(4).hexEncodedUppercase()
            guard expectedHash.uppercased() == actualHash else {
                throw KDBXError.corruptDatabase
            }
        }

        return keyData
    }

    private static func attribute(named name: String, in tag: String) -> String? {
        let prefix = "\(name)=\""
        guard let start = tag.range(of: prefix) else {
            return nil
        }
        let valueStart = start.upperBound
        guard let end = tag[valueStart...].firstIndex(of: "\"") else {
            return nil
        }
        return String(tag[valueStart..<end])
    }
}

public enum KDBXCompositeKey {
    public static func material(from credentials: KDBXCredentials) throws -> Data {
        var componentHashes = Data()

        if !credentials.password.isEmpty {
            componentHashes.append(SHA256.hash(Data(credentials.password.utf8)))
        }

        if let keyFileData = credentials.keyFileData {
            componentHashes.append(try KDBXKeyFile.parse(keyFileData).keyData)
        }

        guard !componentHashes.isEmpty else {
            throw KDBXError.wrongCredentials
        }

        return SHA256.hash(componentHashes)
    }
}

extension Data {
    func hexEncodedUppercase() -> String {
        map { String(format: "%02X", $0) }.joined()
    }
}
