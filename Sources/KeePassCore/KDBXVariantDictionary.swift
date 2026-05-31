import Foundation

public enum KDBXVariantValue: Equatable, Sendable {
    case bytes(Data)
    case uint32(UInt32)
    case uint64(UInt64)
    case bool(Bool)
    case string(String)
}

public struct KDBXVariantDictionary: Equatable, Sendable {
    public private(set) var values: [String: KDBXVariantValue]

    public subscript(key: String) -> KDBXVariantValue? {
        values[key]
    }

    public static func parse(_ data: Data) throws -> KDBXVariantDictionary {
        guard data.count >= 2 else {
            throw KDBXError.corruptDatabase
        }

        let minorVersion = data[0]
        let majorVersion = data[1]
        guard majorVersion == 1, minorVersion == 0 else {
            throw KDBXError.unsupportedFeature("Variant dictionary version \(majorVersion).\(minorVersion) is not supported")
        }

        var offset = 2
        var values: [String: KDBXVariantValue] = [:]

        while offset < data.count {
            let type = data[offset]
            offset += 1

            if type == 0x00 {
                return KDBXVariantDictionary(values: values)
            }

            guard offset + 4 <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let keyLength = Int(data.littleEndianUInt32(at: offset))
            offset += 4

            guard offset + keyLength <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let keyData = data.subdata(in: offset..<(offset + keyLength))
            offset += keyLength

            guard let key = String(data: keyData, encoding: .utf8) else {
                throw KDBXError.corruptDatabase
            }

            guard offset + 4 <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let valueLength = Int(data.littleEndianUInt32(at: offset))
            offset += 4

            guard offset + valueLength <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let valueData = data.subdata(in: offset..<(offset + valueLength))
            offset += valueLength

            values[key] = try parseValue(type: type, data: valueData)
        }

        throw KDBXError.corruptDatabase
    }

    private static func parseValue(type: UInt8, data: Data) throws -> KDBXVariantValue {
        switch type {
        case 0x04:
            guard data.count == 4 else {
                throw KDBXError.corruptDatabase
            }
            return .uint32(data.littleEndianUInt32(at: 0))
        case 0x05:
            guard data.count == 8 else {
                throw KDBXError.corruptDatabase
            }
            return .uint64(data.littleEndianUInt64(at: 0))
        case 0x08:
            guard data.count == 1 else {
                throw KDBXError.corruptDatabase
            }
            return .bool(data[0] != 0)
        case 0x0C:
            guard let string = String(data: data, encoding: .utf8) else {
                throw KDBXError.corruptDatabase
            }
            return .string(string)
        case 0x42:
            return .bytes(data)
        default:
            throw KDBXError.unsupportedFeature("Variant dictionary value type 0x\(String(type, radix: 16)) is not supported")
        }
    }
}

extension Data {
    func littleEndianUInt16(at offset: Int) -> UInt16 {
        UInt16(self[offset]) | (UInt16(self[offset + 1]) << 8)
    }

    func littleEndianUInt32(at offset: Int) -> UInt32 {
        UInt32(self[offset])
            | (UInt32(self[offset + 1]) << 8)
            | (UInt32(self[offset + 2]) << 16)
            | (UInt32(self[offset + 3]) << 24)
    }

    func littleEndianUInt64(at offset: Int) -> UInt64 {
        UInt64(self[offset])
            | (UInt64(self[offset + 1]) << 8)
            | (UInt64(self[offset + 2]) << 16)
            | (UInt64(self[offset + 3]) << 24)
            | (UInt64(self[offset + 4]) << 32)
            | (UInt64(self[offset + 5]) << 40)
            | (UInt64(self[offset + 6]) << 48)
            | (UInt64(self[offset + 7]) << 56)
    }
}
