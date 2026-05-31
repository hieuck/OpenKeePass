import Foundation

public enum KDBX4InnerHeader {
    public enum ProtectedStreamAlgorithm: Equatable, Sendable {
        case salsa20
        case chaCha20
    }

    public struct ProtectedStream: Equatable, Sendable {
        public var algorithm: ProtectedStreamAlgorithm
        public var key: Data
    }

    public struct Parsed: Equatable, Sendable {
        public var body: Data
        public var protectedStream: ProtectedStream?
    }

    public static func strip(from data: Data) throws -> Data {
        try parse(data).body
    }

    public static func parse(_ data: Data) throws -> Parsed {
        guard !data.isEmpty else {
            return Parsed(body: data, protectedStream: nil)
        }

        if data.first == UInt8(ascii: "<") {
            return Parsed(body: data, protectedStream: nil)
        }

        var offset = 0
        var algorithm: ProtectedStreamAlgorithm?
        var key: Data?

        while offset < data.count {
            let fieldID = data[offset]
            offset += 1

            guard offset + 4 <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let length = Int(data.littleEndianUInt32(at: offset))
            offset += 4

            guard offset + length <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let payload = data.subdata(in: offset..<(offset + length))
            offset += length

            if fieldID == 0 {
                let protectedStream = try protectedStream(algorithm: algorithm, key: key)
                return Parsed(body: data.subdata(in: offset..<data.count), protectedStream: protectedStream)
            }

            switch fieldID {
            case 1:
                guard payload.count == 4 else {
                    throw KDBXError.corruptDatabase
                }
                switch payload.littleEndianUInt32(at: 0) {
                case 2:
                    algorithm = .salsa20
                case 3:
                    algorithm = .chaCha20
                default:
                    throw KDBXError.unsupportedFeature("Inner stream algorithm \(payload.littleEndianUInt32(at: 0)) is not supported")
                }
            case 2:
                key = payload
            default:
                break
            }
        }

        throw KDBXError.corruptDatabase
    }

    private static func protectedStream(algorithm: ProtectedStreamAlgorithm?, key: Data?) throws -> ProtectedStream? {
        guard let algorithm else {
            return nil
        }
        guard let key else {
            throw KDBXError.corruptDatabase
        }
        return ProtectedStream(algorithm: algorithm, key: key)
    }
}
