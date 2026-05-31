import Foundation

public struct KDBXHeader: Equatable, Sendable {
    public enum FileSignature: Equatable, Sendable {
        case kdbx
    }

    public enum Compression: Equatable, Sendable {
        case none
        case gzip
        case unknown(UInt32)
    }

    public var fileSignature: FileSignature
    public var majorVersion: UInt16
    public var minorVersion: UInt16
    public var cipherID: Data?
    public var compression: Compression?
    public var masterSeed: Data?
    public var transformSeed: Data?
    public var transformRounds: UInt64?
    public var encryptionIV: Data?
    public var protectedStreamKey: Data?
    public var streamStartBytes: Data?
    public var innerRandomStreamID: UInt32?
    public var kdfParameters: Data?
    public var headerByteCount: Int

    public init(
        fileSignature: FileSignature,
        majorVersion: UInt16,
        minorVersion: UInt16,
        cipherID: Data? = nil,
        compression: Compression? = nil,
        masterSeed: Data? = nil,
        transformSeed: Data? = nil,
        transformRounds: UInt64? = nil,
        encryptionIV: Data? = nil,
        protectedStreamKey: Data? = nil,
        streamStartBytes: Data? = nil,
        innerRandomStreamID: UInt32? = nil,
        kdfParameters: Data? = nil,
        headerByteCount: Int = 12
    ) {
        self.fileSignature = fileSignature
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
        self.cipherID = cipherID
        self.compression = compression
        self.masterSeed = masterSeed
        self.transformSeed = transformSeed
        self.transformRounds = transformRounds
        self.encryptionIV = encryptionIV
        self.protectedStreamKey = protectedStreamKey
        self.streamStartBytes = streamStartBytes
        self.innerRandomStreamID = innerRandomStreamID
        self.kdfParameters = kdfParameters
        self.headerByteCount = headerByteCount
    }

    public static func parse(_ data: Data) throws -> KDBXHeader {
        guard data.count >= 12 else {
            throw KDBXError.truncatedHeader
        }

        let firstSignature = data.littleEndianUInt32(at: 0)
        let secondSignature = data.littleEndianUInt32(at: 4)
        guard firstSignature == 0x9AA2D903, secondSignature == 0xB54BFB67 else {
            throw KDBXError.notKeePassDatabase
        }

        let minorVersion = data.littleEndianUInt16(at: 8)
        let majorVersion = data.littleEndianUInt16(at: 10)
        var header = KDBXHeader(fileSignature: .kdbx, majorVersion: majorVersion, minorVersion: minorVersion)

        if majorVersion == 3, data.count > 12 {
            try header.parseKDBX3Fields(from: data)
        } else if majorVersion == 4, data.count > 12 {
            try header.parseKDBX4Fields(from: data)
        }

        return header
    }

    private mutating func parseKDBX3Fields(from data: Data) throws {
        var offset = 12
        while offset < data.count {
            let fieldID = data[offset]
            offset += 1

            guard offset + 2 <= data.count else {
                throw KDBXError.truncatedHeader
            }

            let length = Int(data.littleEndianUInt16(at: offset))
            offset += 2

            guard offset + length <= data.count else {
                throw KDBXError.truncatedHeader
            }

            let payload = data.subdata(in: offset..<(offset + length))
            offset += length

            if fieldID == 0 {
                headerByteCount = offset
                return
            }

            apply(fieldID: fieldID, payload: payload)
        }

        throw KDBXError.truncatedHeader
    }

    private mutating func parseKDBX4Fields(from data: Data) throws {
        var offset = 12
        while offset < data.count {
            let fieldID = data[offset]
            offset += 1

            guard offset + 4 <= data.count else {
                throw KDBXError.truncatedHeader
            }

            let length = Int(data.littleEndianUInt32(at: offset))
            offset += 4

            guard offset + length <= data.count else {
                throw KDBXError.truncatedHeader
            }

            let payload = data.subdata(in: offset..<(offset + length))
            offset += length

            if fieldID == 0 {
                headerByteCount = offset
                return
            }

            apply(fieldID: fieldID, payload: payload)
        }

        throw KDBXError.truncatedHeader
    }

    private mutating func apply(fieldID: UInt8, payload: Data) {
        switch fieldID {
        case 2:
            cipherID = payload
        case 3:
            guard payload.count >= 4 else {
                compression = nil
                return
            }
            let raw = payload.littleEndianUInt32(at: 0)
            switch raw {
            case 0:
                compression = Compression.none
            case 1:
                compression = .gzip
            default:
                compression = .unknown(raw)
            }
        case 4:
            masterSeed = payload
        case 5:
            transformSeed = payload
        case 6:
            guard payload.count >= 8 else {
                transformRounds = nil
                return
            }
            transformRounds = payload.littleEndianUInt64(at: 0)
        case 7:
            encryptionIV = payload
        case 8:
            protectedStreamKey = payload
        case 9:
            streamStartBytes = payload
        case 10:
            guard payload.count >= 4 else {
                innerRandomStreamID = nil
                return
            }
            innerRandomStreamID = payload.littleEndianUInt32(at: 0)
        case 11:
            kdfParameters = payload
        default:
            break
        }
    }
}
