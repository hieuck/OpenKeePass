import Foundation

public struct KDBXHeader: Equatable, Sendable {
    public enum FileSignature: Equatable, Sendable {
        case kdbx
    }

    public var fileSignature: FileSignature
    public var majorVersion: UInt16
    public var minorVersion: UInt16

    public init(fileSignature: FileSignature, majorVersion: UInt16, minorVersion: UInt16) {
        self.fileSignature = fileSignature
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
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
        return KDBXHeader(fileSignature: .kdbx, majorVersion: majorVersion, minorVersion: minorVersion)
    }
}

private extension Data {
    func littleEndianUInt16(at offset: Int) -> UInt16 {
        UInt16(self[offset]) | (UInt16(self[offset + 1]) << 8)
    }

    func littleEndianUInt32(at offset: Int) -> UInt32 {
        UInt32(self[offset])
            | (UInt32(self[offset + 1]) << 8)
            | (UInt32(self[offset + 2]) << 16)
            | (UInt32(self[offset + 3]) << 24)
    }
}
