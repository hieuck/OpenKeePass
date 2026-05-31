import Foundation

public enum KDBX3BlockStream {
    private static let blockIDByteCount = 4
    private static let hashByteCount = 32
    private static let sizeByteCount = 4

    public static func read(_ data: Data) throws -> Data {
        var offset = 0
        var expectedBlockID: UInt32 = 0
        var payload = Data()

        while true {
            guard offset + blockIDByteCount + hashByteCount + sizeByteCount <= data.count else {
                throw KDBXError.corruptDatabase
            }

            let blockID = data.littleEndianUInt32(at: offset)
            offset += blockIDByteCount
            guard blockID == expectedBlockID else {
                throw KDBXError.corruptDatabase
            }

            let storedHash = data.subdata(in: offset..<(offset + hashByteCount))
            offset += hashByteCount

            let blockSize = Int(data.littleEndianUInt32(at: offset))
            offset += sizeByteCount

            guard offset + blockSize <= data.count else {
                throw KDBXError.corruptDatabase
            }

            let blockPayload = data.subdata(in: offset..<(offset + blockSize))
            offset += blockSize

            if blockSize == 0 {
                guard storedHash == Data(repeating: 0, count: hashByteCount), offset == data.count else {
                    throw KDBXError.corruptDatabase
                }
                return payload
            }

            guard storedHash == SHA256.hash(blockPayload) else {
                throw KDBXError.corruptDatabase
            }

            payload.append(blockPayload)
            expectedBlockID += 1
        }
    }

    public static func isLikelyUnwrappedPayload(_ data: Data) -> Bool {
        data.first == UInt8(ascii: "<") || data.starts(with: Data([0x1F, 0x8B, 0x08]))
    }
}
