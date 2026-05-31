import Foundation

public enum KDBX4BlockStream {
    private static let hmacByteCount = 32
    private static let sizeByteCount = 4

    public static func read(_ data: Data, hmacKeyForBlock: (UInt64) throws -> Data) throws -> Data {
        var offset = 0
        var blockIndex: UInt64 = 0
        var payload = Data()

        while true {
            guard offset + hmacByteCount + sizeByteCount <= data.count else {
                throw KDBXError.corruptDatabase
            }

            let storedHMAC = data.subdata(in: offset..<(offset + hmacByteCount))
            offset += hmacByteCount

            let blockSize = Int(data.littleEndianUInt32(at: offset))
            offset += sizeByteCount

            guard offset + blockSize <= data.count else {
                throw KDBXError.corruptDatabase
            }

            let blockPayload = data.subdata(in: offset..<(offset + blockSize))
            offset += blockSize

            let expectedHMAC = HMACSHA256.authenticate(
                message: hmacMessage(index: blockIndex, payload: blockPayload),
                key: try hmacKeyForBlock(blockIndex)
            )
            guard constantTimeEquals(storedHMAC, expectedHMAC) else {
                throw KDBXError.wrongCredentials
            }

            if blockSize == 0, offset == data.count {
                return payload
            }
            if blockSize == 0 {
                throw KDBXError.corruptDatabase
            }

            payload.append(blockPayload)
            blockIndex += 1
        }
    }

    private static func hmacMessage(index: UInt64, payload: Data) -> Data {
        var message = Data()
        message.appendUInt64LE(index)
        message.appendUInt32LE(UInt32(payload.count))
        message.append(payload)
        return message
    }

    private static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }

        var difference: UInt8 = 0
        for index in 0..<lhs.count {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}

private extension Data {
    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(value & 0x000000FF))
        append(UInt8((value & 0x0000FF00) >> 8))
        append(UInt8((value & 0x00FF0000) >> 16))
        append(UInt8((value & 0xFF000000) >> 24))
    }

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
