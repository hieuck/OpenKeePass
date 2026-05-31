import Foundation

public struct Salsa20Stream: Equatable, Sendable {
    private var key: Data
    private var nonce: Data
    private var counterLow: UInt32
    private var counterHigh: UInt32
    private var buffer = Data()
    private var bufferOffset = 0

    public init(key: Data, nonce: Data, counterLow: UInt32 = 0, counterHigh: UInt32 = 0) throws {
        guard key.count == 32, nonce.count == 8 else {
            throw KDBXError.corruptDatabase
        }
        self.key = key
        self.nonce = nonce
        self.counterLow = counterLow
        self.counterHigh = counterHigh
    }

    public static func protectedValueStream(key: Data) throws -> Salsa20Stream {
        try Salsa20Stream(
            key: key,
            nonce: Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])
        )
    }

    public mutating func apply(to input: Data) throws -> Data {
        var output = Data()
        output.reserveCapacity(input.count)

        for byte in input {
            if bufferOffset == buffer.count {
                buffer = block()
                bufferOffset = 0
                incrementCounter()
            }
            output.append(byte ^ buffer[bufferOffset])
            bufferOffset += 1
        }

        return output
    }

    private mutating func incrementCounter() {
        counterLow &+= 1
        if counterLow == 0 {
            counterHigh &+= 1
        }
    }

    private func block() -> Data {
        let constants = Data("expand 32-byte k".utf8)
        var state: [UInt32] = [
            constants.littleEndianUInt32(at: 0),
            key.littleEndianUInt32(at: 0),
            key.littleEndianUInt32(at: 4),
            key.littleEndianUInt32(at: 8),
            key.littleEndianUInt32(at: 12),
            constants.littleEndianUInt32(at: 4),
            nonce.littleEndianUInt32(at: 0),
            nonce.littleEndianUInt32(at: 4),
            counterLow,
            counterHigh,
            constants.littleEndianUInt32(at: 8),
            key.littleEndianUInt32(at: 16),
            key.littleEndianUInt32(at: 20),
            key.littleEndianUInt32(at: 24),
            key.littleEndianUInt32(at: 28),
            constants.littleEndianUInt32(at: 12)
        ]
        let original = state

        for _ in 0..<10 {
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 5, 9, 13, 1)
            quarterRound(&state, 10, 14, 2, 6)
            quarterRound(&state, 15, 3, 7, 11)
            quarterRound(&state, 0, 1, 2, 3)
            quarterRound(&state, 5, 6, 7, 4)
            quarterRound(&state, 10, 11, 8, 9)
            quarterRound(&state, 15, 12, 13, 14)
        }

        var output = Data()
        output.reserveCapacity(64)
        for index in 0..<16 {
            output.appendUInt32LE(state[index] &+ original[index])
        }
        return output
    }

    private func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[b] ^= (state[a] &+ state[d]).rotatedLeft(7)
        state[c] ^= (state[b] &+ state[a]).rotatedLeft(9)
        state[d] ^= (state[c] &+ state[b]).rotatedLeft(13)
        state[a] ^= (state[d] &+ state[c]).rotatedLeft(18)
    }
}

private extension UInt32 {
    func rotatedLeft(_ count: UInt32) -> UInt32 {
        (self << count) | (self >> (32 - count))
    }
}

private extension Data {
    mutating func appendUInt32LE(_ value: UInt32) {
        append(UInt8(value & 0x000000FF))
        append(UInt8((value & 0x0000FF00) >> 8))
        append(UInt8((value & 0x00FF0000) >> 16))
        append(UInt8((value & 0xFF000000) >> 24))
    }
}
