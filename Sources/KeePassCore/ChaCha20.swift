import Foundation

public struct ChaCha20: Sendable {
    private let key: Data
    private let nonce: Data
    private let initialCounter: UInt32

    public init(key: Data, nonce: Data, initialCounter: UInt32 = 0) throws {
        guard key.count == 32, nonce.count == 12 else {
            throw KDBXError.corruptDatabase
        }
        self.key = key
        self.nonce = nonce
        self.initialCounter = initialCounter
    }

    public func apply(to data: Data) throws -> Data {
        try apply(to: data, startingAtByteOffset: 0)
    }

    public func apply(to data: Data, startingAtByteOffset byteOffset: UInt64) throws -> Data {
        var output = Data(capacity: data.count)
        var counter = initialCounter &+ UInt32(byteOffset / 64)
        var blockOffset = Int(byteOffset % 64)
        var offset = 0

        while offset < data.count {
            let block = block(counter: counter)
            let byteCount = min(64 - blockOffset, data.count - offset)
            for index in 0..<byteCount {
                let inputIndex = data.index(data.startIndex, offsetBy: offset + index)
                output.append(data[inputIndex] ^ block[blockOffset + index])
            }
            offset += byteCount
            counter &+= 1
            blockOffset = 0
        }

        return output
    }

    private func block(counter: UInt32) -> [UInt8] {
        var state: [UInt32] = [
            0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
            key.littleEndianUInt32(at: 0),
            key.littleEndianUInt32(at: 4),
            key.littleEndianUInt32(at: 8),
            key.littleEndianUInt32(at: 12),
            key.littleEndianUInt32(at: 16),
            key.littleEndianUInt32(at: 20),
            key.littleEndianUInt32(at: 24),
            key.littleEndianUInt32(at: 28),
            counter,
            nonce.littleEndianUInt32(at: 0),
            nonce.littleEndianUInt32(at: 4),
            nonce.littleEndianUInt32(at: 8)
        ]
        let original = state

        for _ in 0..<10 {
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 1, 5, 9, 13)
            quarterRound(&state, 2, 6, 10, 14)
            quarterRound(&state, 3, 7, 11, 15)
            quarterRound(&state, 0, 5, 10, 15)
            quarterRound(&state, 1, 6, 11, 12)
            quarterRound(&state, 2, 7, 8, 13)
            quarterRound(&state, 3, 4, 9, 14)
        }

        for index in 0..<state.count {
            state[index] = state[index] &+ original[index]
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(64)
        for word in state {
            bytes.append(UInt8(word & 0x000000FF))
            bytes.append(UInt8((word & 0x0000FF00) >> 8))
            bytes.append(UInt8((word & 0x00FF0000) >> 16))
            bytes.append(UInt8((word & 0xFF000000) >> 24))
        }
        return bytes
    }

    private func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]
        state[d] = rotateLeft(state[d] ^ state[a], by: 16)
        state[c] = state[c] &+ state[d]
        state[b] = rotateLeft(state[b] ^ state[c], by: 12)
        state[a] = state[a] &+ state[b]
        state[d] = rotateLeft(state[d] ^ state[a], by: 8)
        state[c] = state[c] &+ state[d]
        state[b] = rotateLeft(state[b] ^ state[c], by: 7)
    }

    private func rotateLeft(_ value: UInt32, by shift: UInt32) -> UInt32 {
        (value << shift) | (value >> (32 - shift))
    }
}

public struct ChaCha20Stream: Sendable {
    private let cipher: ChaCha20
    private var byteOffset: UInt64 = 0

    public init(key: Data, nonce: Data, initialCounter: UInt32 = 0) throws {
        cipher = try ChaCha20(key: key, nonce: nonce, initialCounter: initialCounter)
    }

    public static func protectedValueStream(innerKey: Data) throws -> ChaCha20Stream {
        guard innerKey.count == 64 else {
            throw KDBXError.corruptDatabase
        }

        let hashedKey = SHA512.hash(innerKey)
        return try ChaCha20Stream(
            key: hashedKey.subdata(in: 0..<32),
            nonce: hashedKey.subdata(in: 32..<44),
            initialCounter: 0
        )
    }

    public mutating func apply(to data: Data) throws -> Data {
        let output = try cipher.apply(to: data, startingAtByteOffset: byteOffset)
        byteOffset += UInt64(data.count)
        return output
    }
}
