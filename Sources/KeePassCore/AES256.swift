import Foundation

public struct AES256: Sendable {
    private let roundKeys: [UInt8]

    public init(key: Data) throws {
        guard key.count == 32 else {
            throw KDBXError.unsupportedFeature("AES-256 requires a 32-byte key")
        }
        roundKeys = AES256.expandKey([UInt8](key))
    }

    public func encryptBlock(_ block: Data) throws -> Data {
        guard block.count == 16 else {
            throw KDBXError.corruptDatabase
        }

        var state = [UInt8](block)
        addRoundKey(&state, round: 0)

        for round in 1..<14 {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, round: round)
        }

        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, round: 14)

        return Data(state)
    }

    public func decryptBlock(_ block: Data) throws -> Data {
        guard block.count == 16 else {
            throw KDBXError.corruptDatabase
        }

        var state = [UInt8](block)
        addRoundKey(&state, round: 14)

        for round in stride(from: 13, through: 1, by: -1) {
            inverseShiftRows(&state)
            inverseSubBytes(&state)
            addRoundKey(&state, round: round)
            inverseMixColumns(&state)
        }

        inverseShiftRows(&state)
        inverseSubBytes(&state)
        addRoundKey(&state, round: 0)

        return Data(state)
    }

    public func encryptCBC(_ plaintext: Data, iv: Data) throws -> Data {
        guard iv.count == 16, plaintext.count.isMultiple(of: 16) else {
            throw KDBXError.corruptDatabase
        }

        var result = Data()
        var previous = iv
        for offset in stride(from: 0, to: plaintext.count, by: 16) {
            let block = plaintext.subdata(in: offset..<(offset + 16)).xor(with: previous)
            let encrypted = try encryptBlock(block)
            result.append(encrypted)
            previous = encrypted
        }
        return result
    }

    public func decryptCBCPKCS7(_ ciphertext: Data, iv: Data) throws -> Data {
        guard iv.count == 16, !ciphertext.isEmpty, ciphertext.count.isMultiple(of: 16) else {
            throw KDBXError.corruptDatabase
        }

        var result = Data()
        var previous = iv
        for offset in stride(from: 0, to: ciphertext.count, by: 16) {
            let block = ciphertext.subdata(in: offset..<(offset + 16))
            let decrypted = try decryptBlock(block).xor(with: previous)
            result.append(decrypted)
            previous = block
        }

        guard let paddingLength = result.last, paddingLength > 0, paddingLength <= 16, result.count >= Int(paddingLength) else {
            throw KDBXError.corruptDatabase
        }

        let padding = result.suffix(Int(paddingLength))
        guard padding.allSatisfy({ $0 == paddingLength }) else {
            throw KDBXError.corruptDatabase
        }

        result.removeLast(Int(paddingLength))
        return result
    }

    private func addRoundKey(_ state: inout [UInt8], round: Int) {
        let offset = round * 16
        for index in 0..<16 {
            state[index] ^= roundKeys[offset + index]
        }
    }

    private func subBytes(_ state: inout [UInt8]) {
        for index in state.indices {
            state[index] = AES256.sBox[Int(state[index])]
        }
    }

    private func shiftRows(_ state: inout [UInt8]) {
        let original = state
        state[0] = original[0]
        state[4] = original[4]
        state[8] = original[8]
        state[12] = original[12]

        state[1] = original[5]
        state[5] = original[9]
        state[9] = original[13]
        state[13] = original[1]

        state[2] = original[10]
        state[6] = original[14]
        state[10] = original[2]
        state[14] = original[6]

        state[3] = original[15]
        state[7] = original[3]
        state[11] = original[7]
        state[15] = original[11]
    }

    private func inverseSubBytes(_ state: inout [UInt8]) {
        for index in state.indices {
            state[index] = AES256.inverseSBox[Int(state[index])]
        }
    }

    private func inverseShiftRows(_ state: inout [UInt8]) {
        let original = state
        state[0] = original[0]
        state[4] = original[4]
        state[8] = original[8]
        state[12] = original[12]

        state[1] = original[13]
        state[5] = original[1]
        state[9] = original[5]
        state[13] = original[9]

        state[2] = original[10]
        state[6] = original[14]
        state[10] = original[2]
        state[14] = original[6]

        state[3] = original[7]
        state[7] = original[11]
        state[11] = original[15]
        state[15] = original[3]
    }

    private func mixColumns(_ state: inout [UInt8]) {
        for column in 0..<4 {
            let index = column * 4
            let s0 = state[index]
            let s1 = state[index + 1]
            let s2 = state[index + 2]
            let s3 = state[index + 3]

            state[index] = multiply(s0, 2) ^ multiply(s1, 3) ^ s2 ^ s3
            state[index + 1] = s0 ^ multiply(s1, 2) ^ multiply(s2, 3) ^ s3
            state[index + 2] = s0 ^ s1 ^ multiply(s2, 2) ^ multiply(s3, 3)
            state[index + 3] = multiply(s0, 3) ^ s1 ^ s2 ^ multiply(s3, 2)
        }
    }

    private func multiply(_ value: UInt8, _ factor: UInt8) -> UInt8 {
        switch factor {
        case 2:
            return xtime(value)
        case 3:
            return xtime(value) ^ value
        case 9:
            return xtime(xtime(xtime(value))) ^ value
        case 11:
            return xtime(xtime(xtime(value)) ^ value) ^ value
        case 13:
            return xtime(xtime(xtime(value) ^ value)) ^ value
        case 14:
            return xtime(xtime(xtime(value) ^ value) ^ value)
        default:
            return value
        }
    }

    private func inverseMixColumns(_ state: inout [UInt8]) {
        for column in 0..<4 {
            let index = column * 4
            let s0 = state[index]
            let s1 = state[index + 1]
            let s2 = state[index + 2]
            let s3 = state[index + 3]

            state[index] = multiply(s0, 14) ^ multiply(s1, 11) ^ multiply(s2, 13) ^ multiply(s3, 9)
            state[index + 1] = multiply(s0, 9) ^ multiply(s1, 14) ^ multiply(s2, 11) ^ multiply(s3, 13)
            state[index + 2] = multiply(s0, 13) ^ multiply(s1, 9) ^ multiply(s2, 14) ^ multiply(s3, 11)
            state[index + 3] = multiply(s0, 11) ^ multiply(s1, 13) ^ multiply(s2, 9) ^ multiply(s3, 14)
        }
    }

    private func xtime(_ value: UInt8) -> UInt8 {
        let shifted = value << 1
        return (value & 0x80) == 0 ? shifted : shifted ^ 0x1B
    }

    private static func expandKey(_ key: [UInt8]) -> [UInt8] {
        var expanded = key
        var bytesGenerated = key.count
        var rconIndex = 1
        var temp = [UInt8](repeating: 0, count: 4)

        while bytesGenerated < 240 {
            for index in 0..<4 {
                temp[index] = expanded[bytesGenerated - 4 + index]
            }

            if bytesGenerated % 32 == 0 {
                temp = keyScheduleCore(temp, rcon: rcon[rconIndex])
                rconIndex += 1
            } else if bytesGenerated % 32 == 16 {
                temp = temp.map { sBox[Int($0)] }
            }

            for index in 0..<4 {
                expanded.append(expanded[bytesGenerated - 32] ^ temp[index])
                bytesGenerated += 1
            }
        }

        return expanded
    }

    private static func keyScheduleCore(_ input: [UInt8], rcon: UInt8) -> [UInt8] {
        var output = [input[1], input[2], input[3], input[0]]
        output = output.map { sBox[Int($0)] }
        output[0] ^= rcon
        return output
    }

    private static let rcon: [UInt8] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36
    ]

    private static let sBox: [UInt8] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]

    private static let inverseSBox: [UInt8] = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    ]
}

private extension Data {
    func xor(with other: Data) -> Data {
        Data(zip(self, other).map { $0 ^ $1 })
    }
}
