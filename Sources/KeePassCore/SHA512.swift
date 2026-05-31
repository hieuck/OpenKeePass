import Foundation

public enum SHA512 {
    public static func hash(_ data: Data) -> Data {
        var message = [UInt8](data)
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)

        while message.count % 128 != 112 {
            message.append(0)
        }

        for _ in 0..<8 {
            message.append(0)
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            message.append(UInt8((bitLength >> UInt64(shift)) & 0xFF))
        }

        var h0: UInt64 = 0x6A09E667F3BCC908
        var h1: UInt64 = 0xBB67AE8584CAA73B
        var h2: UInt64 = 0x3C6EF372FE94F82B
        var h3: UInt64 = 0xA54FF53A5F1D36F1
        var h4: UInt64 = 0x510E527FADE682D1
        var h5: UInt64 = 0x9B05688C2B3E6C1F
        var h6: UInt64 = 0x1F83D9ABFB41BD6B
        var h7: UInt64 = 0x5BE0CD19137E2179

        for chunkStart in stride(from: 0, to: message.count, by: 128) {
            var words = [UInt64](repeating: 0, count: 80)

            for index in 0..<16 {
                let offset = chunkStart + index * 8
                words[index] = UInt64(message[offset]) << 56
                    | UInt64(message[offset + 1]) << 48
                    | UInt64(message[offset + 2]) << 40
                    | UInt64(message[offset + 3]) << 32
                    | UInt64(message[offset + 4]) << 24
                    | UInt64(message[offset + 5]) << 16
                    | UInt64(message[offset + 6]) << 8
                    | UInt64(message[offset + 7])
            }

            for index in 16..<80 {
                let s0 = rotateRight(words[index - 15], by: 1) ^ rotateRight(words[index - 15], by: 8) ^ (words[index - 15] >> 7)
                let s1 = rotateRight(words[index - 2], by: 19) ^ rotateRight(words[index - 2], by: 61) ^ (words[index - 2] >> 6)
                words[index] = words[index - 16] &+ s0 &+ words[index - 7] &+ s1
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            var f = h5
            var g = h6
            var h = h7

            for index in 0..<80 {
                let s1 = rotateRight(e, by: 14) ^ rotateRight(e, by: 18) ^ rotateRight(e, by: 41)
                let ch = (e & f) ^ ((~e) & g)
                let temp1 = h &+ s1 &+ ch &+ constants[index] &+ words[index]
                let s0 = rotateRight(a, by: 28) ^ rotateRight(a, by: 34) ^ rotateRight(a, by: 39)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj

                h = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ temp2
            }

            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
            h5 = h5 &+ f
            h6 = h6 &+ g
            h7 = h7 &+ h
        }

        var digest = Data()
        for value in [h0, h1, h2, h3, h4, h5, h6, h7] {
            for shift in stride(from: 56, through: 0, by: -8) {
                digest.append(UInt8((value >> UInt64(shift)) & 0xFF))
            }
        }
        return digest
    }

    private static func rotateRight(_ value: UInt64, by shift: UInt64) -> UInt64 {
        (value >> shift) | (value << (64 - shift))
    }

    private static let constants: [UInt64] = [
        0x428A2F98D728AE22, 0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019,
        0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE,
        0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210,
        0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
        0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001,
        0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910,
        0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
        0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60,
        0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
    ]
}
