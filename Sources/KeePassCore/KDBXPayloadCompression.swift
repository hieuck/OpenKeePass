import Foundation
import CMiniz

public enum KDBXPayloadCompression {
    public static func decode(_ data: Data, compression: KDBXHeader.Compression?) throws -> Data {
        switch compression ?? .none {
        case .none:
            return data
        case .gzip:
            return try inflateGzip(data)
        case .unknown(let value):
            throw KDBXError.unsupportedFeature("Compression \(value) is not supported")
        }
    }

    private static func inflateGzip(_ data: Data) throws -> Data {
        let deflate = try gzipDeflatePayload(in: data)
        var outputLength = 0
        let outputPointer = deflate.withUnsafeBytes { buffer in
            tinfl_decompress_mem_to_heap(buffer.baseAddress, deflate.count, &outputLength, 0)
        }
        guard let outputPointer else {
            throw KDBXError.corruptDatabase
        }
        defer { mz_free(outputPointer) }

        return Data(bytes: outputPointer, count: outputLength)
    }

    private static func gzipDeflatePayload(in data: Data) throws -> Data {
        guard data.count >= 18,
              data[0] == 0x1F,
              data[1] == 0x8B,
              data[2] == 0x08 else {
            throw KDBXError.corruptDatabase
        }

        let flags = data[3]
        guard flags & 0xE0 == 0 else {
            throw KDBXError.corruptDatabase
        }

        var offset = 10
        if flags & 0x04 != 0 {
            guard offset + 2 <= data.count else {
                throw KDBXError.corruptDatabase
            }
            let extraLength = Int(data.littleEndianUInt16(at: offset))
            offset += 2
            guard offset + extraLength <= data.count else {
                throw KDBXError.corruptDatabase
            }
            offset += extraLength
        }

        if flags & 0x08 != 0 {
            offset = try skipNullTerminatedField(in: data, from: offset)
        }

        if flags & 0x10 != 0 {
            offset = try skipNullTerminatedField(in: data, from: offset)
        }

        if flags & 0x02 != 0 {
            guard offset + 2 <= data.count else {
                throw KDBXError.corruptDatabase
            }
            offset += 2
        }

        guard offset <= data.count - 8 else {
            throw KDBXError.corruptDatabase
        }

        return data.subdata(in: offset..<(data.count - 8))
    }

    private static func skipNullTerminatedField(in data: Data, from offset: Int) throws -> Int {
        var index = offset
        while index < data.count {
            if data[index] == 0 {
                return index + 1
            }
            index += 1
        }
        throw KDBXError.corruptDatabase
    }
}
