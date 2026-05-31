import Foundation

public enum KDBX4InnerHeader {
    public static func strip(from data: Data) throws -> Data {
        guard !data.isEmpty else {
            return data
        }

        if data.first == UInt8(ascii: "<") {
            return data
        }

        var offset = 0
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
            offset += length

            if fieldID == 0 {
                return data.subdata(in: offset..<data.count)
            }
        }

        throw KDBXError.corruptDatabase
    }
}
