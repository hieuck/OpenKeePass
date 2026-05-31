import Foundation

public enum KeePassXMLParser {
    public static func parse(
        _ data: Data,
        protectedStream: KDBX4InnerHeader.ProtectedStream? = nil
    ) throws -> KeePassVault {
        guard var xml = String(data: data, encoding: .utf8) else {
            throw KDBXError.corruptDatabase
        }
        if let protectedStream {
            xml = try decryptProtectedValues(in: xml, protectedStream: protectedStream)
        }

        let databaseName = firstText(in: xml, tag: "DatabaseName") ?? "KeePass"
        guard let rootContent = firstContent(in: xml, tag: "Root"),
              let rootGroupXML = firstElement(in: rootContent, tag: "Group") else {
            throw KDBXError.corruptDatabase
        }

        let binaryPool = try parseBinaryPool(in: xml)
        let rootGroup = try parseGroup(rootGroupXML, binaryPool: binaryPool)
        return KeePassVault(id: rootGroup.id, name: databaseName, root: rootGroup)
    }

    private static func parseGroup(_ xml: String, binaryPool: [String: Data]) throws -> KeePassGroup {
        let id = uuid(from: firstText(in: xml, tag: "UUID")) ?? UUID()
        let title = firstDirectText(in: xml, tag: "Name") ?? "Group"
        let childEntryXMLs = directElements(in: xml, tag: "Entry")
        let childGroupXMLs = directElements(in: xml, tag: "Group")
        let entries = try childEntryXMLs.map { try parseEntry($0, includeHistory: true, binaryPool: binaryPool) }
        let groups = try childGroupXMLs.map { try parseGroup($0, binaryPool: binaryPool) }
        return KeePassGroup(id: id, title: title, groups: groups, entries: entries)
    }

    private static func parseEntry(_ xml: String, includeHistory: Bool, binaryPool: [String: Data]) throws -> KeePassEntry {
        let id = uuid(from: firstDirectText(in: xml, tag: "UUID")) ?? UUID()
        let entryFieldsXML = removingDirectElements(tag: "History", from: xml)
        var fields: [String: KeePassField] = [:]

        for stringXML in directElements(in: entryFieldsXML, tag: "String") {
            guard let key = firstText(in: stringXML, tag: "Key"),
                  let valueElement = firstElement(in: stringXML, tag: "Value") else {
                continue
            }
            let value = innerText(of: valueElement)
            let isProtected = valueElement.localizedCaseInsensitiveContains("Protected=\"True\"")
                || valueElement.localizedCaseInsensitiveContains("Protected=\"true\"")
            fields[key] = KeePassField(name: key, value: value, isProtected: isProtected)
        }

        let standardKeys = Set(["Title", "UserName", "Password", "URL", "Notes"])
        let customFields = fields
            .filter { !standardKeys.contains($0.key) }
            .sorted { $0.key < $1.key }
            .map(\.value)
        let attachments = try directElements(in: entryFieldsXML, tag: "Binary").compactMap { try parseAttachment($0, binaryPool: binaryPool) }
        let history = includeHistory ? try parseHistory(in: xml, binaryPool: binaryPool) : []

        return KeePassEntry(
            id: id,
            title: fields["Title"]?.value ?? "",
            username: fields["UserName"]?.value ?? "",
            password: fields["Password"]?.value ?? "",
            url: fields["URL"]?.value ?? "",
            notes: fields["Notes"]?.value ?? "",
            customFields: customFields,
            attachments: attachments,
            history: history
        )
    }

    private static func parseHistory(in xml: String, binaryPool: [String: Data]) throws -> [KeePassEntry] {
        guard let historyXML = firstDirectElement(in: xml, tag: "History") else {
            return []
        }
        return try directElements(in: historyXML, tag: "Entry").map { try parseEntry($0, includeHistory: false, binaryPool: binaryPool) }
    }

    private static func parseAttachment(_ xml: String, binaryPool: [String: Data]) throws -> KeePassAttachment? {
        guard let key = firstText(in: xml, tag: "Key"),
              let valueElement = firstElement(in: xml, tag: "Value") ?? firstSelfClosingElement(in: xml, tag: "Value") else {
            return nil
        }
        let valueTag = openingTag(of: valueElement)
        if let referenceID = attributeValue(named: "Ref", in: valueTag) {
            guard let data = binaryPool[referenceID] else {
                throw KDBXError.corruptDatabase
            }
            return KeePassAttachment(name: key, data: data, isProtected: false)
        }
        let encoded = innerText(of: valueElement)
        guard let data = Data(base64Encoded: encoded) else {
            throw KDBXError.corruptDatabase
        }
        let isProtected = valueTag.localizedCaseInsensitiveContains("Protected=\"True\"")
            || valueTag.localizedCaseInsensitiveContains("Protected=\"true\"")
        return KeePassAttachment(name: key, data: data, isProtected: isProtected)
    }

    private static func parseBinaryPool(in xml: String) throws -> [String: Data] {
        guard let metaXML = firstElement(in: xml, tag: "Meta"),
              let binariesXML = firstElement(in: metaXML, tag: "Binaries") else {
            return [:]
        }

        var pool: [String: Data] = [:]
        for binaryXML in directElements(in: binariesXML, tag: "Binary") {
            let tag = openingTag(of: binaryXML)
            guard let id = attributeValue(named: "ID", in: tag) else {
                continue
            }
            let encoded = innerText(of: binaryXML)
            guard let encodedData = Data(base64Encoded: encoded) else {
                throw KDBXError.corruptDatabase
            }
            if attributeValue(named: "Compressed", in: tag)?.caseInsensitiveCompare("True") == .orderedSame {
                pool[id] = try KDBXPayloadCompression.decode(encodedData, compression: .gzip)
            } else {
                pool[id] = encodedData
            }
        }
        return pool
    }

    private static func uuid(from base64: String?) -> UUID? {
        guard let base64, let data = Data(base64Encoded: base64), data.count == 16 else {
            return nil
        }
        let bytes = [UInt8](data)
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    private static func firstDirectText(in xml: String, tag: String) -> String? {
        firstDirectElement(in: xml, tag: tag).map(innerText)
    }

    private static func firstText(in xml: String, tag: String) -> String? {
        firstElement(in: xml, tag: tag).map(innerText)
    }

    private static func firstContent(in xml: String, tag: String) -> String? {
        guard let element = firstElement(in: xml, tag: tag) else {
            return nil
        }
        return innerText(of: element)
    }

    private static func firstDirectElement(in xml: String, tag: String) -> String? {
        directElements(in: xml, tag: tag).first
    }

    private static func firstElement(in xml: String, tag: String) -> String? {
        let openPrefix = "<\(tag)"
        guard let openStart = xml.range(of: openPrefix),
              let openEnd = xml[openStart.upperBound...].firstIndex(of: ">") else {
            return nil
        }
        let close = "</\(tag)>"
        var depth = 1
        var cursor = xml.index(after: openEnd)

        while depth > 0 {
            let nextOpen = xml[cursor...].range(of: openPrefix)
            let nextClose = xml[cursor...].range(of: close)
            guard let closeRange = nextClose else {
                return nil
            }

            if let openRange = nextOpen, openRange.lowerBound < closeRange.lowerBound {
                depth += 1
                cursor = xml.index(after: openRange.lowerBound)
            } else {
                depth -= 1
                cursor = closeRange.upperBound
                if depth == 0 {
                    return String(xml[openStart.lowerBound..<closeRange.upperBound])
                }
            }
        }

        return nil
    }

    private static func firstSelfClosingElement(in xml: String, tag: String) -> String? {
        let openPrefix = "<\(tag)"
        guard let openStart = xml.range(of: openPrefix),
              let openEnd = xml[openStart.upperBound...].firstIndex(of: ">") else {
            return nil
        }
        let element = String(xml[openStart.lowerBound...openEnd])
        return element.hasSuffix("/>") ? element : nil
    }

    private static func directElements(in xml: String, tag: String) -> [String] {
        guard let outerContent = contentInsideOuterElement(xml) else {
            return []
        }

        var result: [String] = []
        var searchStart = outerContent.startIndex
        let openPrefix = "<\(tag)"
        let close = "</\(tag)>"

        while let openStart = outerContent[searchStart...].range(of: openPrefix)?.lowerBound {
            guard let openEnd = outerContent[openStart...].firstIndex(of: ">") else {
                break
            }

            var depth = 1
            var cursor = outerContent.index(after: openEnd)
            while depth > 0 {
                let nextOpen = outerContent[cursor...].range(of: openPrefix)
                let nextClose = outerContent[cursor...].range(of: close)
                guard let closeRange = nextClose else {
                    return result
                }

                if let openRange = nextOpen, openRange.lowerBound < closeRange.lowerBound {
                    depth += 1
                    cursor = outerContent.index(after: openRange.lowerBound)
                } else {
                    depth -= 1
                    cursor = closeRange.upperBound
                    if depth == 0 {
                        result.append(String(outerContent[openStart..<closeRange.upperBound]))
                        searchStart = closeRange.upperBound
                    }
                }
            }
        }

        return result
    }

    private static func removingDirectElements(tag: String, from xml: String) -> String {
        var result = xml
        while let element = firstDirectElement(in: result, tag: tag),
              let range = result.range(of: element) {
            result.removeSubrange(range)
        }
        return result
    }

    private static func contentInsideOuterElement(_ xml: String) -> Substring? {
        guard let openEnd = xml.firstIndex(of: ">"),
              let closeStart = xml.range(of: "</", options: .backwards)?.lowerBound,
              openEnd < closeStart else {
            return nil
        }
        return xml[xml.index(after: openEnd)..<closeStart]
    }

    private static func innerText(of element: String) -> String {
        guard let content = contentInsideOuterElement(element) else {
            return ""
        }
        return decodeXML(String(content).trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private static func openingTag(of element: String) -> String {
        guard let end = element.firstIndex(of: ">") else {
            return element
        }
        return String(element[...end])
    }

    private static func attributeValue(named name: String, in tag: String) -> String? {
        for quote in ["\"", "'"] {
            let prefix = "\(name)=\(quote)"
            guard let start = tag.range(of: prefix, options: .caseInsensitive) else {
                continue
            }
            let valueStart = start.upperBound
            guard let end = tag[valueStart...].firstIndex(of: Character(quote)) else {
                return nil
            }
            return String(tag[valueStart..<end])
        }
        return nil
    }

    private static func decodeXML(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&apos;", with: "'")
            .replacingOccurrences(of: "&amp;", with: "&")
    }

    private static func decryptProtectedValues(
        in xml: String,
        protectedStream: KDBX4InnerHeader.ProtectedStream
    ) throws -> String {
        var chaCha20Stream: ChaCha20Stream?
        var salsa20Stream: Salsa20Stream?
        var result = ""
        var cursor = xml.startIndex
        let valuePrefix = "<Value"

        while let valueStart = xml[cursor...].range(of: valuePrefix)?.lowerBound {
            guard let openEnd = xml[valueStart...].firstIndex(of: ">") else {
                throw KDBXError.corruptDatabase
            }
            let openTag = String(xml[valueStart...openEnd])
            let contentStart = xml.index(after: openEnd)
            guard let closeRange = xml[contentStart...].range(of: "</Value>") else {
                throw KDBXError.corruptDatabase
            }

            result.append(contentsOf: xml[cursor..<contentStart])
            let content = String(xml[contentStart..<closeRange.lowerBound])
            if isProtectedValueTag(openTag) {
                let encryptedBase64 = decodeXML(content.trimmingCharacters(in: .whitespacesAndNewlines))
                guard let encrypted = Data(base64Encoded: encryptedBase64) else {
                    throw KDBXError.corruptDatabase
                }
                let decrypted: Data
                switch protectedStream.algorithm {
                case .chaCha20:
                    if chaCha20Stream == nil {
                        chaCha20Stream = try ChaCha20Stream.protectedValueStream(innerKey: protectedStream.key)
                    }
                    decrypted = try chaCha20Stream!.apply(to: encrypted)
                case .salsa20:
                    if salsa20Stream == nil {
                        salsa20Stream = try Salsa20Stream.protectedValueStream(key: protectedStream.key)
                    }
                    decrypted = try salsa20Stream!.apply(to: encrypted)
                }
                guard let decryptedValue = String(data: decrypted, encoding: .utf8) else {
                    throw KDBXError.corruptDatabase
                }
                result.append(encodeXML(decryptedValue))
            } else {
                result.append(content)
            }

            cursor = closeRange.lowerBound
        }

        result.append(contentsOf: xml[cursor...])
        return result
    }

    private static func isProtectedValueTag(_ tag: String) -> Bool {
        tag.localizedCaseInsensitiveContains("Protected=\"True\"")
            || tag.localizedCaseInsensitiveContains("Protected=\"true\"")
    }

    private static func encodeXML(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}
