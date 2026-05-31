import Foundation

public struct AppGroupContainer: Equatable, Sendable {
    public let identifier: String

    public init(identifier: String = "group.dev.openkeepass") {
        self.identifier = identifier
    }

    public func url(fileManager: FileManager = .default) -> URL? {
        #if os(iOS)
        fileManager.containerURL(forSecurityApplicationGroupIdentifier: identifier)
        #else
        nil
        #endif
    }
}
