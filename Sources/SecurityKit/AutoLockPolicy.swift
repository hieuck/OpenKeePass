import Foundation

public struct AutoLockPolicy: Equatable, Sendable {
    public var isEnabled: Bool
    public var timeout: TimeInterval

    public init(isEnabled: Bool, timeout: TimeInterval) {
        self.isEnabled = isEnabled
        self.timeout = timeout
    }

    public func shouldLock(now: Date, lastInactiveAt: Date?) -> Bool {
        guard isEnabled, timeout > 0, let lastInactiveAt else {
            return false
        }
        return now.timeIntervalSince(lastInactiveAt) >= timeout
    }
}
