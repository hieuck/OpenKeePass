import Foundation

public protocol BiometricGate: Sendable {
    func authenticate(reason: String) async throws -> Bool
}

public struct UnavailableBiometricGate: BiometricGate {
    public init() {}

    public func authenticate(reason: String) async throws -> Bool {
        false
    }
}
