import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public protocol BiometricGate: Sendable {
    func authenticate(reason: String) async throws -> Bool
}

public struct UnavailableBiometricGate: BiometricGate {
    public init() {}

    public func authenticate(reason: String) async throws -> Bool {
        false
    }
}

#if canImport(LocalAuthentication)
public struct LocalBiometricGate: BiometricGate {
    public init() {}

    public func authenticate(reason: String) async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return false
        }
        return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
    }
}
#endif
