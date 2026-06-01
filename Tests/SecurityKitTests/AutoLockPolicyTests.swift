import Foundation
import XCTest
@testable import SecurityKit

final class AutoLockPolicyTests: XCTestCase {
    func testDoesNotLockWhenDisabled() {
        let policy = AutoLockPolicy(isEnabled: false, timeout: 60)
        let lastInactiveAt = Date(timeIntervalSince1970: 100)

        XCTAssertFalse(policy.shouldLock(now: Date(timeIntervalSince1970: 1_000), lastInactiveAt: lastInactiveAt))
    }

    func testDoesNotLockBeforeTimeout() {
        let policy = AutoLockPolicy(isEnabled: true, timeout: 300)
        let lastInactiveAt = Date(timeIntervalSince1970: 100)

        XCTAssertFalse(policy.shouldLock(now: Date(timeIntervalSince1970: 399), lastInactiveAt: lastInactiveAt))
    }

    func testLocksAtTimeout() {
        let policy = AutoLockPolicy(isEnabled: true, timeout: 300)
        let lastInactiveAt = Date(timeIntervalSince1970: 100)

        XCTAssertTrue(policy.shouldLock(now: Date(timeIntervalSince1970: 400), lastInactiveAt: lastInactiveAt))
    }

    func testManualLockIsAvailableOnlyWhenProtectionIsEnabled() {
        XCTAssertTrue(AutoLockPolicy(isEnabled: true, timeout: 300).canLockManually)
        XCTAssertFalse(AutoLockPolicy(isEnabled: false, timeout: 300).canLockManually)
    }
}
