import XCTest
@testable import SecurityKit

final class SecurityKitModuleTests: XCTestCase {
    func testModuleIsAvailable() {
        XCTAssertNotNil(SecurityKitModule.self)
    }
}
