import XCTest
@testable import KeePassCore

final class KeePassCoreModuleTests: XCTestCase {
    func testModuleIsAvailable() {
        XCTAssertNotNil(KeePassCoreModule.self)
    }
}
