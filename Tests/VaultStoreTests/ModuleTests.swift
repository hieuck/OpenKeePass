import XCTest
@testable import VaultStore

final class VaultStoreModuleTests: XCTestCase {
    func testModuleIsAvailable() {
        XCTAssertNotNil(VaultStoreModule.self)
    }
}
