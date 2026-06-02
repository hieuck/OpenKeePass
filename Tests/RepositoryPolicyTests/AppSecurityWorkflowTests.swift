import Foundation
import XCTest

final class AppSecurityWorkflowTests: XCTestCase {
    func testVaultSessionCanBeLockedFromVaultUI() throws {
        let repositoryRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let sessionModel = try String(
            contentsOf: repositoryRoot.appendingPathComponent("OpenKeePassApp/VaultSessionModel.swift"),
            encoding: .utf8
        )
        let groupListView = try String(
            contentsOf: repositoryRoot.appendingPathComponent("OpenKeePassApp/GroupListView.swift"),
            encoding: .utf8
        )

        XCTAssertSourceContains(sessionModel, "func lock()")
        XCTAssertSourceContains(sessionModel, "store.lock()")
        XCTAssertSourceContains(sessionModel, "credentials = nil")
        XCTAssertSourceContains(sessionModel, "vault = nil")
        XCTAssertSourceContains(sessionModel, "isDirty = false")
        XCTAssertSourceContains(groupListView, "Label(\"Lock Vault\", systemImage: \"lock.fill\")")
        XCTAssertSourceContains(groupListView, "model.lock()")
        XCTAssertSourceContains(groupListView, "dismiss()")
    }
}

private func XCTAssertSourceContains(
    _ haystack: String,
    _ needle: String,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    XCTAssertTrue(
        haystack.contains(needle),
        "Expected to find \(needle)",
        file: file,
        line: line
    )
}
