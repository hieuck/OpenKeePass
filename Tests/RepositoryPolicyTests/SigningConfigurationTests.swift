import Foundation
import XCTest

final class SigningConfigurationTests: XCTestCase {
    func testAppAndAutoFillShareRequiredEntitlements() throws {
        let repositoryRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let appEntitlements = try propertyListDictionary(
            at: repositoryRoot.appendingPathComponent("OpenKeePassApp/OpenKeePassApp.entitlements")
        )
        let autoFillEntitlements = try propertyListDictionary(
            at: repositoryRoot.appendingPathComponent("OpenKeePassAutoFill/OpenKeePassAutoFill.entitlements")
        )

        XCTAssertEqual(
            stringArray(appEntitlements["com.apple.security.application-groups"]),
            ["group.dev.openkeepass"]
        )
        XCTAssertEqual(
            stringArray(autoFillEntitlements["com.apple.security.application-groups"]),
            ["group.dev.openkeepass"]
        )
        XCTAssertEqual(
            stringArray(appEntitlements["keychain-access-groups"]),
            ["$(AppIdentifierPrefix)dev.openkeepass.shared"]
        )
        XCTAssertEqual(
            stringArray(autoFillEntitlements["keychain-access-groups"]),
            ["$(AppIdentifierPrefix)dev.openkeepass.shared"]
        )
    }

    func testWorkflowKeepsUnsignedIPAAndSupportsOptionalSignedIPA() throws {
        let repositoryRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let workflow = try String(
            contentsOf: repositoryRoot.appendingPathComponent(".github/workflows/ios.yml"),
            encoding: .utf8
        )

        XCTAssertContains(workflow, "CODE_SIGNING_ALLOWED=NO")
        XCTAssertContains(workflow, "OpenKeePass-unsigned-ipa")
        XCTAssertContains(workflow, "OPENKEEPASS_SIGNING_CERTIFICATE_BASE64")
        XCTAssertContains(workflow, "OPENKEEPASS_SIGNING_CERTIFICATE_PASSWORD")
        XCTAssertContains(workflow, "OPENKEEPASS_APP_PROVISIONING_PROFILE_BASE64")
        XCTAssertContains(workflow, "OPENKEEPASS_AUTOFILL_PROVISIONING_PROFILE_BASE64")
        XCTAssertContains(workflow, "OpenKeePass-signed-ipa")
        XCTAssertContains(workflow, "ExportOptions.plist")
        XCTAssertContains(workflow, "base64 -D")
    }

    func testProjectDefinesSeparateProvisioningProfileSettingsForAppAndAutoFill() throws {
        let repositoryRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let project = try String(
            contentsOf: repositoryRoot.appendingPathComponent("project.yml"),
            encoding: .utf8
        )

        XCTAssertContains(project, "PRODUCT_BUNDLE_IDENTIFIER: dev.openkeepass.app")
        XCTAssertContains(project, "PROVISIONING_PROFILE_SPECIFIER: $(OPENKEEPASS_APP_PROFILE_SPECIFIER)")
        XCTAssertContains(project, "PRODUCT_BUNDLE_IDENTIFIER: dev.openkeepass.app.autofill")
        XCTAssertContains(project, "PROVISIONING_PROFILE_SPECIFIER: $(OPENKEEPASS_AUTOFILL_PROFILE_SPECIFIER)")
        XCTAssertEqual(project.components(separatedBy: "com.apple.security.application-groups:").count - 1, 2)
        XCTAssertEqual(project.components(separatedBy: "keychain-access-groups:").count - 1, 2)
        XCTAssertEqual(project.components(separatedBy: "group.dev.openkeepass").count - 1, 2)
        XCTAssertEqual(project.components(separatedBy: "$(AppIdentifierPrefix)dev.openkeepass.shared").count - 1, 2)
    }
}

private func propertyListDictionary(at url: URL) throws -> [String: Any] {
    let data = try Data(contentsOf: url)
    let object = try PropertyListSerialization.propertyList(from: data, format: nil)
    guard let dictionary = object as? [String: Any] else {
        throw PropertyListError.notADictionary
    }
    return dictionary
}

private enum PropertyListError: Error {
    case notADictionary
}

private func stringArray(_ value: Any?) -> [String]? {
    if let strings = value as? [String] {
        return strings
    }
    if let array = value as? NSArray {
        return array.compactMap { $0 as? String }
    }
    return nil
}

private func XCTAssertContains(
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
