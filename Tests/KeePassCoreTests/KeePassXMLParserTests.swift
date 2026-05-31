import Foundation
import XCTest
@testable import KeePassCore

final class KeePassXMLParserTests: XCTestCase {
    func testParsesDatabaseNameRootGroupNestedGroupsAndEntries() throws {
        let xml = """
        <KeePassFile>
          <Meta>
            <DatabaseName>Personal</DatabaseName>
          </Meta>
          <Root>
            <Group>
              <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
              <Name>Root</Name>
              <Entry>
                <UUID>EREREREREREREREREREREQ==</UUID>
                <String><Key>Title</Key><Value>GitHub</Value></String>
                <String><Key>UserName</Key><Value>octo</Value></String>
                <String><Key>Password</Key><Value>secret</Value></String>
                <String><Key>URL</Key><Value>https://github.com</Value></String>
                <String><Key>Notes</Key><Value>Recovery codes elsewhere</Value></String>
                <String><Key>email</Key><Value>octo@example.com</Value></String>
              </Entry>
              <Group>
                <UUID>IiIiIiIiIiIiIiIiIiIiIg==</UUID>
                <Name>Nested</Name>
              </Group>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(Data(xml.utf8))

        XCTAssertEqual(vault.name, "Personal")
        XCTAssertEqual(vault.root.title, "Root")
        XCTAssertEqual(vault.root.groups.first?.title, "Nested")
        XCTAssertEqual(vault.root.entries.first?.title, "GitHub")
        XCTAssertEqual(vault.root.entries.first?.username, "octo")
        XCTAssertEqual(vault.root.entries.first?.password, "secret")
        XCTAssertEqual(vault.root.entries.first?.url, "https://github.com")
        XCTAssertEqual(vault.root.entries.first?.notes, "Recovery codes elsewhere")
        XCTAssertEqual(vault.root.entries.first?.customFields, [
            KeePassField(name: "email", value: "octo@example.com", isProtected: false)
        ])
    }

    func testProtectedValueIsMarkedProtected() throws {
        let xml = """
        <KeePassFile>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value Protected="True">Secret Title</Value></String>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(Data(xml.utf8))

        XCTAssertEqual(vault.root.entries.first?.title, "Secret Title")
        XCTAssertEqual(vault.root.entries.first?.customFields, [KeePassField]())
    }

    func testRejectsXMLWithoutRootGroup() {
        XCTAssertThrowsError(try KeePassXMLParser.parse(Data("<KeePassFile/>".utf8))) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}
