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

    func testDecryptsProtectedValuesWithChaCha20StreamInDocumentOrder() throws {
        let innerKey = Data(0x00...0x3F)
        var stream = try ChaCha20Stream.protectedValueStream(innerKey: innerKey)
        let encryptedPassword = try stream.apply(to: Data("secret".utf8)).base64EncodedString()
        let encryptedNotes = try stream.apply(to: Data("notes".utf8)).base64EncodedString()
        let xml = """
        <KeePassFile>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Password</Key><Value Protected="True">\(encryptedPassword)</Value></String>
                <String><Key>Notes</Key><Value Protected="True">\(encryptedNotes)</Value></String>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(
            Data(xml.utf8),
            protectedStream: .init(algorithm: .chaCha20, key: innerKey)
        )

        XCTAssertEqual(vault.root.entries.first?.password, "secret")
        XCTAssertEqual(vault.root.entries.first?.notes, "notes")
    }

    func testParsesInlineEntryAttachments() throws {
        let xml = """
        <KeePassFile>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>Document</Value></String>
                <Binary><Key>recovery.txt</Key><Value>cmVjb3ZlcnktY29kZQ==</Value></Binary>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(Data(xml.utf8))

        XCTAssertEqual(vault.root.entries.first?.attachments, [
            KeePassAttachment(name: "recovery.txt", data: Data("recovery-code".utf8), isProtected: false)
        ])
    }

    func testParsesBinaryPoolAttachmentReferences() throws {
        let xml = """
        <KeePassFile>
          <Meta>
            <Binaries>
              <Binary ID="0">cmVmZXJlbmNlZC1kYXRh</Binary>
            </Binaries>
          </Meta>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>Document</Value></String>
                <Binary><Key>referenced.txt</Key><Value Ref="0"></Value></Binary>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(Data(xml.utf8))

        XCTAssertEqual(vault.root.entries.first?.attachments, [
            KeePassAttachment(name: "referenced.txt", data: Data("referenced-data".utf8), isProtected: false)
        ])
    }

    func testParsesCompressedBinaryPoolAttachmentReferences() throws {
        let xml = """
        <KeePassFile>
          <Meta>
            <Binaries>
              <Binary ID="0" Compressed="True">H4sIAAAAAAAACkvOzy0oSi0uTk3RTUksSQQA14gwtg8AAAA=</Binary>
            </Binaries>
          </Meta>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <Binary><Key>compressed.txt</Key><Value Ref="0"></Value></Binary>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(Data(xml.utf8))

        XCTAssertEqual(vault.root.entries.first?.attachments, [
            KeePassAttachment(name: "compressed.txt", data: Data("compressed-data".utf8), isProtected: false)
        ])
    }

    func testParsesEntryHistory() throws {
        let xml = """
        <KeePassFile>
          <Root>
            <Group>
              <Name>Root</Name>
              <Entry>
                <String><Key>Title</Key><Value>GitHub</Value></String>
                <String><Key>UserName</Key><Value>current-user</Value></String>
                <History>
                  <Entry>
                    <String><Key>Title</Key><Value>GitHub</Value></String>
                    <String><Key>UserName</Key><Value>previous-user</Value></String>
                    <String><Key>Password</Key><Value>old-secret</Value></String>
                  </Entry>
                </History>
              </Entry>
            </Group>
          </Root>
        </KeePassFile>
        """

        let vault = try KeePassXMLParser.parse(Data(xml.utf8))

        XCTAssertEqual(vault.root.entries.first?.history.first?.username, "previous-user")
        XCTAssertEqual(vault.root.entries.first?.history.first?.password, "old-secret")
    }

    func testRejectsXMLWithoutRootGroup() {
        XCTAssertThrowsError(try KeePassXMLParser.parse(Data("<KeePassFile/>".utf8))) { error in
            XCTAssertEqual(error as? KDBXError, .corruptDatabase)
        }
    }
}
