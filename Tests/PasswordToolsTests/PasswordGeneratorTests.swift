import XCTest
@testable import PasswordTools

final class PasswordGeneratorTests: XCTestCase {
    func testGeneratesRequestedLength() {
        let generator = PasswordGenerator(random: .deterministic(seed: 1))

        let password = generator.generate(options: .init(length: 24))

        XCTAssertEqual(password.count, 24)
    }

    func testIncludesEnabledCharacterClasses() {
        let generator = PasswordGenerator(random: .deterministic(seed: 2))

        let password = generator.generate(
            options: .init(
                length: 32,
                includeUppercase: true,
                includeLowercase: true,
                includeDigits: true,
                includeSymbols: true
            )
        )

        XCTAssertTrue(password.contains(where: { $0.isUppercase }))
        XCTAssertTrue(password.contains(where: { $0.isLowercase }))
        XCTAssertTrue(password.contains(where: { $0.isNumber }))
        XCTAssertTrue(password.contains(where: { "!@#$%^&*()-_=+[]{};:,.?/".contains($0) }))
    }

    func testRejectsEmptyCharacterSet() {
        let generator = PasswordGenerator(random: .deterministic(seed: 3))

        XCTAssertThrowsError(
            try generator.generateStrict(
                options: .init(
                    length: 16,
                    includeUppercase: false,
                    includeLowercase: false,
                    includeDigits: false,
                    includeSymbols: false
                )
            )
        ) { error in
            XCTAssertEqual(error as? PasswordGeneratorError, .emptyCharacterSet)
        }
    }

    func testCanExcludeAmbiguousCharacters() throws {
        let generator = PasswordGenerator(random: .deterministic(seed: 4))

        let password = try generator.generateStrict(
            options: .init(
                length: 64,
                includeUppercase: false,
                includeLowercase: false,
                includeDigits: true,
                includeSymbols: false,
                excludeAmbiguousCharacters: true
            )
        )

        XCTAssertFalse(password.contains("0"))
        XCTAssertFalse(password.contains("1"))
        XCTAssertTrue(password.allSatisfy { "23456789".contains($0) })
    }
}
