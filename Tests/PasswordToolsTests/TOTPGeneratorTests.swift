import Foundation
import XCTest
@testable import PasswordTools

final class TOTPGeneratorTests: XCTestCase {
    func testGeneratesRFC6238SHA1Vectors() throws {
        let secret = Data("12345678901234567890".utf8)
        let generator = TOTPGenerator()

        XCTAssertEqual(try generator.code(secret: secret, timeInterval: 59, digits: 8, period: 30), "94287082")
        XCTAssertEqual(try generator.code(secret: secret, timeInterval: 1_111_111_109, digits: 8, period: 30), "07081804")
        XCTAssertEqual(try generator.code(secret: secret, timeInterval: 1_111_111_111, digits: 8, period: 30), "14050471")
        XCTAssertEqual(try generator.code(secret: secret, timeInterval: 1_234_567_890, digits: 8, period: 30), "89005924")
        XCTAssertEqual(try generator.code(secret: secret, timeInterval: 2_000_000_000, digits: 8, period: 30), "69279037")
        XCTAssertEqual(try generator.code(secret: secret, timeInterval: 20_000_000_000, digits: 8, period: 30), "65353130")
    }

    func testParsesOTPAUTHURIAndGeneratesCode() throws {
        let configuration = try TOTPConfiguration(
            uri: "otpauth://totp/GitHub:octo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8&period=30"
        )

        XCTAssertEqual(configuration.issuer, "GitHub")
        XCTAssertEqual(configuration.accountName, "octo")
        XCTAssertEqual(configuration.digits, 8)
        XCTAssertEqual(configuration.period, 30)
        XCTAssertEqual(try TOTPGenerator().code(configuration: configuration, timeInterval: 59), "94287082")
    }

    func testRejectsInvalidBase32Secret() {
        XCTAssertThrowsError(try TOTPConfiguration(uri: "otpauth://totp/Bad?secret=NOT-BASE32"))
    }

    func testCreatesConfigurationFromKeePassOTPURIField() throws {
        let configuration = try XCTUnwrap(TOTPConfiguration(keePassFields: [
            (name: "otp", value: "otpauth://totp/GitHub:octo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8")
        ]))

        XCTAssertEqual(configuration.issuer, "GitHub")
        XCTAssertEqual(configuration.accountName, "octo")
        XCTAssertEqual(configuration.digits, 8)
        XCTAssertEqual(try TOTPGenerator().code(configuration: configuration, timeInterval: 59), "94287082")
    }

    func testCreatesConfigurationFromKeePassXCTimeOTPFields() throws {
        let configuration = try XCTUnwrap(TOTPConfiguration(keePassFields: [
            (name: "TimeOtp-Secret", value: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            (name: "TimeOtp-Length", value: "8"),
            (name: "TimeOtp-Period", value: "30")
        ]))

        XCTAssertEqual(configuration.digits, 8)
        XCTAssertEqual(configuration.period, 30)
        XCTAssertEqual(try TOTPGenerator().code(configuration: configuration, timeInterval: 59), "94287082")
    }
}
