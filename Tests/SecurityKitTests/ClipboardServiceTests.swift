import XCTest
@testable import SecurityKit

final class ClipboardServiceTests: XCTestCase {
    func testCopyWritesValueImmediately() {
        let pasteboard = MemoryPasteboard()
        let scheduler = ManualClipboardScheduler()
        let service = ClipboardService(pasteboard: pasteboard, scheduler: scheduler)

        service.copy("secret", expiration: 30)

        XCTAssertEqual(pasteboard.value, "secret")
    }

    func testExpirationClearsMatchingValue() {
        let pasteboard = MemoryPasteboard()
        let scheduler = ManualClipboardScheduler()
        let service = ClipboardService(pasteboard: pasteboard, scheduler: scheduler)
        service.copy("secret", expiration: 30)

        scheduler.runNext()

        XCTAssertEqual(pasteboard.value, nil)
    }

    func testExpirationDoesNotClearNewerClipboardValue() {
        let pasteboard = MemoryPasteboard()
        let scheduler = ManualClipboardScheduler()
        let service = ClipboardService(pasteboard: pasteboard, scheduler: scheduler)
        service.copy("old", expiration: 30)
        service.copy("new", expiration: 30)

        scheduler.runNext()

        XCTAssertEqual(pasteboard.value, "new")
    }
}

private final class MemoryPasteboard: ClipboardWriting {
    var value: String?

    func write(_ value: String) {
        self.value = value
    }

    func clear(ifCurrentValueEquals expectedValue: String) {
        if value == expectedValue {
            value = nil
        }
    }
}

private final class ManualClipboardScheduler: ClipboardScheduling {
    private var actions: [() -> Void] = []

    func schedule(after seconds: TimeInterval, action: @escaping () -> Void) {
        actions.append(action)
    }

    func runNext() {
        guard !actions.isEmpty else {
            return
        }
        actions.removeFirst()()
    }
}
