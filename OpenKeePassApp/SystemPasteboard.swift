import SecurityKit
import UIKit

final class SystemPasteboard: ClipboardWriting {
    func write(_ value: String) {
        UIPasteboard.general.string = value
    }

    func clear(ifCurrentValueEquals expectedValue: String) {
        guard UIPasteboard.general.string == expectedValue else {
            return
        }
        UIPasteboard.general.string = nil
    }
}
