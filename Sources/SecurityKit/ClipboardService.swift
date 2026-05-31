import Foundation

public protocol ClipboardWriting: AnyObject {
    func write(_ value: String)
    func clear(ifCurrentValueEquals expectedValue: String)
}

public protocol ClipboardScheduling: AnyObject {
    func schedule(after seconds: TimeInterval, action: @escaping () -> Void)
}

public final class ClipboardService {
    private let pasteboard: ClipboardWriting
    private let scheduler: ClipboardScheduling

    public init(pasteboard: ClipboardWriting, scheduler: ClipboardScheduling) {
        self.pasteboard = pasteboard
        self.scheduler = scheduler
    }

    public func copy(_ value: String, expiration: TimeInterval) {
        pasteboard.write(value)
        scheduler.schedule(after: expiration) { [weak pasteboard] in
            pasteboard?.clear(ifCurrentValueEquals: value)
        }
    }
}

public final class DispatchClipboardScheduler: ClipboardScheduling {
    public init() {}

    public func schedule(after seconds: TimeInterval, action: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: action)
    }
}
