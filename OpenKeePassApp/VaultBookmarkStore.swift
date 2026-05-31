import Foundation

struct VaultBookmarkStore {
    private let defaults: UserDefaults
    private let bookmarkKey = "vault.recentBookmark"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func save(_ url: URL) throws {
        let bookmark = try url.bookmarkData(
            options: [],
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        )
        defaults.set(bookmark, forKey: bookmarkKey)
    }

    func restore() -> URL? {
        guard let bookmark = defaults.data(forKey: bookmarkKey) else {
            return nil
        }

        var isStale = false
        guard let url = try? URL(
            resolvingBookmarkData: bookmark,
            options: [],
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        ), !isStale else {
            clear()
            return nil
        }

        return url
    }

    func clear() {
        defaults.removeObject(forKey: bookmarkKey)
    }
}
