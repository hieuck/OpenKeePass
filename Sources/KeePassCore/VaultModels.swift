import Foundation

public struct KeePassVault: Equatable, Sendable {
    public var id: UUID
    public var name: String
    public var root: KeePassGroup

    public init(id: UUID, name: String, root: KeePassGroup) {
        self.id = id
        self.name = name
        self.root = root
    }

    public func searchEntries(matching query: String) -> [KeePassEntry] {
        let normalizedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return root.flattenedEntries().filter { entry in
            normalizedQuery.isEmpty || entry.matches(normalizedQuery)
        }
    }
}

public struct KeePassGroup: Identifiable, Equatable, Sendable {
    public var id: UUID
    public var title: String
    public var groups: [KeePassGroup]
    public var entries: [KeePassEntry]

    public init(id: UUID, title: String, groups: [KeePassGroup], entries: [KeePassEntry]) {
        self.id = id
        self.title = title
        self.groups = groups
        self.entries = entries
    }

    public func flattenedEntries() -> [KeePassEntry] {
        entries + groups.flatMap { $0.flattenedEntries() }
    }
}

public struct KeePassEntry: Identifiable, Equatable, Sendable {
    public var id: UUID
    public var title: String
    public var username: String
    public var password: String
    public var url: String
    public var notes: String
    public var customFields: [KeePassField]
    public var attachments: [KeePassAttachment]
    public var history: [KeePassEntry]

    public init(
        id: UUID,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        customFields: [KeePassField],
        attachments: [KeePassAttachment] = [],
        history: [KeePassEntry] = []
    ) {
        self.id = id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.customFields = customFields
        self.attachments = attachments
        self.history = history
    }

    public init(
        id: UUID,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        customFields: [KeePassField]
    ) {
        self.init(
            id: id,
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes,
            customFields: customFields,
            attachments: [],
            history: []
        )
    }

    public func matches(_ normalizedQuery: String) -> Bool {
        searchableValues.contains { value in
            value.lowercased().contains(normalizedQuery)
        }
    }

    private var searchableValues: [String] {
        [title, username, url, notes] + customFields.map(\.value)
    }
}

public struct KeePassField: Equatable, Sendable {
    public var name: String
    public var value: String
    public var isProtected: Bool

    public init(name: String, value: String, isProtected: Bool) {
        self.name = name
        self.value = value
        self.isProtected = isProtected
    }
}

public struct KeePassAttachment: Equatable, Sendable {
    public var name: String
    public var data: Data
    public var isProtected: Bool

    public init(name: String, data: Data, isProtected: Bool) {
        self.name = name
        self.data = data
        self.isProtected = isProtected
    }
}
