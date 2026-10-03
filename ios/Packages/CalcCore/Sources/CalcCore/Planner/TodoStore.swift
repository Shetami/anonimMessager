import Foundation

public struct TodoItem: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var title: String
    /// Start of the day the task is planned for.
    public var day: Date
    public var done: Bool
    public let created: Date
}

/// Task list for the daily planner disguise, persisted as a plain JSON file.
///
/// Any new task may be an unlock code, and a code must never reach disk. So a
/// candidate task is added as *held*: it shows up instantly, exactly like any
/// other task, but is left out of every save until the caller either
/// `release`s it (wrong code, so it's an ordinary task) or `discard`s it (the
/// code opened the vault).
public struct TodoStore: Sendable {
    public private(set) var items: [TodoItem] = []
    private var held: Set<UUID> = []
    private let fileURL: URL?
    private let calendar: Calendar

    /// `fileURL == nil` keeps everything in memory (previews, tests).
    public init(fileURL: URL?, calendar: Calendar = .current) {
        self.fileURL = fileURL
        self.calendar = calendar
        if let fileURL, let data = try? Data(contentsOf: fileURL),
           let saved = try? JSONDecoder().decode([TodoItem].self, from: data) {
            items = saved
        }
    }

    /// Canonical form of a task title.
    public static func normalize(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
    }

    /// The vault code a typed text stands for. Case-insensitive, because the
    /// task field auto-capitalizes while the settings code field does not.
    public static func code(from text: String) -> String {
        normalize(text).lowercased()
    }

    public func items(on day: Date) -> [TodoItem] {
        items.filter { calendar.isDate($0.day, inSameDayAs: day) }
    }

    public func hasOpenItems(on day: Date) -> Bool {
        items.contains { !$0.done && calendar.isDate($0.day, inSameDayAs: day) }
    }

    @discardableResult
    public mutating func add(_ title: String, on day: Date, held: Bool = false) -> TodoItem? {
        let title = Self.normalize(title)
        guard !title.isEmpty else { return nil }
        let item = TodoItem(id: UUID(), title: title, day: calendar.startOfDay(for: day), done: false, created: Date())
        items.append(item)
        if held {
            self.held.insert(item.id)
        } else {
            save()
        }
        return item
    }

    /// The held task turned out to be an ordinary task: persist it.
    public mutating func release(_ id: UUID) {
        guard held.remove(id) != nil else { return }
        save()
    }

    /// The held task was an unlock code: forget it without it ever being saved.
    public mutating func discard(_ id: UUID) {
        guard held.remove(id) != nil else { return }
        items.removeAll { $0.id == id }
    }

    public mutating func toggle(_ id: UUID) {
        mutate(id) { $0.done.toggle() }
    }

    public mutating func move(_ id: UUID, to day: Date) {
        let day = calendar.startOfDay(for: day)
        mutate(id) { $0.day = day }
    }

    public mutating func remove(_ id: UUID) {
        items.removeAll { $0.id == id }
        held.remove(id)
        save()
    }

    private mutating func mutate(_ id: UUID, _ change: (inout TodoItem) -> Void) {
        guard let i = items.firstIndex(where: { $0.id == id }) else { return }
        change(&items[i])
        save()
    }

    private func save() {
        guard let fileURL else { return }
        let persisted = items.filter { !held.contains($0.id) }
        guard let data = try? JSONEncoder().encode(persisted) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        #if os(iOS)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try? data.write(to: fileURL, options: .atomic)
        #endif
        // Mistyped codes end up here as tasks; keep them out of iCloud backups.
        var url = fileURL
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
}
