import Foundation

/// Attachment files of one profile. Files are kept exactly as they travel
/// over the relay (encrypted with the attachment's own key); the keys live
/// only in the profile's SecureDatabase, so crypto-erasing the vault makes
/// these files unreadable too.
public final class AttachmentStore: @unchecked Sendable {
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var dir = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
    }

    func url(_ id: String) -> URL { directory.appendingPathComponent(id) }

    public func contains(_ id: String) -> Bool {
        FileManager.default.fileExists(atPath: url(id).path)
    }

    func write(_ data: Data, id: String) throws {
        #if os(iOS)
        try data.write(to: url(id), options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url(id), options: .atomic)
        #endif
    }

    /// Memory-mapped, so even large files don't have to fit in RAM.
    func read(_ id: String) throws -> Data {
        try Data(contentsOf: url(id), options: .alwaysMapped)
    }

    func delete(_ id: String) {
        try? FileManager.default.removeItem(at: url(id))
    }
}
