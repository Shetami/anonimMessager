import CryptoKit
import Foundation
import SQLite3

public enum DatabaseError: Error {
    case sqlite(String)
    case decrypt
}

/// Encrypted key/value store on top of SQLite.
///
/// Every value is sealed with ChaCha20-Poly1305 under the profile's database
/// key, with the row's identity as associated data so rows cannot be swapped.
/// Collection names, record keys and grouping keys are replaced by keyed
/// HMACs, and sort keys (timestamps) travel inside the ciphertext, so the
/// file reveals only row counts and sizes — nothing about who you talk to,
/// what was said or when.
public final class SecureDatabase: @unchecked Sendable {
    private var db: OpaquePointer?
    private let dataKey: SymmetricKey
    private let indexKey: SymmetricKey
    private let queue = DispatchQueue(label: "calc.db")
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    public let url: URL

    public init(url: URL, profile: UnlockedProfile) throws {
        self.url = url
        self.dataKey = profile.databaseKey
        self.indexKey = profile.indexKey
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        #if os(iOS)
        let protection = SQLITE_OPEN_FILEPROTECTION_COMPLETE
        #else
        let protection: Int32 = 0
        #endif
        guard sqlite3_open_v2(url.path, &db, flags | protection, nil) == SQLITE_OK else {
            throw DatabaseError.sqlite("open")
        }
        // secure_delete zeroes freed pages; no WAL so nothing lingers in side files.
        try exec("""
            PRAGMA secure_delete = ON;
            PRAGMA journal_mode = DELETE;
            PRAGMA temp_store = MEMORY;
            """)
        try migrate()
        var u = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? u.setResourceValues(values)
    }

    deinit {
        sqlite3_close_v2(db)
    }

    // MARK: - Public API

    public func put<T: Encodable>(_ value: T, collection: String, key: String, group: String? = nil, sort: Int64 = 0) throws {
        let c = mac(collection)
        let k = mac(collection + "\u{0}" + key)
        let sealed = try seal(try encoder.encode(value), sort: sort, c: c, k: k)
        try queue.sync {
            try run("INSERT OR REPLACE INTO r (c, k, g, v) VALUES (?, ?, ?, ?)",
                    [.blob(c), .blob(k), group.map { .blob(mac(collection + "\u{1}" + $0)) } ?? .null, .blob(sealed)])
        }
    }

    public func get<T: Decodable>(_ type: T.Type, collection: String, key: String) throws -> T? {
        let c = mac(collection)
        let k = mac(collection + "\u{0}" + key)
        let rows = try queue.sync {
            try query("SELECT k, v FROM r WHERE c = ? AND k = ?", [.blob(c), .blob(k)])
        }
        guard let row = rows.first else { return nil }
        return try open(T.self, c: c, k: row.0, v: row.1).value
    }

    /// Lists a collection (optionally only one group) ordered by sort key.
    /// The sort key is encrypted, so ordering happens after decryption.
    public func list<T: Decodable>(_ type: T.Type, collection: String, group: String? = nil) throws -> [T] {
        let c = mac(collection)
        let rows = try queue.sync { () -> [(Data, Data)] in
            if let group {
                return try query("SELECT k, v FROM r WHERE c = ? AND g = ?",
                                 [.blob(c), .blob(mac(collection + "\u{1}" + group))])
            }
            return try query("SELECT k, v FROM r WHERE c = ?", [.blob(c)])
        }
        return try rows.enumerated()
            .map { (offset: $0.offset, record: try open(T.self, c: c, k: $0.element.0, v: $0.element.1)) }
            .sorted { ($0.record.sort, $0.offset) < ($1.record.sort, $1.offset) }
            .map(\.record.value)
    }

    public func delete(collection: String, key: String) throws {
        let c = mac(collection)
        try queue.sync {
            try run("DELETE FROM r WHERE c = ? AND k = ?", [.blob(c), .blob(mac(collection + "\u{0}" + key))])
        }
    }

    public func deleteGroup(collection: String, group: String) throws {
        try queue.sync {
            try run("DELETE FROM r WHERE c = ? AND g = ?", [.blob(mac(collection)), .blob(mac(collection + "\u{1}" + group))])
        }
    }

    public func deleteCollection(_ collection: String) throws {
        try queue.sync { try run("DELETE FROM r WHERE c = ?", [.blob(mac(collection))]) }
    }

    /// Wipes every row and rebuilds the file so freed pages are gone too.
    public func wipeAll() throws {
        try queue.sync {
            try exec("DELETE FROM r; VACUUM;")
        }
    }

    // MARK: - Internals

    private func mac(_ s: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(s.utf8), using: indexKey)).prefix(16)
    }

    /// Sealed value = ChaChaPoly(sort[8, big-endian] || json), bound to the row.
    private func seal(_ json: Data, sort: Int64, c: Data, k: Data) throws -> Data {
        var plaintext = withUnsafeBytes(of: sort.bigEndian) { Data($0) }
        plaintext.append(json)
        return try ChaChaPoly.seal(plaintext, using: dataKey, authenticating: c + k).combined
    }

    private func decrypt(c: Data, k: Data, v: Data) throws -> Data {
        guard let box = try? ChaChaPoly.SealedBox(combined: v),
              let plaintext = try? ChaChaPoly.open(box, using: dataKey, authenticating: c + k)
        else { throw DatabaseError.decrypt }
        return plaintext
    }

    private func open<T: Decodable>(_ type: T.Type, c: Data, k: Data, v: Data) throws -> (sort: Int64, value: T) {
        let plaintext = try decrypt(c: c, k: k, v: v)
        guard plaintext.count >= 8 else { throw DatabaseError.decrypt }
        let sort = Int64(bitPattern: plaintext.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
        return (sort, try decoder.decode(T.self, from: plaintext.dropFirst(8)))
    }

    // MARK: - Schema

    static let schemaVersion: Int64 = 1

    private static let schema = """
        CREATE TABLE r (
            c BLOB NOT NULL,
            k BLOB NOT NULL,
            g BLOB,
            v BLOB NOT NULL,
            PRIMARY KEY (c, k)
        ) WITHOUT ROWID;
        CREATE INDEX r_g ON r (c, g);
        """

    private func migrate() throws {
        guard try scalar("PRAGMA user_version") < Self.schemaVersion else { return }
        try exec("BEGIN IMMEDIATE")
        do {
            if try scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'r'") == 0 {
                try exec(Self.schema)
            } else {
                try migrateFromV0()
            }
            try exec("PRAGMA user_version = \(Self.schemaVersion); COMMIT")
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
        // Rebuild the file so pages that held plaintext sort keys are gone.
        try exec("VACUUM")
    }

    /// Version 0 kept sort keys (message timestamps) in a plaintext column.
    /// Moves them into the ciphertext.
    private func migrateFromV0() throws {
        let stmt = try prepare("SELECT c, k, g, s, v FROM r", [])
        defer { sqlite3_finalize(stmt) }
        var rows: [(c: Data, k: Data, g: Data?, s: Int64, v: Data)] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw DatabaseError.sqlite(String(cString: sqlite3_errmsg(db))) }
            let g = sqlite3_column_type(stmt, 2) == SQLITE_NULL ? nil : column(stmt, 2)
            rows.append((column(stmt, 0), column(stmt, 1), g, sqlite3_column_int64(stmt, 3), column(stmt, 4)))
        }
        try exec("DROP TABLE r;" + Self.schema)
        for row in rows {
            let sealed = try seal(try decrypt(c: row.c, k: row.k, v: row.v), sort: row.s, c: row.c, k: row.k)
            try run("INSERT INTO r (c, k, g, v) VALUES (?, ?, ?, ?)",
                    [.blob(row.c), .blob(row.k), row.g.map { .blob($0) } ?? .null, .blob(sealed)])
        }
    }

    private func scalar(_ sql: String) throws -> Int64 {
        let stmt = try prepare(sql, [])
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { throw DatabaseError.sqlite(String(cString: sqlite3_errmsg(db))) }
        return sqlite3_column_int64(stmt, 0)
    }

    private enum Bind {
        case blob(Data), int(Int64), null
    }

    private func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(db, sql, nil, nil, &err) == SQLITE_OK else {
            let msg = err.map { String(cString: $0) } ?? "exec"
            sqlite3_free(err)
            throw DatabaseError.sqlite(msg)
        }
    }

    private func prepare(_ sql: String, _ binds: [Bind]) throws -> OpaquePointer? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw DatabaseError.sqlite(String(cString: sqlite3_errmsg(db)))
        }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (i, b) in binds.enumerated() {
            let idx = Int32(i + 1)
            switch b {
            case .blob(let d):
                _ = d.withUnsafeBytes { sqlite3_bind_blob(stmt, idx, $0.baseAddress, Int32(d.count), transient) }
            case .int(let n):
                sqlite3_bind_int64(stmt, idx, n)
            case .null:
                sqlite3_bind_null(stmt, idx)
            }
        }
        return stmt
    }

    private func run(_ sql: String, _ binds: [Bind]) throws {
        let stmt = try prepare(sql, binds)
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw DatabaseError.sqlite(String(cString: sqlite3_errmsg(db)))
        }
    }

    private func query(_ sql: String, _ binds: [Bind]) throws -> [(Data, Data)] {
        let stmt = try prepare(sql, binds)
        defer { sqlite3_finalize(stmt) }
        var out: [(Data, Data)] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw DatabaseError.sqlite(String(cString: sqlite3_errmsg(db))) }
            out.append((column(stmt, 0), column(stmt, 1)))
        }
        return out
    }

    private func column(_ stmt: OpaquePointer?, _ i: Int32) -> Data {
        let n = Int(sqlite3_column_bytes(stmt, i))
        guard n > 0, let p = sqlite3_column_blob(stmt, i) else { return Data() }
        return Data(bytes: p, count: n)
    }
}
