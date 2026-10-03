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
/// HMACs, so the file reveals only row counts and sizes — nothing about who
/// you talk to or what was said.
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
            CREATE TABLE IF NOT EXISTS r (
                c BLOB NOT NULL,
                k BLOB NOT NULL,
                g BLOB,
                s INTEGER NOT NULL DEFAULT 0,
                v BLOB NOT NULL,
                PRIMARY KEY (c, k)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS r_g ON r (c, g, s);
            """)
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
        let plaintext = try encoder.encode(value)
        let sealed = try ChaChaPoly.seal(plaintext, using: dataKey, authenticating: c + k).combined
        try queue.sync {
            try run("INSERT OR REPLACE INTO r (c, k, g, s, v) VALUES (?, ?, ?, ?, ?)",
                    [.blob(c), .blob(k), group.map { .blob(mac(collection + "\u{1}" + $0)) } ?? .null, .int(sort), .blob(sealed)])
        }
    }

    public func get<T: Decodable>(_ type: T.Type, collection: String, key: String) throws -> T? {
        let c = mac(collection)
        let k = mac(collection + "\u{0}" + key)
        let rows = try queue.sync {
            try query("SELECT k, v FROM r WHERE c = ? AND k = ?", [.blob(c), .blob(k)])
        }
        guard let row = rows.first else { return nil }
        return try open(T.self, c: c, k: row.0, v: row.1)
    }

    /// Lists a collection (optionally only one group) ordered by sort key.
    public func list<T: Decodable>(_ type: T.Type, collection: String, group: String? = nil,
                                   limit: Int = -1, newestFirst: Bool = false) throws -> [T] {
        let c = mac(collection)
        let order = newestFirst ? "DESC" : "ASC"
        let rows = try queue.sync { () -> [(Data, Data)] in
            if let group {
                return try query("SELECT k, v FROM r WHERE c = ? AND g = ? ORDER BY s \(order) LIMIT ?",
                                 [.blob(c), .blob(mac(collection + "\u{1}" + group)), .int(Int64(limit))])
            }
            return try query("SELECT k, v FROM r WHERE c = ? ORDER BY s \(order) LIMIT ?", [.blob(c), .int(Int64(limit))])
        }
        return try rows.map { try open(T.self, c: c, k: $0.0, v: $0.1) }
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

    private func open<T: Decodable>(_ type: T.Type, c: Data, k: Data, v: Data) throws -> T {
        guard let box = try? ChaChaPoly.SealedBox(combined: v),
              let plaintext = try? ChaChaPoly.open(box, using: dataKey, authenticating: c + k)
        else { throw DatabaseError.decrypt }
        return try decoder.decode(T.self, from: plaintext)
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
