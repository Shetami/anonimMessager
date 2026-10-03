import Foundation

/// Pads plaintext to fixed bucket sizes before encryption so ciphertext
/// length reveals almost nothing about message length.
/// Scheme: ISO/IEC 7816-4 (0x80 then zeros).
public enum Padding {
    static let buckets = [1024, 4096, 16384, 65536]
    static let largeStep = 65536

    public static func paddedSize(for length: Int) -> Int {
        let needed = length + 1
        if let b = buckets.first(where: { $0 >= needed }) { return b }
        return (needed + largeStep - 1) / largeStep * largeStep
    }

    public static func pad(_ data: Data) -> Data {
        var out = data
        out.append(0x80)
        out.append(Data(count: paddedSize(for: data.count) - out.count))
        return out
    }

    public static func unpad(_ data: Data) -> Data? {
        guard let idx = data.lastIndex(where: { $0 != 0 }), data[idx] == 0x80 else { return nil }
        return data[data.startIndex..<idx]
    }
}
