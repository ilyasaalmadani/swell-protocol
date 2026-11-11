// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation

// Swell Protocol, spec section 4 (encoding): big-endian integers, `bytes` = `i32 length | data`, `str` = `bytes` of UTF-8,
// `raw(n)` = exactly n bytes. These two small types are the only reader and writer the library uses.

/// Binary writer.
public final class SPOut {
    private var buf = [UInt8]()
    public init() {}
    @discardableResult public func u8(_ v: Int) -> SPOut { buf.append(UInt8(truncatingIfNeeded: v)); return self }
    @discardableResult public func i32(_ v: Int32) -> SPOut { raw(withUnsafeBytes(of: v.bigEndian, Array.init)) }
    @discardableResult public func i64(_ v: Int64) -> SPOut { raw(withUnsafeBytes(of: v.bigEndian, Array.init)) }
    @discardableResult public func raw(_ b: [UInt8]) -> SPOut { buf.append(contentsOf: b); return self }
    @discardableResult public func bytes(_ b: [UInt8]) -> SPOut { i32(Int32(b.count)); return raw(b) }
    @discardableResult public func str(_ s: String) -> SPOut { bytes(Array(s.utf8)) }
    public func done() -> [UInt8] { buf }
}

/// Bounded reader. Every read throws on underflow; `end()` rejects trailing bytes.
public final class SPIn {
    private let b: [UInt8]
    private var pos = 0
    public init(_ b: [UInt8]) { self.b = b }
    public var remaining: Int { b.count - pos }

    public func u8() throws -> Int { Int(try raw(1)[0]) }
    public func i32() throws -> Int32 {
        let r = try raw(4); return Int32(bitPattern: r.reduce(UInt32(0)) { $0 << 8 | UInt32($1) })
    }
    public func i64() throws -> Int64 {
        let r = try raw(8); return Int64(bitPattern: r.reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
    }
    public func raw(_ n: Int) throws -> [UInt8] {
        guard n >= 0, n <= remaining else { throw SwellProtocolError.format("short read") }
        defer { pos += n }
        return Array(b[pos..<pos + n])
    }
    public func bytes(max: Int) throws -> [UInt8] {
        let n = Int(try i32())
        guard n >= 0, n <= max else { throw SwellProtocolError.format("field size") }
        return try raw(n)
    }
    public func str(max: Int) throws -> String {
        guard let s = String(bytes: try bytes(max: max), encoding: .utf8) else { throw SwellProtocolError.format("utf8") }
        return s
    }
    public func end() throws { if remaining != 0 { throw SwellProtocolError.format("trailing bytes") } }
}

/// Lower-case hexadecimal, for tests, vectors and storage keys.
public enum SPHex {
    public static func encode(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    public static func decode(_ s: String) throws -> [UInt8] {
        let c = Array(s.utf8)
        guard c.count % 2 == 0 else { throw SwellProtocolError.format("hex") }
        return try stride(from: 0, to: c.count, by: 2).map { i in
            guard let v = UInt8(String(decoding: c[i..<i + 2], as: UTF8.self), radix: 16) else { throw SwellProtocolError.format("hex") }
            return v
        }
    }
}
