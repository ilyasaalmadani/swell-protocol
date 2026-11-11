// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation
import XCTest
@testable import SwellProtocol

/// Test entropy: hands out recorded chunks in order, and recorded KEM encapsulations in order. A request for a different size or past the
/// end fails the test, so a vector never silently draws randomness it does not record.
final class QueueEntropy: SPEntropy, @unchecked Sendable {
    private let lock = NSLock()
    private var chunks: [[UInt8]]
    private var kems: [(ct: [UInt8], ss: [UInt8])]
    private(set) var drawn: [[UInt8]] = []
    var leftover: Int { lock.lock(); defer { lock.unlock() }; return chunks.count + kems.count }
    init(chunks: [[UInt8]], kems: [(ct: [UInt8], ss: [UInt8])] = []) { self.chunks = chunks; self.kems = kems }
    func bytes(_ n: Int) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        guard !chunks.isEmpty, chunks[0].count == n else { throw SwellProtocolError.random }
        let c = chunks.removeFirst(); drawn.append(c); return c
    }
    func encapsulate(_ ek: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        guard !kems.isEmpty else { throw SwellProtocolError.random }
        return kems.removeFirst()
    }
}

/// Repeats one byte: `b(0x11, 32)` is `11*32` as written in the vectors.
func rep(_ v: UInt8, _ n: Int) -> [UInt8] { [UInt8](repeating: v, count: n) }
func hx(_ b: [UInt8]) -> String { SPHex.encode(b) }
func unhx(_ s: String) -> [UInt8] { try! SPHex.decode(s) }

/// The shared vector files live in docs/protocol-vectors. Writing them is a deliberate act (`SWELL_WRITE_VECTORS=1 swift test`); a normal run
/// recomputes everything from the recorded inputs and fails if a single byte differs from the file. The Kotlin tests read the same files.
enum Vectors {
    static var dir: URL {
        // ios/SwellProtocol/Tests/SwellProtocolTests/VectorSupport.swift -> repository root
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("docs/protocol-vectors")
    }
    static var writing: Bool { ProcessInfo.processInfo.environment["SWELL_WRITE_VECTORS"] == "1" }

    static func url(_ name: String) -> URL { dir.appendingPathComponent(name) }

    /// The recorded file as a dictionary, if it exists.
    static func load(_ name: String) -> [String: Any]? {
        guard let d = try? Data(contentsOf: url(name)), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return nil }
        return o
    }

    static func render(_ doc: [String: Any]) throws -> String {
        let d = try JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return String(decoding: d, as: UTF8.self) + "\n"
    }

    /// Writes (in write mode) or compares the file with `doc`.
    static func check(_ name: String, _ doc: [String: Any], file: StaticString = #filePath, line: UInt = #line) throws {
        let text = try render(doc)
        if writing {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try text.write(to: url(name), atomically: true, encoding: .utf8)
            return
        }
        guard let existing = try? String(contentsOf: url(name), encoding: .utf8) else {
            XCTFail("\(name) is missing: run SWELL_WRITE_VECTORS=1 swift test", file: file, line: line); return
        }
        XCTAssertEqual(existing, text, "\(name) differs from what this code computes", file: file, line: line)
    }
}

/// Generation-time entropy: deterministic bytes (SHA-512 of a label and a counter), every chunk recorded, KEM encapsulation real
/// (CryptoKit offers no way to fix its randomness) and recorded. The recorded streams go into the vector file and are replayed by
/// `QueueEntropy` on every later run and on every other platform.
final class RecordingEntropy: SPEntropy, @unchecked Sendable {
    private let lock = NSLock()
    private let label: String
    private var counter = 0
    private(set) var chunks: [[UInt8]] = []
    private(set) var kems: [(ct: [UInt8], ss: [UInt8])] = []
    init(label: String) { self.label = label }
    func bytes(_ n: Int) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        counter += 1
        var out: [UInt8] = []
        var block = 0
        while out.count < n { out += SP.sha512(Array("\(label)/\(counter)/\(block)".utf8)); block += 1 }
        let c = Array(out.prefix(n)); chunks.append(c); return c
    }
    func encapsulate(_ ek: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        let r = try SP.kemEncapsulate(ek); kems.append(r); return r
    }
    var record: [String: Any] { ["chunks": chunks.map(hx), "kem": kems.map { ["ct": hx($0.ct), "ss": hx($0.ss)] }] }
}

extension QueueEntropy {
    /// Replays a `record` made by `RecordingEntropy`.
    static func replay(_ rec: [String: Any]) -> QueueEntropy {
        let chunks = (rec["chunks"] as? [String] ?? []).map(unhx)
        let kems = (rec["kem"] as? [[String: String]] ?? []).map { (ct: unhx($0["ct"]!), ss: unhx($0["ss"]!)) }
        return QueueEntropy(chunks: chunks, kems: kems)
    }
}
