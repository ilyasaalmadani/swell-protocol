import Foundation


// Swell Protocol draft 2, byte layouts. Spec sections: 5 (bundle, invite v4), 7.3 (header), 7.4 (body and padding),
// 7.5 (envelopes), 7.6 (PQ field), 6.4 (upgrade frames, inner type 26), PROTOCOL.md 5o (MSG ciphertextType 32).

public enum SPWire {
    /// Envelope version byte (draft 1 used 1; existing peer frames start with 2 but never travel where an envelope does).
    public static let ver: UInt8 = 2
    public static let kindBundle: UInt8 = 0, kindHello: UInt8 = 1, kindData: UInt8 = 2

    /// Header plaintext (spec 7.3): `raw32 dh_pub | i32 pn | i32 n | i32 epoch` = 44 bytes; hct adds the 16-byte tag.
    public static let headerLen = 44, hctLen = 60
    /// HELLO prefix after `ver | kind`: `raw32 ID_J | raw32 E | raw1088 ct`.
    public static let helloKeysLen = 32 + 32 + SP.kemCTLen
    /// Bundle (spec 5): `u8 2 | raw32 ID_I | raw32 EPK | raw1184 EK | i64 expiresAtMs` = 1257 bytes.
    public static let bundleLen = 1 + 32 + 32 + SP.kemEKLen + 8

    /// Padding buckets, the same as PROTOCOL.md section 1 (spec 7.4).
    public static let buckets = [1024, 4096, 16384, 65536, 262144]
    /// A PQ field never moves a frame whose bucket is above 16 KiB into a larger bucket (spec 7.6, review F14: mailbox PUT limit).
    public static let pqBucketCap = 16384

    /// The bucket a padded content of `need` bytes (4-byte length included) uses, or nil when too large.
    public static func bucket(_ need: Int) -> Int? { buckets.first { $0 >= need } }

    // MARK: header (7.3)

    public struct Header: Equatable, Sendable {
        public var dhPub: [UInt8]
        public var pn: Int32
        public var n: Int32
        public var epoch: Int32
        public func encode() -> [UInt8] { dhPub + SP.be32(pn) + SP.be32(n) + SP.be32(epoch) }
        public static func decode(_ b: [UInt8]) throws -> Header {
            guard b.count == headerLen else { throw SwellProtocolError.format("header length") }
            let r = SPIn(b)
            let h = Header(dhPub: try r.raw(32), pn: try r.i32(), n: try r.i32(), epoch: try r.i32())
            guard h.pn >= 0, h.n >= 0, h.epoch >= 0 else { throw SwellProtocolError.format("header values") }
            return h
        }
    }

    // MARK: PQ field and padding (7.4, 7.6)

    /// The PQ ratchet field at the start of the padded content: none, an encapsulation key, or a ciphertext.
    public enum PQField: Equatable, Sendable {
        case none
        case ek(target: Int32, ek: [UInt8])
        case ct(target: Int32, ct: [UInt8])

        func encode() -> [UInt8] {
            switch self {
            case .none: return [0]
            case .ek(let t, let ek): return [1] + SP.be32(t) + ek
            case .ct(let t, let ct): return [2] + SP.be32(t) + ct
            }
        }
    }

    /// `padded = i32 length | content | zero bytes up to the bucket`, `content = pq field | inner message`.
    public static func pad(pq: PQField, inner: [UInt8]) throws -> [UInt8] {
        try padRaw(pq.encode() + inner)
    }

    /// The padding of 7.4 for any content (the link frames of 6.4 use it too).
    public static func padRaw(_ content: [UInt8]) throws -> [UInt8] {
        let need = 4 + content.count
        guard let size = bucket(need) else { throw SwellProtocolError.limit("message too large") }
        return SP.be32(Int32(content.count)) + content + [UInt8](repeating: 0, count: size - need)
    }

    /// Strict inverse of `padRaw`: the size must be a bucket, the length in range, every padding byte zero (checked in constant time).
    public static func unpadRaw(_ p: [UInt8]) throws -> [UInt8] {
        guard buckets.contains(p.count) else { throw SwellProtocolError.format("bucket") }
        let r = SPIn(p)
        let n = Int(try r.i32())
        guard n >= 1, n <= p.count - 4 else { throw SwellProtocolError.format("padding length") }
        guard SP.isZero(Array(p[(4 + n)...])) else { throw SwellProtocolError.format("padding bytes") }
        return Array(p[4..<(4 + n)])
    }

    /// Strict inverse of `pad`.
    public static func unpad(_ p: [UInt8]) throws -> (pq: PQField, inner: [UInt8]) {
        let content = try unpadRaw(p)
        let n = content.count
        let c = SPIn(content)
        let pq: PQField
        switch try c.u8() {
        case 0: pq = .none
        case 1:
            let t = try c.i32(); guard t > 0 else { throw SwellProtocolError.format("pq target") }
            pq = .ek(target: t, ek: try c.raw(SP.kemEKLen))
        case 2:
            let t = try c.i32(); guard t > 0 else { throw SwellProtocolError.format("pq target") }
            pq = .ct(target: t, ct: try c.raw(SP.kemCTLen))
        default: throw SwellProtocolError.format("pq kind")
        }
        return (pq, Array(content[(n - c.remaining)...]))
    }

    // MARK: envelopes (7.5)

    public struct Envelope: Sendable {
        public var kind: UInt8
        /// For HELLO: `ID_J | E | ct` (helloKeysLen bytes); empty for DATA.
        public var helloKeys: [UInt8]
        public var hnonce: [UInt8]
        public var hct: [UInt8]
        public var body: [UInt8]

        /// `u8 ver | u8 kind` and, for HELLO, the three keys: the `prefix` of spec 7.3, bound into both ADs.
        public var prefix: [UInt8] { [ver, kind] + helloKeys }
        public func encode() -> [UInt8] { prefix + hnonce + hct + body }

        public static func decode(_ b: [UInt8]) throws -> Envelope {
            guard b.count >= 2, b[0] == ver else { throw SwellProtocolError.format("version") }
            let kind = b[1]
            let keys: Int
            switch kind {
            case kindData: keys = 0
            case kindHello: keys = helloKeysLen
            default: throw SwellProtocolError.format("kind")
            }
            let start = 2 + keys, bodyStart = start + 12 + hctLen
            // Smallest body: the 1 KiB bucket plus the tag.
            guard b.count >= bodyStart + buckets[0] + 16 else { throw SwellProtocolError.format("envelope length") }
            return Envelope(kind: kind, helloKeys: Array(b[2..<start]), hnonce: Array(b[start..<(start + 12)]),
                            hct: Array(b[(start + 12)..<bodyStart]), body: Array(b[bodyStart...]))
        }
    }

    // MARK: bundle (5)

    public struct Bundle: Equatable, Sendable {
        public var idI: [UInt8], epk: [UInt8], ek: [UInt8], expiresAtMs: Int64
        public func encode() -> [UInt8] { [ver] + idI + epk + ek + SP.be64(expiresAtMs) }
        public static func decode(_ b: [UInt8]) throws -> Bundle {
            guard b.count == bundleLen, b[0] == ver else { throw SwellProtocolError.format("bundle") }
            let r = SPIn(b); _ = try r.u8()
            return Bundle(idI: try r.raw(32), epk: try r.raw(32), ek: try r.raw(SP.kemEKLen), expiresAtMs: try r.i64())
        }
        /// `bundleCommit = SHA256Tagged("bundle", bundle)`.
        public var commit: [UInt8] { SP.tagged("bundle", encode()) }
    }
}

/// Session frames, inner message type 26 (spec 6.4, PROTOCOL.md 5o). OFFER, HELLO, RESET and SYNC travel in a link frame (`SPLink`);
/// READY travels inside the first Swell message each way.
public enum SPUpgradeFrame: Equatable, Sendable {
    public static let innerType: UInt8 = 26
    /// I offers a Swell handshake (link frame).
    case offer(offerId: [UInt8], bundle: [UInt8])
    /// J answers with the HELLO envelope (link frame).
    case hello(offerId: [UInt8], envelope: [UInt8])
    /// Inside the first Swell messages in each direction: the session for this offer works.
    case ready(offerId: [UInt8])
    /// "I hold no Swell session for this contact" (link frame, e.g. after a restore). The receiver drops its Swell state.
    case reset
    /// "Your Swell messages do not open here; this is the session I hold" (link frame): `SHA256Tagged("session", T)`, or 32 zero
    /// bytes for none. A receiver whose own value differs drops its state and answers RESET (spec 6.4 "Sessions that differ").
    case sync(sessionHash: [UInt8])

    public func encode() -> [UInt8] {
        let o = SPOut().u8(Int(Self.innerType))
        switch self {
        case .offer(let id, let b): o.u8(1).raw(id).bytes(b)
        case .hello(let id, let e): o.u8(2).raw(id).bytes(e)
        case .ready(let id): o.u8(3).raw(id)
        case .reset: o.u8(4)
        case .sync(let h): o.u8(5).raw(h)
        }
        return o.done()
    }

    /// Reads the frame after its inner type byte. Unknown ops are refused (the caller ignores the frame).
    public static func decode(_ r: SPIn) throws -> SPUpgradeFrame {
        switch try r.u8() {
        case 1: return .offer(offerId: try r.raw(16), bundle: try r.bytes(max: SPWire.bundleLen))
        case 2: return .hello(offerId: try r.raw(16), envelope: try r.bytes(max: 8192))
        case 3: return .ready(offerId: try r.raw(16))
        case 4: return .reset
        case 5: return .sync(sessionHash: try r.raw(32))
        default: throw SwellProtocolError.format("upgrade op")
        }
    }
}
