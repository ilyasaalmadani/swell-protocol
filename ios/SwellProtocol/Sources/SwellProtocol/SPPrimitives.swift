import Foundation
import CryptoKit


// Swell Protocol, draft 2 (docs/SWELL-PROTOCOL-SPEC.md). Clean-room implementation: written only from that
// specification and the public documents it lists (docs/CLEAN-ROOM.md). No libsignal or Signal app source was read.
//
// This file: spec section 4 (encoding and primitive boundaries) and section 4.1 (availability).
// Every primitive comes from CryptoKit: X25519 (Curve25519.KeyAgreement), HKDF-SHA-256, SHA-256, AES-256-GCM, ML-KEM-768.

/// Errors of the Swell Protocol. The cases say only what failed, never a key or a byte of plaintext.
public enum SwellProtocolError: Error, Equatable, Sendable {
    /// A length, version, kind or field is wrong (parse failure).
    case format(String)
    /// An AEAD did not open, a DH output was all zero, or a commitment did not match.
    case crypto(String)
    /// The message was a duplicate, a replay or uses a key already deleted.
    case duplicate
    /// A limit of spec 8.1 was hit (MAX_SKIP, MAX_CHAIN).
    case limit(String)
    /// No session (or no pending handshake) exists for this relationship.
    case noSession
    /// The platform random source failed: stop, never fall back (spec 4).
    case random
}

/// Where fresh keys and nonces come from. The system source is the only one an app uses; tests give a fixed one so the shared
/// vectors (docs/protocol-vectors) can be reproduced byte for byte. ML-KEM encapsulation takes no outside randomness in CryptoKit,
/// so its ciphertext is recorded in the vectors instead.
public protocol SPEntropy: Sendable {
    func bytes(_ n: Int) throws -> [UInt8]
    /// `KEM.Enc(ek)`. Only tests replace this (with recorded values).
    func encapsulate(_ ek: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8])
}

extension SPEntropy {
    public func encapsulate(_ ek: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8]) { try SP.kemEncapsulate(ek) }
}

/// `SecRandomCopyBytes`. A failure stops the operation (spec 4).
public struct SPSystemEntropy: SPEntropy {
    public init() {}
    public func bytes(_ n: Int) throws -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &b) == errSecSuccess else { throw SwellProtocolError.random }
        return b
    }
}

/// Spec 4: `Info`, `SHA256Tagged`, HKDF, AEAD, X25519, ML-KEM-768, constant-time compare, best-effort wiping.
public enum SP {
    /// Domain version of the session layer (draft 2 and 3 share it: a draft 2 session keeps working in draft 3). It is in every `Info`
    /// and every tagged hash, so no draft 1 value can be reused. New draft 3 items use their own labels (section 9).
    public static let version: UInt8 = 2

    // MARK: lengths (spec 4)
    public static let x25519Len = 32
    public static let kemEKLen = 1184, kemCTLen = 1088, kemSSLen = 32, kemSeedLen = 64


    // MARK: 4 encoders

    /// `Info(label, f1..fn) = "Swell" | 0x00 | u8 2 | u8 len(label) | label | (u16 len(f) | f)*`.
    public static func info(_ label: String, _ fields: [UInt8]...) -> [UInt8] {
        let l = Array(label.utf8)
        precondition(l.count < 256 && l.allSatisfy { $0 < 0x80 }, "labels are short ASCII")
        var out: [UInt8] = Array("Swell".utf8) + [0, version, UInt8(l.count)] + l
        for f in fields {
            precondition(f.count <= 0xFFFF)
            out += [UInt8(f.count >> 8), UInt8(f.count & 0xFF)] + f
        }
        return out
    }

    /// `SHA256Tagged(tag, data) = SHA-256("Swell" | 0x00 | u8 2 | u8 len(tag) | tag | data)`.
    public static func tagged(_ tag: String, _ data: [UInt8]) -> [UInt8] {
        let t = Array(tag.utf8)
        var h = SHA256()
        h.update(data: Array("Swell".utf8) + [0, version, UInt8(t.count)] + t)
        h.update(data: data)
        return Array(h.finalize())
    }

    /// Saturating addition for times and counters: never traps, whatever a peer sent (review N1).
    public static func sat(_ a: Int64, _ b: Int64) -> Int64 {
        let (r, o) = a.addingReportingOverflow(b)
        return o ? (b > 0 ? Int64.max : Int64.min) : r
    }

    /// True when `then` is less than `gap` before `now` (a clock that went back counts as "not recent"). Never traps.
    public static func within(_ then: Int64, _ now: Int64, _ gap: Int64) -> Bool { then <= now && now < sat(then, gap) }

    public static func be32(_ v: Int32) -> [UInt8] { withUnsafeBytes(of: v.bigEndian) { Array($0) } }
    public static func be64(_ v: Int64) -> [UInt8] { withUnsafeBytes(of: v.bigEndian) { Array($0) } }

    // MARK: HKDF-SHA-256 (RFC 5869)

    /// `HKDF(salt, ikm, info, L)`: Extract then Expand.
    public static func hkdf(salt: [UInt8], ikm: [UInt8], info: [UInt8], _ length: Int) -> [UInt8] {
        let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: length)
        return k.withUnsafeBytes { Array($0) }
    }

    /// `Expand(prk, info, L)` alone, with a 32-byte `prk`.
    public static func expand(_ prk: [UInt8], _ info: [UInt8], _ length: Int) -> [UInt8] {
        precondition(prk.count == 32)
        let k = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: length)
        return k.withUnsafeBytes { Array($0) }
    }

    // MARK: AES-256-GCM

    /// `AEAD(key, nonce, ad, pt)` = AES-256-GCM, output `ciphertext | 16-byte tag`.
    public static func seal(key: [UInt8], nonce: [UInt8], ad: [UInt8], _ pt: [UInt8]) throws -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 12)
        let box = try AES.GCM.seal(pt, using: SymmetricKey(data: key), nonce: try AES.GCM.Nonce(data: nonce), authenticating: ad)
        return Array(box.ciphertext) + Array(box.tag)
    }

    public static func open(key: [UInt8], nonce: [UInt8], ad: [UInt8], _ ct: [UInt8]) throws -> [UInt8] {
        guard key.count == 32, nonce.count == 12, ct.count >= 16 else { throw SwellProtocolError.crypto("aead") }
        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ct[..<(ct.count - 16)], tag: ct[(ct.count - 16)...])
            return Array(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: ad))
        } catch { throw SwellProtocolError.crypto("aead") }
    }

    // MARK: X25519 (RFC 7748)

    /// A fresh X25519 key pair: (private 32, public 32). The private key is 32 bytes from `entropy`.
    public static func x25519(_ entropy: SPEntropy = SPSystemEntropy()) throws -> (sk: [UInt8], pk: [UInt8]) {
        let sk = try entropy.bytes(32)
        return (sk, try x25519Public(sk))
    }

    public static func x25519Public(_ sk: [UInt8]) throws -> [UInt8] {
        guard sk.count == 32 else { throw SwellProtocolError.format("x25519 key") }
        return Array(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk).publicKey.rawRepresentation)
    }

    /// `DH(sk, pk)`. An all-zero output (low-order peer key) is refused on both sides, for every DH (spec 4).
    public static func dh(_ sk: [UInt8], _ pk: [UInt8]) throws -> [UInt8] {
        guard sk.count == 32, pk.count == 32 else { throw SwellProtocolError.format("x25519 length") }
        let shared: [UInt8]
        do {
            let a = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk)
            let b = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pk)
            shared = try a.sharedSecretFromKeyAgreement(with: b).withUnsafeBytes { Array($0) }
        } catch { throw SwellProtocolError.crypto("dh") }
        guard shared.count == 32, !isZero(shared) else { throw SwellProtocolError.crypto("dh zero") }
        return shared
    }

    // MARK: ML-KEM-768 (FIPS 203)

    /// A fresh ML-KEM-768 key: (64-byte seed `d | z`, the private form kept on the device; 1184-byte encapsulation key).
    public static func kemGenerate(_ entropy: SPEntropy = SPSystemEntropy()) throws -> (seed: [UInt8], ek: [UInt8]) {
        let seed = try entropy.bytes(kemSeedLen)
        return (seed, try kemPublic(seed: seed))
    }

    /// The encapsulation key of a stored seed.
    public static func kemPublic(seed: [UInt8]) throws -> [UInt8] {
        guard seed.count == kemSeedLen else { throw SwellProtocolError.format("kem seed") }
        return Array(try MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil).publicKey.rawRepresentation)
    }

    /// `KEM.Enc(ek)`: validates `ek` (CryptoKit applies the FIPS 203 encapsulation-key check), returns (ct 1088, ss 32).
    public static func kemEncapsulate(_ ek: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8]) {
        guard ek.count == kemEKLen else { throw SwellProtocolError.format("kem ek") }
        do {
            let r = try MLKEM768.PublicKey(rawRepresentation: ek).encapsulate()
            return (Array(r.encapsulated), r.sharedSecret.withUnsafeBytes { Array($0) })
        } catch { throw SwellProtocolError.crypto("kem ek") }
    }

    /// `KEM.Dec(dk, ct)`. A wrong `ct` gives a pseudo-random secret (implicit rejection), so a later AEAD fails.
    public static func kemDecapsulate(seed: [UInt8], _ ct: [UInt8]) throws -> [UInt8] {
        guard seed.count == kemSeedLen, ct.count == kemCTLen else { throw SwellProtocolError.format("kem ct") }
        do {
            let k = try MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil)
            return try k.decapsulate(ct).withUnsafeBytes { Array($0) }
        } catch { throw SwellProtocolError.crypto("kem dec") }
    }

    // MARK: randomness, comparison, wiping

    /// Platform random bytes (SecRandomCopyBytes). A failure stops the operation (spec 4).
    public static func random(_ n: Int) throws -> [UInt8] { try SPSystemEntropy().bytes(n) }

    // MARK: SHA-2 (FIPS 180-4)

    public static func sha256(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: b)) }
    public static func sha512(_ b: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: b)) }

    /// Constant-time equality: the time depends only on the lengths, never on where the bytes differ.
    public static func ctEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    /// Constant-time all-zero check.
    public static func isZero(_ a: [UInt8]) -> Bool {
        var d: UInt8 = 0
        for x in a { d |= x }
        return d == 0
    }

    /// Best-effort wipe of a buffer. It reaches the bytes only when this array is their sole owner: if the storage is shared
    /// with another value (copy-on-write), Swift copies first and the zeros land in the copy (review F13). Call it only on
    /// buffers made and held by the caller alone. It never promises erasure (spec 12).
    public static func wipe(_ b: inout [UInt8]) {
        guard !b.isEmpty else { return }
        b.withUnsafeMutableBytes { p in
            if let base = p.baseAddress { memset_s(base, p.count, 0, p.count) }
        }
        b = []
    }
}
