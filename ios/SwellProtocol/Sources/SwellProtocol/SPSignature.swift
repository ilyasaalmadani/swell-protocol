// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation
import CryptoKit

// Swell Protocol draft 3, spec section 5.2 (SwellSig): signatures by an identity key.
//
// The identity key is an X25519 key (SPIdentity). SwellSig signs with the Ed25519 verification equation of RFC 8032 under the
// Edwards form of that same key (RFC 7748 section 4.1 gives the map), so any RFC 8032 verifier checks it and nothing but the
// scalar of the X25519 key is needed to sign. The scheme is the one Signal's published XEdDSA also builds on, but it was written here
// from RFC 8032 and RFC 7748 alone (docs/CLEAN-ROOM.md).
//
//   u      = the 32-byte X25519 public key of the signer
//   A      = Edwards y-coordinate  y = (u - 1) / (u + 1) mod p, written as 32 bytes little endian with the sign bit of x set to 0
//   a      = the X25519 private key clamped as RFC 7748 does (byte 0 &= 248, byte 31 &= 127, byte 31 |= 64), little endian integer
//   msg    = "swell-sig-v3" | 0x00 | u8 len(context) | context | message
//   rseed  = first 32 bytes of SHA-512("swell-sig-nonce" | 0x00 | private key | msg)
//   (R, r) = the RFC 8032 section 5.1.5 key pair of the seed rseed: R is its public key, r its clamped scalar
//   k      = SHA-512(R | A | msg) as little endian integer, mod L
//   S      = (r + k * a0) mod L        where a0 = a if the point a*B has an even x, otherwise L - a
//   signature = R | S (S as 32 bytes little endian), 64 bytes
//
// An implementation that cannot see the sign of x computes S for both a and L - a and keeps the one that an RFC 8032 verifier accepts
// under A. Exactly one does.
//
// Verification (spec 5.2, "strict"): S below L; R a canonical encoding of a point of order exactly L (not the identity, no small-order
// part); A of order exactly L; then [S]B = R + [k]A. With R and A in the prime-order subgroup the cofactored and the plain RFC 8032
// equations give the same answer, so any RFC 8032 verifier may do the last step and every platform accepts exactly the same signatures.
//
// Not constant time: the integer arithmetic below is for a signature made rarely, on the person's own phone.

public enum SPSignature {
    public static let length = 64
    static let domain = Array("swell-sig-v3".utf8)

    static func message(context: String, _ m: [UInt8]) -> [UInt8] {
        let c = Array(context.utf8)
        precondition(c.count < 256 && c.allSatisfy { $0 < 0x80 }, "contexts are short ASCII")
        return domain + [0, UInt8(c.count)] + c + m
    }

    /// The Edwards public key `A` of an X25519 public key `u`: 32 bytes, sign bit 0. Nil when `u` has no such image (u = -1).
    public static func edwardsKey(fromX25519 u: [UInt8]) -> [UInt8]? {
        guard u.count == 32 else { return nil }
        var masked = u; masked[31] &= 0x7F // RFC 7748: the top bit of u is ignored
        let x = SPBig(le: masked).modP()
        let denom = x.addModP(SPBig(1))
        guard !denom.isZero else { return nil }
        let y = x.subModP(SPBig(1)).mulModP(denom.invModP())
        return y.leBytes(32)
    }

    public static func sign(identitySecret k: [UInt8], context: String, _ message: [UInt8]) throws -> [UInt8] {
        guard k.count == 32 else { throw SwellProtocolError.format("identity key") }
        let u = try SP.x25519Public(k)
        guard let aEnc = edwardsKey(fromX25519: u) else { throw SwellProtocolError.crypto("signature key") }
        let msg = Self.message(context: context, message)
        let rseed = Array(SP.sha512(Array("swell-sig-nonce".utf8) + [0] + k + msg).prefix(32))
        let rKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rseed)
        let bigR = Array(rKey.publicKey.rawRepresentation)
        let r = SPBig(le: clamp(Array(SP.sha512(rseed).prefix(32)))).mod(SPBig.l)
        let kk = SPBig(le: SP.sha512(bigR + aEnc + msg)).mod(SPBig.l)
        let a = SPBig(le: clamp(k)).mod(SPBig.l)
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: aEnc)
        for a0 in [a, SPBig.l - a] {
            let s = r.addMod(kk.mulMod(a0, SPBig.l), SPBig.l)
            let sig = bigR + s.leBytes(32)
            if verifier.isValidSignature(sig, for: msg) { return sig }
        }
        throw SwellProtocolError.crypto("signature")
    }

    public static func verify(identityPublic u: [UInt8], context: String, message: [UInt8], signature: [UInt8]) -> Bool {
        guard signature.count == length, SPIdentity.isValidPublic(u), let aEnc = edwardsKey(fromX25519: u),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: aEnc) else { return false }
        // The strict checks of spec 5.2, made here so that the equation the library uses (cofactored or not) cannot matter.
        guard SPBig(le: Array(signature[32...])) < SPBig.l,
              let r = SPEdPoint.decode(Array(signature[..<32])), !r.isIdentity, r.mul(SPBig.l).isIdentity,
              primeOrder(aEnc) else { return false }
        return key.isValidSignature(signature, for: Self.message(context: context, message))
    }

    /// True when the Edwards key `aEnc` decodes to a point of order exactly L. A key made by `SPIdentity` always is; a hostile one with a
    /// small-order part is not. Remembered per key: it is the same few keys again and again (a group's members).
    static func primeOrder(_ aEnc: [UInt8]) -> Bool {
        let key = Data(aEnc)
        if let known = primeOrderCache.withLock({ $0[key] }) { return known }
        let ok = SPEdPoint.decode(aEnc).map { !$0.isIdentity && $0.mul(SPBig.l).isIdentity } ?? false
        primeOrderCache.withLock { if $0.count > 256 { $0.removeAll() }; $0[key] = ok }
        return ok
    }
    private static let primeOrderCache = SPLocked<[Data: Bool]>([:])

    static func clamp(_ k: [UInt8]) -> [UInt8] {
        var c = k
        c[0] &= 248; c[31] &= 127; c[31] |= 64
        return c
    }
}

/// A value behind a lock (the prime-order cache of `SPSignature`).
final class SPLocked<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    init(_ v: T) { value = v }
    func withLock<R>(_ f: (inout T) -> R) -> R { lock.lock(); defer { lock.unlock() }; return f(&value) }
}

/// A point of the Ed25519 curve -x^2 + y^2 = 1 + d x^2 y^2 in extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z
/// (RFC 8032 section 5.1.4). Only for the checks of SwellSig verification and its tests. Not constant time.
struct SPEdPoint {
    var x: SPBig, y: SPBig, z: SPBig, t: SPBig

    static let d: SPBig = (SPBig.p - SPBig(121665)).mulModP(SPBig(121666).invModP())
    static let d2: SPBig = d.addModP(d)
    /// sqrt(-1) = 2^((p-1)/4) mod p
    static let sqrtM1: SPBig = SPBig(2).powModP((SPBig.p - SPBig(1)).shiftedRight(2))
    static let identity = SPEdPoint(x: SPBig(), y: SPBig(1), z: SPBig(1), t: SPBig())
    /// The base point B (y = 4/5, x even).
    static let base: SPEdPoint = decode((try? SPHex.decode("5866666666666666666666666666666666666666666666666666666666666666")) ?? [])!

    var isIdentity: Bool { x.isZero && y == z }

    /// RFC 8032 section 5.1.3, strict: y must be below p, and x = 0 with the sign bit set is refused.
    static func decode(_ b: [UInt8]) -> SPEdPoint? {
        guard b.count == 32 else { return nil }
        var yb = b; let sign = yb[31] >> 7; yb[31] &= 0x7F
        let y = SPBig(le: yb)
        guard y < SPBig.p else { return nil }
        let y2 = y.mulModP(y)
        let u = y2.subModP(SPBig(1)), v = d.mulModP(y2).addModP(SPBig(1))
        let v3 = v.mulModP(v).mulModP(v), v7 = v3.mulModP(v3).mulModP(v)
        var x = u.mulModP(v3).mulModP(u.mulModP(v7).powModP((SPBig.p - SPBig(5)).shiftedRight(3)))
        let vx2 = v.mulModP(x.mulModP(x))
        if vx2 == u { } else if vx2 == SPBig().subModP(u) { x = x.mulModP(sqrtM1) } else { return nil }
        if x.isZero && sign == 1 { return nil }
        if (x.bit(0) ? 1 : 0) != sign { x = SPBig().subModP(x) }
        return SPEdPoint(x: x, y: y, z: SPBig(1), t: x.mulModP(y))
    }

    func encode() -> [UInt8] {
        let zi = z.invModP()
        let ax = x.mulModP(zi), ay = y.mulModP(zi)
        var out = ay.leBytes(32)
        if ax.bit(0) { out[31] |= 0x80 }
        return out
    }

    /// Complete addition for a = -1 (Hisil, Wong, Carter, Dawson 2008, "add-2008-hwcd-3"); also doubles.
    func adding(_ q: SPEdPoint) -> SPEdPoint {
        let a = y.subModP(x).mulModP(q.y.subModP(q.x))
        let b = y.addModP(x).mulModP(q.y.addModP(q.x))
        let c = t.mulModP(SPEdPoint.d2).mulModP(q.t)
        let dd = z.addModP(z).mulModP(q.z)
        let e = b.subModP(a), f = dd.subModP(c), g = dd.addModP(c), h = b.addModP(a)
        return SPEdPoint(x: e.mulModP(f), y: g.mulModP(h), z: f.mulModP(g), t: e.mulModP(h))
    }
    func negated() -> SPEdPoint { SPEdPoint(x: SPBig().subModP(x), y: y, z: z, t: SPBig().subModP(t)) }

    /// [k]P by double and add from the top bit.
    func mul(_ k: SPBig) -> SPEdPoint {
        var r = SPEdPoint.identity
        for i in stride(from: k.bitCount - 1, through: 0, by: -1) {
            r = r.adding(r)
            if k.bit(i) { r = r.adding(self) }
        }
        return r
    }
}

/// A small unsigned integer for SwellSig: little-endian 32-bit limbs, normalized (no high zero limbs). Only what SwellSig needs.
struct SPBig: Equatable, Comparable {
    private(set) var w: [UInt32]

    init(_ v: UInt32 = 0) { w = v == 0 ? [] : [v] }
    init(le bytes: [UInt8]) {
        var limbs = [UInt32](repeating: 0, count: (bytes.count + 3) / 4)
        for (i, b) in bytes.enumerated() { limbs[i / 4] |= UInt32(b) << UInt32(8 * (i % 4)) }
        w = limbs
        normalize()
    }
    private init(limbs: [UInt32]) { w = limbs; normalize() }

    /// 2^255 - 19
    static let p: SPBig = { var v = SPBig(1); v = v.shiftedLeft(255); return v - SPBig(19) }()
    /// 2^252 + 27742317777372353535851937790883648493
    static let l: SPBig = SPBig(le: (try? SPHex.decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")) ?? [])

    var isZero: Bool { w.isEmpty }
    var bitCount: Int { w.isEmpty ? 0 : 32 * (w.count - 1) + (32 - w[w.count - 1].leadingZeroBitCount) }
    func bit(_ i: Int) -> Bool { i / 32 < w.count && (w[i / 32] >> UInt32(i % 32)) & 1 == 1 }

    private mutating func normalize() { while let last = w.last, last == 0 { w.removeLast() } }

    func leBytes(_ n: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: n)
        for i in 0..<n where i / 4 < w.count { out[i] = UInt8((w[i / 4] >> UInt32(8 * (i % 4))) & 0xFF) }
        return out
    }

    static func < (a: SPBig, b: SPBig) -> Bool {
        if a.w.count != b.w.count { return a.w.count < b.w.count }
        for i in stride(from: a.w.count - 1, through: 0, by: -1) where a.w[i] != b.w[i] { return a.w[i] < b.w[i] }
        return false
    }

    static func + (a: SPBig, b: SPBig) -> SPBig {
        var out = [UInt32](); var carry: UInt64 = 0
        for i in 0..<max(a.w.count, b.w.count) {
            let s = UInt64(i < a.w.count ? a.w[i] : 0) + UInt64(i < b.w.count ? b.w[i] : 0) + carry
            out.append(UInt32(truncatingIfNeeded: s)); carry = s >> 32
        }
        if carry > 0 { out.append(UInt32(carry)) }
        return SPBig(limbs: out)
    }

    /// `a - b`; requires `a >= b`.
    static func - (a: SPBig, b: SPBig) -> SPBig {
        precondition(!(a < b))
        var out = [UInt32](); var borrow: Int64 = 0
        for i in 0..<a.w.count {
            var d = Int64(a.w[i]) - Int64(i < b.w.count ? b.w[i] : 0) - borrow
            if d < 0 { d += 1 << 32; borrow = 1 } else { borrow = 0 }
            out.append(UInt32(d))
        }
        return SPBig(limbs: out)
    }

    static func * (a: SPBig, b: SPBig) -> SPBig {
        guard !a.isZero, !b.isZero else { return SPBig() }
        var out = [UInt32](repeating: 0, count: a.w.count + b.w.count)
        for i in 0..<a.w.count {
            var carry: UInt64 = 0
            for j in 0..<b.w.count {
                let t = UInt64(a.w[i]) * UInt64(b.w[j]) + UInt64(out[i + j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: t); carry = t >> 32
            }
            out[i + b.w.count] = UInt32(truncatingIfNeeded: carry)
        }
        return SPBig(limbs: out)
    }

    func shiftedLeft(_ n: Int) -> SPBig {
        guard !isZero else { return self }
        var out = [UInt32](repeating: 0, count: n / 32)
        let s = UInt32(n % 32)
        if s == 0 { out += w } else {
            var carry: UInt32 = 0
            for x in w { out.append((x << s) | carry); carry = x >> (32 - s) }
            if carry > 0 { out.append(carry) }
        }
        return SPBig(limbs: out)
    }

    func shiftedRight(_ n: Int) -> SPBig {
        let limbs = n / 32, s = UInt32(n % 32)
        guard limbs < w.count else { return SPBig() }
        var out = Array(w[limbs...])
        if s > 0 {
            for i in 0..<out.count { out[i] = (out[i] >> s) | (i + 1 < out.count ? out[i + 1] << (32 - s) : 0) }
        }
        return SPBig(limbs: out)
    }

    /// `self mod m` by shift and subtract.
    func mod(_ m: SPBig) -> SPBig {
        var r = SPBig()
        for i in stride(from: bitCount - 1, through: 0, by: -1) {
            r = r.shiftedLeft(1)
            if bit(i) { r = r + SPBig(1) }
            if !(r < m) { r = r - m }
        }
        return r
    }

    func addMod(_ b: SPBig, _ m: SPBig) -> SPBig { let s = self + b; return s < m ? s : s - m }
    func mulMod(_ b: SPBig, _ m: SPBig) -> SPBig { (self * b).mod(m) }

    // MARK: arithmetic modulo p = 2^255 - 19 (fold the high part: 2^255 = 19)

    func modP() -> SPBig {
        var x = self
        while x.bitCount > 255 {
            let hi = x.shiftedRight(255)
            let lo = x - hi.shiftedLeft(255)
            x = lo + hi * SPBig(19)
        }
        return x < SPBig.p ? x : x - SPBig.p
    }
    func addModP(_ b: SPBig) -> SPBig { (self + b).modP() }
    func subModP(_ b: SPBig) -> SPBig { self < b ? (self + SPBig.p) - b : self - b }
    func mulModP(_ b: SPBig) -> SPBig { (self * b).modP() }
    /// `self^(p-2) mod p`
    func invModP() -> SPBig { powModP(SPBig.p - SPBig(2)) }
    /// `self^e mod p`
    func powModP(_ e: SPBig) -> SPBig {
        var result = SPBig(1)
        for i in stride(from: e.bitCount - 1, through: 0, by: -1) {
            result = result.mulModP(result)
            if e.bit(i) { result = result.mulModP(self) }
        }
        return result
    }
}

/// Little-endian bytes of a big-endian hex string (constants only).
func SPHexLE(_ be: String) -> [UInt8] { ((try? SPHex.decode(be)) ?? []).reversed() }
