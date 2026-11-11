// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import XCTest
import CryptoKit
@testable import SwellProtocol

/// docs/protocol-vectors: mlkem768.json, identity.json, signature.json, kdf.json. See Vectors (VectorSupport.swift).
final class PrimitiveVectorTests: XCTestCase {

    // MARK: ML-KEM-768 (FIPS 203) through CryptoKit, for BouncyCastle and any other implementation to match

    func testMLKEMVectors() throws {
        let recorded = Vectors.load("mlkem768.json")
        let seeds: [[UInt8]] = [Array(0..<64), rep(0x01, 64), (0..<64).map { UInt8(255 - $0) }]
        var cases: [[String: Any]] = []
        for (i, seed) in seeds.enumerated() {
            let ek = try SP.kemPublic(seed: seed)
            XCTAssertEqual(ek.count, 1184)
            // The encapsulation is random: keep the one already recorded, so regenerating the file does not change it.
            var ct: [UInt8], ss: [UInt8]
            if let old = (recorded?["cases"] as? [[String: Any]])?[safe: i], let c = old["ct"] as? String, let s = old["ss"] as? String {
                ct = unhx(c); ss = unhx(s)
            } else {
                (ct, ss) = try SP.kemEncapsulate(ek)
            }
            XCTAssertEqual(try SP.kemDecapsulate(seed: seed, ct), ss, "the recorded pair decapsulates")
            var bad = ct; bad[bad.count - 1] ^= 1
            let rejected = try SP.kemDecapsulate(seed: seed, bad) // implicit rejection: a pseudo-random secret, deterministic
            XCTAssertNotEqual(rejected, ss)
            cases.append(["seed": hx(seed), "ek": hx(ek), "ct": hx(ct), "ss": hx(ss), "tamperedCt": hx(bad), "tamperedSs": hx(rejected)])
        }
        // An encapsulation key whose first coefficient is 0xFFF (>= q = 3329) must be refused (FIPS 203 section 7.2 modulus check).
        var invalid = try SP.kemPublic(seed: seeds[0]); invalid[0] = 0xFF; invalid[1] |= 0x0F
        XCTAssertThrowsError(try SP.kemEncapsulate(invalid))
        try Vectors.check("mlkem768.json", [
            "description": "ML-KEM-768 (FIPS 203) from CryptoKit. seed (64 bytes d|z) -> ek (1184); ek + ct -> ss (32); decapsulate(seed, ct) -> ss; decapsulate(seed, tamperedCt) -> tamperedSs (implicit rejection, deterministic). invalidEk must be refused by encapsulation.",
            "cases": cases, "invalidEk": [hx(invalid)]])
    }

    // MARK: identity (spec 5.1)

    func testIdentityVectors() throws {
        var derive: [[String: Any]] = []
        for entropy in [rep(0x00, 16), rep(0x11, 16), Array(0..<16)] {
            let id = try SPIdentity.derive(entropy: entropy)
            XCTAssertEqual(id.serialized.count, 33)
            XCTAssertEqual(try SPIdentity.publicKey(serialized: id.serialized), id.publicKey)
            // The same key as CryptoKit makes from the scalar, and as the account code of the apps.
            XCTAssertEqual(id.publicKey, Array(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: id.secret).publicKey.rawRepresentation))
            derive.append(["entropy": hx(entropy), "secret": hx(id.secret), "public": hx(id.publicKey), "serialized": hx(id.serialized)])
        }
        // Keys that are not valid identity public keys: small order points, a non-canonical encoding, a wrong type byte or length.
        let p = SPHex_p
        let invalid: [[String: Any]] = [
            ["public": hx(rep(0, 32)), "why": "u = 0, order 2"],
            ["public": hx([1] + rep(0, 31)), "why": "u = 1, order 4"],
            ["public": hx(p), "why": "u = p, not canonical"],
            ["public": hx(rep(0xFF, 31) + [0xFF]), "why": "top bit set"],
            ["public": hx(unhx("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")), "why": "order 8 point"],
        ]
        for c in invalid { XCTAssertFalse(SPIdentity.isValidPublic(unhx(c["public"] as! String)), c["why"] as! String) }
        let ok = try SPIdentity.derive(entropy: rep(0x11, 16))
        XCTAssertTrue(SPIdentity.isValidPublic(ok.publicKey))
        XCTAssertThrowsError(try SPIdentity.publicKey(serialized: [6] + ok.publicKey))
        XCTAssertThrowsError(try SPIdentity.publicKey(serialized: ok.publicKey))
        try Vectors.check("identity.json", [
            "description": "secret = HKDF-SHA-256(ikm = entropy16, salt = 32 zero bytes, info = ASCII 'swell identity v1', L = 32); public = X25519(secret, 9); serialized = 0x05 | public. invalidPublic keys must be refused as identity public keys.",
            "derive": derive, "invalidPublic": invalid])
    }

    // MARK: SwellSig (spec 5.2)

    func testSignatureVectors() throws {
        // The map from X25519 to Edwards, checked against CryptoKit's own Ed25519 key: the key with seed s has the Edwards public key A and
        // the X25519 scalar clamp(SHA-512(s)[0..<32]); both must describe the same point (A with its sign bit cleared).
        for s in 0..<8 {
            let seed = SP.sha256([UInt8(s)])
            let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            var a = Array(SP.sha512(seed).prefix(32)); a[0] &= 248; a[31] &= 127; a[31] |= 64
            let u = try SP.x25519Public(a)
            var expect = Array(ed.publicKey.rawRepresentation); expect[31] &= 0x7F
            XCTAssertEqual(SPSignature.edwardsKey(fromX25519: u), expect, "seed \(s)")
        }
        var map: [[String: Any]] = []
        for e in [rep(0x00, 16), rep(0x11, 16), Array(0..<16)] {
            let id = try SPIdentity.derive(entropy: e)
            map.append(["x25519": hx(id.publicKey), "edwards": hx(SPSignature.edwardsKey(fromX25519: id.publicKey)!)])
        }

        let id = try SPIdentity.derive(entropy: rep(0x11, 16))
        let messages: [(String, [UInt8])] = [("swell-group-state-v1", []), ("swell-group-state-v1", Array("group state bytes".utf8)), ("test", rep(0xAB, 300))]
        var cases: [[String: Any]] = []
        for (ctx, m) in messages {
            let sig = try SPSignature.sign(identitySecret: id.secret, context: ctx, m)
            XCTAssertEqual(sig, try SPSignature.sign(identitySecret: id.secret, context: ctx, m), "deterministic")
            XCTAssertTrue(SPSignature.verify(identityPublic: id.publicKey, context: ctx, message: m, signature: sig))
            XCTAssertFalse(SPSignature.verify(identityPublic: id.publicKey, context: ctx + "x", message: m, signature: sig))
            var other = m; other.append(0)
            XCTAssertFalse(SPSignature.verify(identityPublic: id.publicKey, context: ctx, message: other, signature: sig))
            cases.append(["secret": hx(id.secret), "public": hx(id.publicKey), "context": ctx, "message": hx(m), "signature": hx(sig)])
        }
        // Both signs of x occur among honest keys: sign with many keys and check all verify.
        for i in 0..<12 {
            let k = try SPIdentity.derive(entropy: rep(UInt8(0x30 + i), 16))
            let sig = try SPSignature.sign(identitySecret: k.secret, context: "t", [UInt8(i)])
            XCTAssertTrue(SPSignature.verify(identityPublic: k.publicKey, context: "t", message: [UInt8(i)], signature: sig), "key \(i)")
        }
        // Rejections: flipped bit in R, flipped bit in S, S >= L, a signature under another key, a short signature.
        let good = try SPSignature.sign(identitySecret: id.secret, context: "swell-group-state-v1", Array("x".utf8))
        func flip(_ at: Int) -> [UInt8] { var s = good; s[at] ^= 1; return s }
        var sPlusL = good
        do { // S + L (still 32 bytes): a valid signature value made non-canonical
            let s = SPBig(le: Array(good[32...])) + SPBig.l
            sPlusL = Array(good[..<32]) + s.leBytes(32)
        }
        let negatives: [[String: Any]] = [
            ["why": "bit flipped in R", "signature": hx(flip(0))],
            ["why": "bit flipped in S", "signature": hx(flip(40))],
            ["why": "S + L, not canonical", "signature": hx(sPlusL)],
            ["why": "63 bytes", "signature": hx(Array(good.dropLast()))],
        ]
        for n in negatives { XCTAssertFalse(SPSignature.verify(identityPublic: id.publicKey, context: "swell-group-state-v1", message: Array("x".utf8), signature: unhx(n["signature"] as! String)), n["why"] as! String) }
        let stranger = try SPIdentity.derive(entropy: rep(0x12, 16))
        XCTAssertFalse(SPSignature.verify(identityPublic: stranger.publicKey, context: "swell-group-state-v1", message: Array("x".utf8), signature: good))
        let strict = try strictCases(id: id, good: good)
        try Vectors.check("signature.json", [
            "description": "SwellSig (spec 5.2). edwardsMap: X25519 public -> Edwards key A (y, sign bit 0). sign: deterministic, the signature must match byte for byte and verify. negative: each must fail verification of (public, context swell-group-state-v1, message 78) . strict: hostile signatures on which RFC 8032 verifiers can differ; every one must fail SwellSig verification (spec 5.2 strict rules), whatever the two equations say. plainEquation and cofactoredEquation say whether [S]B = R + [k]A and [8][S]B = [8]R + [8][k]A hold, with k = SHA-512(R | A | msg) mod L, computed by the generator; they explain each case and are not checked.",
            "edwardsMap": map, "sign": cases, "negativePublic": hx(id.publicKey), "negativeMessage": hx(Array("x".utf8)), "negative": negatives,
            "strict": strict])
    }

    /// Spec 5.2 strict verification: signatures with a small-order part in R or A, R the identity, R not canonical. Each must be refused.
    private func strictCases(id: SPIdentity, good: [UInt8]) throws -> [[String: Any]] {
        let ctx = "swell-group-state-v1"
        func msg(_ m: [UInt8]) -> [UInt8] { SPSignature.message(context: ctx, m) }
        func kOf(_ r: [UInt8], _ a: [UInt8], _ m: [UInt8]) -> SPBig { SPBig(le: SP.sha512(r + a + msg(m))).mod(SPBig.l) }
        func same(_ p: SPEdPoint, _ q: SPEdPoint) -> Bool { p.encode() == q.encode() }
        // A point of order exactly 8: [L] of a point that has a small-order part, kept when [4] of it is not the identity.
        var t8: SPEdPoint?
        var yTry: UInt32 = 2
        while t8 == nil {
            if let p = SPEdPoint.decode(SPBig(yTry).leBytes(32)) {
                let t = p.mul(SPBig.l)
                if !t.adding(t).adding(t.adding(t)).isIdentity { t8 = t }
            }
            yTry += 1
        }
        let torsion = t8!
        XCTAssertTrue(torsion.mul(SPBig(8)).isIdentity)
        // The Ed25519 scalar that goes with the verifier's A of an identity: a or L - a (the sign of x of [a]B).
        func scalar(_ secret: [UInt8], _ aEnc: [UInt8]) -> SPBig {
            let a = SPBig(le: SPSignature.clamp(secret)).mod(SPBig.l)
            return SPEdPoint.base.mul(a).encode() == aEnc ? a : SPBig.l - a
        }
        func equations(_ u: [UInt8], _ m: [UInt8], _ sig: [UInt8]) -> (plain: Bool, cofactored: Bool) {
            // R read leniently (y reduced mod p), as a lenient verifier would: the equations are about the point, not the encoding.
            var yr = Array(sig[..<32]); let signBit = yr[31] & 0x80; yr[31] &= 0x7F
            var canon = SPBig(le: yr).modP().leBytes(32); canon[31] |= signBit
            guard let aEnc = SPSignature.edwardsKey(fromX25519: u), let a = SPEdPoint.decode(aEnc), let r = SPEdPoint.decode(canon) else { return (false, false) }
            let sb = SPEdPoint.base.mul(SPBig(le: Array(sig[32...])))
            let rhs = r.adding(a.mul(kOf(Array(sig[..<32]), aEnc, m)))
            return (same(sb, rhs), same(sb.mul(SPBig(8)), rhs.mul(SPBig(8))))
        }
        var out: [[String: Any]] = []
        func add(_ why: String, _ u: [UInt8], _ m: [UInt8], _ sig: [UInt8]) {
            XCTAssertFalse(SPSignature.verify(identityPublic: u, context: ctx, message: m, signature: sig), why)
            let e = equations(u, m, sig)
            out.append(["why": why, "public": hx(u), "context": ctx, "message": hx(m), "signature": hx(sig), "plainEquation": e.plain, "cofactoredEquation": e.cofactored])
        }
        let m0 = Array("x".utf8)
        let aEnc = SPSignature.edwardsKey(fromX25519: id.publicKey)!
        let a0 = scalar(id.secret, aEnc)
        XCTAssertEqual(SPEdPoint.base.mul(a0).encode(), aEnc)
        // 1. R = [r]B plus a point of order 8, S = r + k a with k over those R bytes: the cofactored equation holds, the plain one does not.
        let r1s = SPBig(le: SP.sha256(Array("edge nonce".utf8))).mod(SPBig.l)
        let r1 = SPEdPoint.base.mul(r1s).adding(torsion).encode()
        add("R + a point of order 8 (cofactored equation holds)", id.publicKey, m0, r1 + r1s.addMod(kOf(r1, aEnc, m0).mulMod(a0, SPBig.l), SPBig.l).leBytes(32))
        // 2. R the identity, S = k a: both equations hold. Made only with the secret; refused because R is not of order L.
        let rId = SPEdPoint.identity.encode()
        add("R is the identity, S = k a (both equations hold)", id.publicKey, m0, rId + kOf(rId, aEnc, m0).mulMod(a0, SPBig.l).leBytes(32))
        // 3. The identity with a non-canonical y (p + 1), S = k a over those bytes: a lenient decoder reads it as the identity.
        let rNon = (SPBig.p + SPBig(1)).leBytes(32)
        add("R not canonical (y = p + 1), S = k a", id.publicKey, m0, rNon + kOf(rNon, aEnc, m0).mulMod(a0, SPBig.l).leBytes(32))
        // 4. A hostile identity key whose Edwards form has a point of order 8 in it. With k = 0 mod 8 (before and after reducing mod L)
        // every plain verifier accepts the signature; SwellSig refuses the key.
        let hostileA = SPBig(le: SPSignature.clamp(SP.sha256(Array("hostile".utf8)))).mod(SPBig.l)
        let q = SPEdPoint.base.mul(hostileA).adding(torsion)
        let qEnc = q.encode()
        var yq = qEnc; yq[31] &= 0x7F
        let y = SPBig(le: yq)
        let uHostile = SPBig(1).addModP(y).mulModP(SPBig(1).subModP(y).invModP()).leBytes(32) // u = (1 + y) / (1 - y)
        XCTAssertTrue(SPIdentity.isValidPublic(uHostile), "canonical and not of small order: it passes spec 5.1")
        let vEnc = SPSignature.edwardsKey(fromX25519: uHostile)!
        let v = SPEdPoint.decode(vEnc)!
        let aEff = same(v, q) ? hostileA : SPBig.l - hostileA
        let r = SPBig(le: SP.sha256(Array("hostile nonce".utf8))).mod(SPBig.l), rEnc = SPEdPoint.base.mul(r).encode()
        var counter: UInt32 = 0, m4: [UInt8] = []
        while true {
            m4 = Array("hostile state ".utf8) + SPBig(counter).leBytes(4)
            let full = SPBig(le: SP.sha512(rEnc + vEnc + msg(m4)))
            if full.mod(SPBig(8)).isZero && full.mod(SPBig.l).mod(SPBig(8)).isZero { break }
            counter += 1
        }
        let s4 = r.addMod(kOf(rEnc, vEnc, m4).mulMod(aEff, SPBig.l), SPBig.l)
        add("A has a point of order 8 in it, k = 0 mod 8 (both equations hold)", uHostile, m4, rEnc + s4.leBytes(32))
        XCTAssertEqual(out.map { $0["plainEquation"] as! Bool }, [false, true, true, true])
        XCTAssertEqual(out.map { $0["cofactoredEquation"] as! Bool }, [true, true, true, true])
        return out
    }
}

private let SPHex_p: [UInt8] = SPHexLE("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")

extension Array {
    subscript(safe i: Int) -> Element? { indices.contains(i) ? self[i] : nil }
}
