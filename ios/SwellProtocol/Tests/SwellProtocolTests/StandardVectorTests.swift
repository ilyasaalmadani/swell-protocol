// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import XCTest
import CryptoKit
@testable import SwellProtocol

/// Spec appendix A (docs/SWELL-PROTOCOL-SPEC.md, draft 3 keeps the draft 2 values): standard primitive vectors and Swell's own vectors.
/// Every hex value here is also printed in the spec; a Kotlin implementation must produce the same bytes.
final class StandardVectorTests: XCTestCase {
    static func h(_ s: String) -> [UInt8] { try! SPHex.decode(s) }
    static func rep(_ b: UInt8, _ n: Int) -> [UInt8] { [UInt8](repeating: b, count: n) }

    /// All Swell vectors in one place: name -> hex. `SWELL_DUMP_VECTORS=1 swift test --filter StandardVectorTests` prints them.
    static func swellVectors() throws -> [(String, String)] {
        var v: [(String, String)] = []
        func add(_ n: String, _ b: [UInt8]) { v.append((n, SPHex.encode(b))) }
        add("A.1 Info(\"root\")", SP.info("root"))
        add("A.2 Info(\"pq-message\", i32 5)", SP.info("pq-message", SP.be32(5)))
        add("A.3 SHA256Tagged(\"bundle\", 00*4)", SP.tagged("bundle", rep(0, 4)))
        let rk = SPSession.kdfRK(rep(0x01, 32), rep(0x02, 32))
        add("A.4 KDF_RK(01*32, 02*32).RK'", rk.rk); add("A.4 .CK", rk.ck); add("A.4 .NHK", rk.nhk)
        let ck = SPSession.kdfCK(rep(0x03, 32))
        add("A.5 KDF_CK(03*32).CK'", ck.ck); add("A.5 .mk_dr", ck.mk)
        let mk = SPSession.combine(rep(0x04, 32), pq: rep(0x05, 32), epoch: 1)
        add("A.6 combine(mk_dr 04*32, PQ 05*32, epoch 1).mk", mk.key); add("A.6 .body_nonce", mk.nonce)
        let header = SPWire.Header(dhPub: rep(0x07, 32), pn: 1, n: 2, epoch: 3).encode()
        add("A.7 header(dh_pub 07*32, pn 1, n 2, epoch 3)", header)
        let hk = SPSession.headerKeys(rep(0x06, 32))
        add("A.7 hk_enc(hk 06*32)", hk.enc); add("A.7 hk_iv", hk.iv)
        add("A.7 hnonce", SPSession.headerNonce(iv: hk.iv, header: header))
        // Handshake from fixed keys; ss_kem stands in for ML-KEM (whose encapsulation is randomised).
        let idI = try SP.x25519Public(rep(0x11, 32)), epk = try SP.x25519Public(rep(0x12, 32))
        let idJ = try SP.x25519Public(rep(0x13, 32)), e = try SP.x25519Public(rep(0x14, 32))
        let b = SPWire.Bundle(idI: idI, epk: epk, ek: rep(0x15, SP.kemEKLen), expiresAtMs: 1_800_000_000_000)
        add("A.8 bundleCommit", b.commit)
        let t = SPHandshake.transcript(b, idJ: idJ, e: e, ct: rep(0x16, SP.kemCTLen), binding: rep(0x17, 32))
        add("A.8 T", t)
        let dh1 = try SP.dh(rep(0x13, 32), epk), dh2 = try SP.dh(rep(0x14, 32), idI), dh3 = try SP.dh(rep(0x14, 32), epk)
        let k = SPHandshake.keys(t: t, dh1: dh1, dh2: dh2, dh3: dh3, ss: rep(0x18, 32))
        add("A.8 RK0", k.rk0); add("A.8 shared_hka", k.hka); add("A.8 shared_nhkb", k.nhkb); add("A.8 PQ0", k.pq0)
        add("A.9 PQ_1 = next(PQ 08*32, ss 09*32, t 1, ek 0a*1184, ct 0b*1088)",
            SPPQState.nextKey(rep(0x08, 32), ss: rep(0x09, 32), target: 1, ek: rep(0x0a, SP.kemEKLen), ct: rep(0x0b, SP.kemCTLen)))
        add("A.10 upgrade binding(channel 0c*16, keys 05|0d*32 and 05|0e*32, offer 0f*16)",
            SPHandshake.upgradeBinding(channelId: rep(0x0c, 16), identityA: [5] + rep(0x0e, 32), identityB: [5] + rep(0x0d, 32), offerId: rep(0x0f, 16)))
        add("A.11 safety bytes(ID 0c*32, ID 0d*32)", SPHandshake.safetyBytes(rep(0x0d, 32), rep(0x0c, 32)))
        return v
    }

    static let expected: [String: String] = [
        "A.1 Info(\"root\")": "5377656c6c000204726f6f74",
        "A.2 Info(\"pq-message\", i32 5)": "5377656c6c00020a70712d6d657373616765000400000005",
        "A.3 SHA256Tagged(\"bundle\", 00*4)": "292e76d917b207cc9f3bd135f323609c7b110b321705a8f47012bc47b7fbaca6",
        "A.4 KDF_RK(01*32, 02*32).RK'": "867d297231be8e1dd34dbd9ad0b6a6355b2feb9ab7f24e444c78779626ae69ba",
        "A.4 .CK": "f1ebe66a8309a8712f86f3b3e11891bb02087bce91b2ae4a0a084d9b76a082cf",
        "A.4 .NHK": "80e4c12cadf0acdaa48a1765a63f9224a43f8a2ccfca60271c5c13eb3939224e",
        "A.5 KDF_CK(03*32).CK'": "70fc6d94291a0e4dbc5af3839301772646620faaeb2733d7d9f54b4e8c80c53f",
        "A.5 .mk_dr": "d3d194ab575909331c94c2cf10090ec36b9daf94038bb5077b005a0a3ef2fa0e",
        "A.6 combine(mk_dr 04*32, PQ 05*32, epoch 1).mk": "c4cd9ed26fbd4c361a29c64fcc01604b1e043fc88939a44b0b610d7654e93cfb",
        "A.6 .body_nonce": "f50bc14935410b17ca9212da",
        "A.7 header(dh_pub 07*32, pn 1, n 2, epoch 3)": "0707070707070707070707070707070707070707070707070707070707070707000000010000000200000003",
        "A.7 hk_enc(hk 06*32)": "036f00d2bd4b7cdeafe6e423fa85b7072545c6ead718d123d828a2bc61784197",
        "A.7 hk_iv": "4ff5aa6aa18eaddb7fb90b3d4423f29a344c80555ccaac8e6e3e5218c552836d",
        "A.7 hnonce": "fb5351a08626fcca5d921060",
        "A.8 bundleCommit": "932c74e147a28b35236af22ee822cbdb726722e70a0c539a6fc3b00ff5c6fcd9",
        "A.8 T": "3490cc2321d9e8a39a7d55f84bf7a8e6999f005897d2fc1289baa776666befa0",
        "A.8 RK0": "add2d1531c5d153e495c91787d6515ae641fb66ebe5a3e4756ce5ad431d14d9b",
        "A.8 shared_hka": "90f60e5471d21011fd3c87e24fb813844066b59bbd88c9eab661fe84b9a15626",
        "A.8 shared_nhkb": "14a82ce5c49aa99ed7f2754d83ee99ceb5abf4a364ce0c82ff7c0090af1e0996",
        "A.8 PQ0": "5fb047f9baae785bea365c7b296f73480e38c62a7497927f2bfb983bf0a644c6",
        "A.9 PQ_1 = next(PQ 08*32, ss 09*32, t 1, ek 0a*1184, ct 0b*1088)": "58fd84d676c909bec66b6998ace3d9659ccdc03c5d1f1f55d0e0df057929aeff",
        "A.10 upgrade binding(channel 0c*16, keys 05|0d*32 and 05|0e*32, offer 0f*16)": "7bf5c11a10049b2be0d07b6acc141c7a41b32635176574b373e1ff51f57f96a0",
        "A.11 safety bytes(ID 0c*32, ID 0d*32)": "803464028e6feb306761fe119327684c7e93105265959a185d8326964b758a6088f0ac7eea029ac69efc7211cc6ea1d2fb928e35c03890896d7ae822",
    ]

    func testSwellVectors() throws {
        let v = try Self.swellVectors()
        if ProcessInfo.processInfo.environment["SWELL_DUMP_VECTORS"] != nil { for (n, x) in v { print("VECTOR \(n) = \(x)") } }
        XCTAssertEqual(v.count, Self.expected.count, "vector table")
        for (n, x) in v { XCTAssertEqual(x, Self.expected[n], n) }
    }

    func testSafetyDigitsVector() {
        let s = SPHandshake.safetyNumber(Self.rep(0x0c, 32), Self.rep(0x0d, 32))
        XCTAssertEqual(s, SPHandshake.safetyNumber(Self.rep(0x0d, 32), Self.rep(0x0c, 32)), "order-free")
        XCTAssertEqual(s.split(separator: " ").count, 12)
        XCTAssertEqual(s, Self.expectedSafety)
    }
    static let expectedSafety = "83374 87809 49736 81682 00861 99701 74092 18534 66860 61298 45872 90914"

    // MARK: standard vectors at the primitive boundary (spec 13)

    /// RFC 7748 section 6.1.
    func testX25519RFC7748() throws {
        let a = Self.h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let b = Self.h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        XCTAssertEqual(try SP.x25519Public(a), Self.h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        XCTAssertEqual(try SP.x25519Public(b), Self.h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        XCTAssertEqual(try SP.dh(a, try SP.x25519Public(b)), Self.h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
    }

    /// All-zero DH output (a low-order point) is refused (spec 4).
    func testX25519ZeroOutputRefused() {
        XCTAssertThrowsError(try SP.dh(Self.rep(0x22, 32), Self.rep(0, 32)))
        var one = Self.rep(0, 32); one[0] = 1
        XCTAssertThrowsError(try SP.dh(Self.rep(0x22, 32), one))
    }

    /// RFC 5869 test case 1.
    func testHKDFRFC5869() {
        let okm = SP.hkdf(salt: Self.h("000102030405060708090a0b0c"), ikm: Self.rep(0x0b, 22), info: Self.h("f0f1f2f3f4f5f6f7f8f9"), 42)
        XCTAssertEqual(SPHex.encode(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        let prk = Self.h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        XCTAssertEqual(SP.expand(prk, Self.h("f0f1f2f3f4f5f6f7f8f9"), 42), okm)
    }

    /// AES-256-GCM, the zero-key cases of the original GCM test set (cases 13 and 14).
    func testAESGCMVectors() throws {
        let k = Self.rep(0, 32), n = Self.rep(0, 12)
        XCTAssertEqual(SPHex.encode(try SP.seal(key: k, nonce: n, ad: [], [])), "530f8afbc74536b9a963b4f1c4cb738b")
        XCTAssertEqual(SPHex.encode(try SP.seal(key: k, nonce: n, ad: [], Self.rep(0, 16))), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        var bad = try SP.seal(key: k, nonce: n, ad: [1], [9, 9]); bad[0] ^= 1
        XCTAssertThrowsError(try SP.open(key: k, nonce: n, ad: [1], bad))
    }

    /// ML-KEM-768 boundary: lengths, seed determinism, round trip, and implicit rejection of a changed ciphertext.
    func testMLKEMBoundary() throws {
        let k = try SP.kemGenerate()
        XCTAssertEqual(k.seed.count, 64); XCTAssertEqual(k.ek.count, 1184)
        XCTAssertEqual(try SP.kemPublic(seed: k.seed), k.ek, "the stored seed gives back the same key")
        let enc = try SP.kemEncapsulate(k.ek)
        XCTAssertEqual(enc.ct.count, 1088); XCTAssertEqual(enc.ss.count, 32)
        XCTAssertEqual(try SP.kemDecapsulate(seed: k.seed, enc.ct), enc.ss)
        var ct = enc.ct; ct[100] ^= 0x40
        let rejected = try SP.kemDecapsulate(seed: k.seed, ct)
        XCTAssertNotEqual(rejected, enc.ss, "implicit rejection: a pseudo-random secret, no error")
        XCTAssertEqual(try SP.kemDecapsulate(seed: k.seed, ct), rejected, "and a deterministic one")
        XCTAssertThrowsError(try SP.kemEncapsulate(Self.rep(0xFF, 1184)), "an encapsulation key that fails the FIPS 203 check")
    }

    func testConstantTimeHelpers() {
        XCTAssertTrue(SP.ctEqual([1, 2, 3], [1, 2, 3]))
        XCTAssertFalse(SP.ctEqual([1, 2, 3], [1, 2, 4]))
        XCTAssertFalse(SP.ctEqual([1, 2], [1, 2, 3]))
        XCTAssertTrue(SP.isZero([0, 0])); XCTAssertFalse(SP.isZero([0, 1]))
        var b: [UInt8] = [1, 2, 3]; SP.wipe(&b); XCTAssertTrue(b.isEmpty)
    }

    /// Every label is distinct and the encoder is length-prefixed, so no two (label, fields) collide.
    func testInfoEncoding() {
        XCTAssertEqual(SP.info("root"), Array("Swell".utf8) + [0, 2, 4] + Array("root".utf8))
        XCTAssertEqual(SP.info("x", [1, 2]), Array("Swell".utf8) + [0, 2, 1, 0x78, 0, 2, 1, 2])
        XCTAssertNotEqual(SP.info("ab", [1]), SP.info("a", [0x62, 1]))
    }

    // MARK: padding (spec 7.4) at every bucket edge

    func testPaddingEdges() throws {
        for size in SPWire.buckets {
            let fits = size - 4 - 1 // 4-byte length, 1-byte empty PQ field
            let p = try SPWire.pad(pq: .none, inner: Self.rep(0x41, fits))
            XCTAssertEqual(p.count, size)
            XCTAssertEqual(try SPWire.unpad(p).inner, Self.rep(0x41, fits))
            if size != SPWire.buckets.last! { XCTAssertEqual(try SPWire.pad(pq: .none, inner: Self.rep(0x41, fits + 1)).count, SPWire.buckets[SPWire.buckets.firstIndex(of: size)! + 1]) }
        }
        XCTAssertThrowsError(try SPWire.pad(pq: .none, inner: Self.rep(0, 262144 - 4)))
        var p = try SPWire.pad(pq: .none, inner: [1, 2, 3])
        p[p.count - 1] = 1
        XCTAssertThrowsError(try SPWire.unpad(p), "non-zero padding")
        XCTAssertThrowsError(try SPWire.unpad(Self.rep(0, 1000)), "not a bucket size")
        var q = try SPWire.pad(pq: .none, inner: [1]); q[0] = 0x7F
        XCTAssertThrowsError(try SPWire.unpad(q), "length out of range")
        let ek = try SPWire.pad(pq: .ek(target: 3, ek: Self.rep(7, 1184)), inner: [9])
        XCTAssertEqual(try SPWire.unpad(ek).pq, .ek(target: 3, ek: Self.rep(7, 1184)))
        XCTAssertEqual(try SPWire.unpad(ek).inner, [9])
        var badKind = try SPWire.pad(pq: .none, inner: [1]); badKind[4] = 3
        XCTAssertThrowsError(try SPWire.unpad(badKind), "unknown PQ kind")
    }
}
