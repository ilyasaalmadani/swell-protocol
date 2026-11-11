// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation

// Swell Protocol draft 3, spec sections 5 (bundle), 6 (handshake), 7.1 (initial state), 11 (safety numbers).
// The pattern is X3DH without a one-time prekey plus an ML-KEM-768 secret as in PQXDH (both public-domain documents).
// Draft 3: `ID_I` and `ID_J` are the two people's identity keys (SPIdentity), checked by the caller against the invite or the
// contact record, and the prekey signature is replaced by the secrecy of the invite (or by the link key, SPLink). A person
// proves they hold their identity key by the handshake itself: without its private key no HELLO opens (spec 6.3).

/// I's secrets for one open bundle (an invite or an offer). Deleted at accept or at expiry (spec 12).
/// The identity private key is not here: it is one key for the whole account and is passed in at accept time.
public struct SPInviterSecrets: Sendable {
    public var epkSK: [UInt8], kemSeed: [UInt8]
    public var bundle: SPWire.Bundle

    public init(epkSK: [UInt8], kemSeed: [UInt8], bundle: SPWire.Bundle) { self.epkSK = epkSK; self.kemSeed = kemSeed; self.bundle = bundle }

    public func encode() -> [UInt8] { SPOut().raw(epkSK).raw(kemSeed).raw(bundle.encode()).done() }
    public static func decode(_ b: [UInt8]) throws -> SPInviterSecrets {
        let r = SPIn(b)
        let s = SPInviterSecrets(epkSK: try r.raw(32), kemSeed: try r.raw(SP.kemSeedLen), bundle: try SPWire.Bundle.decode(try r.raw(SPWire.bundleLen)))
        try r.end()
        return s
    }
}

public enum SPHandshake {
    /// I accepts a HELLO up to this long after `expiresAtMs` (spec 6.2 step 1).
    public static let acceptGraceMillis: Int64 = 10 * 60 * 1000
    /// J refuses a bundle that expires more than this far ahead (7 days, the longest lifetime of an offer, plus one hour of clock skew),
    /// so a contact can neither overflow an expiry nor keep J's HELLO_SENT alive for ever (review N1).
    public static let maxExpiryAheadMillis: Int64 = 7 * 86400 * 1000 + 3600 * 1000

    /// Spec 5: fresh `epk_sk, EPK`, `(dk, EK)` and the bundle for the identity key `idI`. Draws 32 bytes (`epk_sk`) then 64 bytes
    /// (the ML-KEM seed) from `entropy`.
    public static func makeBundle(identityPublic idI: [UInt8], expiresAtMs: Int64, entropy: SPEntropy = SPSystemEntropy()) throws -> SPInviterSecrets {
        guard SPIdentity.isValidPublic(idI) else { throw SwellProtocolError.format("identity key") }
        let epk = try SP.x25519(entropy)
        let kem = try SP.kemGenerate(entropy)
        return SPInviterSecrets(epkSK: epk.sk, kemSeed: kem.seed, bundle: SPWire.Bundle(idI: idI, epk: epk.pk, ek: kem.ek, expiresAtMs: expiresAtMs))
    }

    /// `T = SHA256Tagged("transcript", ID_I | ID_J | EPK | EK | E | ct | binding | i64 expiresAtMs)`.
    /// `binding` is 32 bytes: the invite's binding (6.1) or the offer binding (6.4).
    public static func transcript(_ b: SPWire.Bundle, idJ: [UInt8], e: [UInt8], ct: [UInt8], binding: [UInt8]) -> [UInt8] {
        SP.tagged("transcript", b.idI + idJ + b.epk + b.ek + e + ct + binding + SP.be64(b.expiresAtMs))
    }

    /// `hs = HKDF(salt = T, ikm = 0xFF*32 | dh1 | dh2 | dh3 | ss_kem, info = Info("handshake"), 128)`
    /// -> `RK0 | shared_hka | shared_nhkb | PQ0` (32 bytes each).
    public static func keys(t: [UInt8], dh1: [UInt8], dh2: [UInt8], dh3: [UInt8], ss: [UInt8]) -> (rk0: [UInt8], hka: [UInt8], nhkb: [UInt8], pq0: [UInt8]) {
        var ikm = [UInt8](repeating: 0xFF, count: 32) + dh1 + dh2 + dh3 + ss
        var hs = SP.hkdf(salt: t, ikm: ikm, info: SP.info("handshake"), 128)
        defer { SP.wipe(&ikm); SP.wipe(&hs) }
        return (Array(hs[0..<32]), Array(hs[32..<64]), Array(hs[64..<96]), Array(hs[96..<128]))
    }

    /// Spec 6.1 (J redeems), steps 2 to 5: checks the bundle, runs the handshake, sets up the Alice role (7.1) and builds the
    /// HELLO as ratchet message 0 carrying `inner`. Returns the exact HELLO bytes and the state; the caller commits both in
    /// one transaction. `expectedInviter` is the 32-byte public identity key the bundle must name (from the invite or the contact record).
    /// `entropy` is drawn in this order: `E` (32 bytes), `ratchet_sk` (32 bytes), plus the KEM encapsulation.
    public static func joinerStart(bundle b: SPWire.Bundle, expectedInviter: [UInt8], identity: SPIdentity, binding: [UInt8], inner: [UInt8],
                                   now: Int64, policy: SPPolicy = .standard, entropy: SPEntropy = SPSystemEntropy()) throws -> (hello: [UInt8], session: SPSession) {
        guard binding.count == 32 else { throw SwellProtocolError.format("binding") }
        guard SP.ctEqual(b.idI, expectedInviter), SPIdentity.isValidPublic(b.idI) else { throw SwellProtocolError.crypto("inviter identity") }
        guard now <= b.expiresAtMs else { throw SwellProtocolError.format("expired") }
        guard b.expiresAtMs <= SP.sat(now, maxExpiryAheadMillis) else { throw SwellProtocolError.format("expiry too far ahead") }
        var e = try SP.x25519(entropy), ratchet = try SP.x25519(entropy)
        let kem = try entropy.encapsulate(b.ek)
        let dh1 = try SP.dh(identity.secret, b.epk), dh2 = try SP.dh(e.sk, b.idI), dh3 = try SP.dh(e.sk, b.epk)
        let t = transcript(b, idJ: identity.publicKey, e: e.pk, ct: kem.ct, binding: binding)
        let k = keys(t: t, dh1: dh1, dh2: dh2, dh3: dh3, ss: kem.ss)
        // Spec 6.1 step 5: e_sk, ss_kem, the DH outputs and hs are never stored, and go out of scope here
        // (Swift gives no erasure guarantee for them, spec 12).
        e.sk = []
        // 7.1, J (Alice): RK, CKs, NHKs = KDF_RK(RK0, DH(ratchet_sk, EPK)); HKs = shared_hka; NHKr = shared_nhkb.
        let r = SPSession.kdfRK(k.rk0, try SP.dh(ratchet.sk, b.epk))
        var s = SPSession(inviter: false, transcript: t, idSelf: identity.publicKey, idPeer: b.idI, dhsSK: ratchet.sk, dhsPK: ratchet.pk,
                          rk: r.rk, pq: SPPQState(pq0: k.pq0, now: now))
        s.entropy = entropy
        ratchet.sk = []
        s.dhr = b.epk; s.cks = r.ck; s.nhks = r.nhk; s.hks = k.hka; s.nhkr = k.nhkb
        let (after, hello) = try s.encrypt(inner, now: now, policy: policy, helloKeys: identity.publicKey + e.pk + kem.ct)
        return (hello, after)
    }

    /// Spec 6.2 (I accepts), steps 1 to 3: the handshake from I's side, the Bob role (7.1), and the normal receive of the HELLO.
    /// Returns J's inner message and the state (`session.idPeer` is J's public identity key, proved by the HELLO opening).
    /// Throws, changing nothing, on any failure (6.2 step 4).
    public static func inviterAccept(_ secrets: SPInviterSecrets, identity: SPIdentity, hello: [UInt8], binding: [UInt8], now: Int64,
                                     policy: SPPolicy = .standard, entropy: SPEntropy = SPSystemEntropy()) throws -> (inner: [UInt8], session: SPSession) {
        guard binding.count == 32 else { throw SwellProtocolError.format("binding") }
        guard SP.ctEqual(secrets.bundle.idI, identity.publicKey) else { throw SwellProtocolError.crypto("bundle identity") }
        guard now <= SP.sat(secrets.bundle.expiresAtMs, acceptGraceMillis) else { throw SwellProtocolError.format("expired") }
        let env = try SPWire.Envelope.decode(hello)
        guard env.kind == SPWire.kindHello, env.helloKeys.count == SPWire.helloKeysLen else { throw SwellProtocolError.format("hello") }
        let idJ = Array(env.helloKeys[0..<32]), e = Array(env.helloKeys[32..<64]), ct = Array(env.helloKeys[64...])
        guard SPIdentity.isValidPublic(idJ) else { throw SwellProtocolError.format("joiner identity") }
        var dh1 = try SP.dh(secrets.epkSK, idJ), dh2 = try SP.dh(identity.secret, e), dh3 = try SP.dh(secrets.epkSK, e)
        var ss = try SP.kemDecapsulate(seed: secrets.kemSeed, ct)
        let t = transcript(secrets.bundle, idJ: idJ, e: e, ct: ct, binding: binding)
        let k = keys(t: t, dh1: dh1, dh2: dh2, dh3: dh3, ss: ss)
        SP.wipe(&ss); SP.wipe(&dh1); SP.wipe(&dh2); SP.wipe(&dh3) // owned outright here, so these wipes reach the only copy
        // 7.1, I (Bob): DHs = (epk_sk, EPK); RK = RK0; NHKs = shared_nhkb; NHKr = shared_hka.
        var s = SPSession(inviter: true, transcript: t, idSelf: secrets.bundle.idI, idPeer: idJ, dhsSK: secrets.epkSK,
                          dhsPK: secrets.bundle.epk, rk: k.rk0, pq: SPPQState(pq0: k.pq0, now: now))
        s.entropy = entropy
        s.nhks = k.nhkb; s.nhkr = k.hka
        let (after, inner) = try s.decrypt(hello, now: now, policy: policy, allowHello: true)
        return (inner, after)
    }

    // MARK: 6.1 and 6.4 bindings

    /// Invite binding of a mailbox invite (version 5): the invite's `queueId` (32 bytes).
    /// Direct-onion invite (version 6): `SHA256Tagged("direct", secret)`.
    public static func directBinding(secret: [UInt8]) -> [UInt8] { SP.tagged("direct", secret) }

    /// `binding = SHA256Tagged("upgrade", channelId | lo | hi | offerId)`, with `lo`, `hi` the two serialized identity keys
    /// (33 bytes each, `SPIdentity.serialized`) in unsigned byte order. Used by the link path (6.4).
    public static func upgradeBinding(channelId: [UInt8], identityA: [UInt8], identityB: [UInt8], offerId: [UInt8]) -> [UInt8] {
        let (lo, hi) = identityA.lexicographicallyPrecedes(identityB) ? (identityA, identityB) : (identityB, identityA)
        return SP.tagged("upgrade", channelId + lo + hi + offerId)
    }

    // MARK: 11 safety numbers

    /// `okm = HKDF(salt = 32 zero bytes, ikm = lo | hi, info = Info("safety"), 60)`, `lo` and `hi` the two serialized identity keys
    /// (33 bytes each) in unsigned byte order. The 60 bytes are also the content of the safety-number QR code (spec 11).
    public static func safetyBytes(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        let (lo, hi) = a.lexicographicallyPrecedes(b) ? (a, b) : (b, a)
        return SP.hkdf(salt: [UInt8](repeating: 0, count: 32), ikm: lo + hi, info: SP.info("safety"), 60)
    }

    /// 12 groups of 5 digits: each group is 5 bytes of `safetyBytes` read as a big-endian number mod 100000, printed with leading zeros.
    public static func safetyNumber(_ a: [UInt8], _ b: [UInt8]) -> String {
        let okm = safetyBytes(a, b)
        return (0..<12).map { g -> String in
            var v: UInt64 = 0
            for i in 0..<5 { v = (v << 8) | UInt64(okm[g * 5 + i]) }
            let s = String(v % 100_000)
            return String(repeating: "0", count: 5 - s.count) + s
        }.joined(separator: " ")
    }

    /// Text of the safety-number QR code: `swell-safety:` + base64url without padding of the 60 bytes of `safetyBytes`.
    /// Both phones compute the same text, so scanning is an equality check.
    public static func safetyQRText(_ a: [UInt8], _ b: [UInt8]) -> String {
        "swell-safety:" + Data(safetyBytes(a, b)).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
