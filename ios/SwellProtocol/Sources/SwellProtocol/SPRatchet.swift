import Foundation


// Swell Protocol draft 2, spec sections 7 (ratchet) and 8 (send and receive).
//
// The Double Ratchet with header encryption as published (revision 4, public domain), with the Swell differences of spec
// section 7: labelled HKDF-Expand chain steps, a header nonce derived from the header, an `epoch` field in the header, and
// every message key mixed with the PQ epoch key (7.2, 7.6). All operations work on a copy (`var s = self`) and the caller
// stores the result only on success (8.3 step 4), in the same database transaction as the message (8.2, 8.3 step 5).

/// One stored skipped message key (spec 8.1): its header key, number, chain-step key and when it was stored.
public struct SPSkipped: Sendable {
    public var hk: [UInt8], n: Int32, mk: [UInt8], at: Int64
}

/// The full state of one Swell Protocol session (spec 7.1 fields plus 7.6 PQ state). Never logged.
public struct SPSession: Sendable {
    /// True for I (inviter, "Bob" role), false for J (joiner, "Alice" role).
    public var inviter: Bool
    /// Transcript hash T (6.1), bound into every AD.
    public var transcript: [UInt8]
    /// The two public identity keys of the handshake (32-byte X25519 form), kept so the app can check them against the contact.
    public var idSelf: [UInt8], idPeer: [UInt8]
    public var dhsSK: [UInt8], dhsPK: [UInt8]
    /// Empty = None (as in the published text).
    public var dhr: [UInt8] = []
    public var rk: [UInt8]
    public var cks: [UInt8] = [], ckr: [UInt8] = []
    public var hks: [UInt8] = [], hkr: [UInt8] = [], nhks: [UInt8] = [], nhkr: [UInt8] = []
    public var ns: Int32 = 0, nr: Int32 = 0, pn: Int32 = 0
    public var skipped: [SPSkipped] = []
    public var pq: SPPQState
    /// Where new ratchet keys and ML-KEM keys come from. Not stored. Only tests replace it.
    public var entropy: SPEntropy = SPSystemEntropy()

    // MARK: 7.2 key derivation

    /// `KDF_RK(RK, dh) = HKDF(salt = RK, ikm = dh, info = Info("root"), 96) -> RK' | CK | NHK`.
    static func kdfRK(_ rk: [UInt8], _ dh: [UInt8]) -> (rk: [UInt8], ck: [UInt8], nhk: [UInt8]) {
        var o = SP.hkdf(salt: rk, ikm: dh, info: SP.info("root"), 96)
        defer { SP.wipe(&o) }
        return (Array(o[0..<32]), Array(o[32..<64]), Array(o[64..<96]))
    }

    /// `KDF_CK(CK)`: `CK' = Expand(CK, Info("chain"), 32)`, chain-step key `mk_dr = Expand(CK, Info("message"), 32)`.
    static func kdfCK(_ ck: [UInt8]) -> (ck: [UInt8], mk: [UInt8]) {
        (SP.expand(ck, SP.info("chain"), 32), SP.expand(ck, SP.info("message"), 32))
    }

    /// Spec 7.2 / 7.6: `mk | body_nonce = HKDF(salt = PQ_epoch, ikm = mk_dr, info = Info("pq-message", i32 epoch), 44)`.
    static func combine(_ mkDR: [UInt8], pq: [UInt8], epoch: Int32) -> (key: [UInt8], nonce: [UInt8]) {
        var o = SP.hkdf(salt: pq, ikm: mkDR, info: SP.info("pq-message", SP.be32(epoch)), 44)
        defer { SP.wipe(&o) }
        return (Array(o[0..<32]), Array(o[32..<44]))
    }

    /// Header protection keys: `hk_enc = Expand(hk, Info("header-enc"), 32)`, `hk_iv = Expand(hk, Info("header-iv"), 32)`,
    /// `hnonce = Expand(hk_iv, Info("header-nonce", header), 12)`.
    static func headerKeys(_ hk: [UInt8]) -> (enc: [UInt8], iv: [UInt8]) {
        (SP.expand(hk, SP.info("header-enc"), 32), SP.expand(hk, SP.info("header-iv"), 32))
    }
    static func headerNonce(iv: [UInt8], header: [UInt8]) -> [UInt8] { SP.expand(iv, SP.info("header-nonce", header), 12) }

    static func headerAD(prefix: [UInt8], transcript: [UInt8]) -> [UInt8] { Array("SWL2-H".utf8) + prefix + transcript }
    static func bodyAD(transcript: [UInt8], prefix: [UInt8], hnonce: [UInt8], hct: [UInt8]) -> [UInt8] {
        Array("SWL2-M".utf8) + transcript + prefix + hnonce + hct
    }

    // MARK: 8.2 send

    /// Encrypts one inner message. Returns the new state and the exact envelope bytes; the caller commits both in one
    /// transaction and retries the same bytes, never re-encrypting. `helloKeys` non-empty makes a HELLO (J's message 0).
    /// `allowPQ` is false for best-effort frames that may be lost without a retry (review F5).
    public func encrypt(_ inner: [UInt8], now: Int64, policy: SPPolicy = .standard, helloKeys: [UInt8] = [], allowPQ: Bool = true) throws -> (SPSession, [UInt8]) {
        var s = self
        guard s.cks.count == 32, s.hks.count == 32 else { throw SwellProtocolError.noSession }
        guard s.ns < policy.maxChain else { throw SwellProtocolError.limit("chain") }
        s.pruneSkipped(now: now, policy: policy)
        let plain = SPWire.bucket(4 + 1 + inner.count)
        let field = try s.pq.prepareSend(inviter: inviter, firstOfChain: s.ns == 0, now: now, policy: policy, entropy: entropy) { len in
            guard allowPQ, let without = plain, let with = SPWire.bucket(4 + len + inner.count) else { return false }
            return with == without || without <= SPWire.pqBucketCap
        }
        guard let epochKey = s.pq.key(s.pq.sendEpoch) else { throw SwellProtocolError.noSession }
        let step = Self.kdfCK(s.cks)
        var mk = Self.combine(step.mk, pq: epochKey, epoch: s.pq.sendEpoch)
        let header = SPWire.Header(dhPub: s.dhsPK, pn: s.pn, n: s.ns, epoch: s.pq.sendEpoch).encode()
        let kind = helloKeys.isEmpty ? SPWire.kindData : SPWire.kindHello
        let prefix = [SPWire.ver, kind] + helloKeys
        let hk = Self.headerKeys(s.hks)
        let hnonce = Self.headerNonce(iv: hk.iv, header: header)
        let hct = try SP.seal(key: hk.enc, nonce: hnonce, ad: Self.headerAD(prefix: prefix, transcript: s.transcript), header)
        let body = try SP.seal(key: mk.key, nonce: mk.nonce, ad: Self.bodyAD(transcript: s.transcript, prefix: prefix, hnonce: hnonce, hct: hct),
                               try SPWire.pad(pq: field, inner: inner))
        SP.wipe(&mk.key)
        s.cks = step.ck // the old chain key leaves the stored state with this step
        s.ns += 1
        if s.pq.sentInEpoch < Int32.max { s.pq.sentInEpoch += 1 }
        return (s, prefix + hnonce + hct + body)
    }

    // MARK: 8.3 receive

    /// Opens one envelope on a copy of the state. Throws without any state change on every failure (8.4).
    /// `allowHello` is set only by the inviter's handshake (6.2); everywhere else a HELLO is dropped.
    public func decrypt(_ bytes: [UInt8], now: Int64, policy: SPPolicy = .standard, allowHello: Bool = false) throws -> (SPSession, [UInt8]) {
        var s = self
        let env = try SPWire.Envelope.decode(bytes)
        guard env.kind == SPWire.kindData || (allowHello && env.kind == SPWire.kindHello) else { throw SwellProtocolError.format("kind") }
        s.pruneSkipped(now: now, policy: policy)
        let hAD = Self.headerAD(prefix: env.prefix, transcript: s.transcript)

        // Step 2: every distinct candidate header key (those of stored skipped keys, HKr, NHKr); exactly one must open the header.
        var candidates: [[UInt8]] = []
        for k in s.skipped.map(\.hk) + [s.hkr, s.nhkr] where k.count == 32 && !candidates.contains(where: { SP.ctEqual($0, k) }) {
            candidates.append(k)
        }
        var opened: [([UInt8], [UInt8])] = []
        for hk in candidates {
            let keys = Self.headerKeys(hk)
            if let h = try? SP.open(key: keys.enc, nonce: env.hnonce, ad: hAD, env.hct) {
                // The nonce must be the one derived from this header (spec 7.3).
                guard SP.ctEqual(Self.headerNonce(iv: keys.iv, header: h), env.hnonce) else { continue }
                opened.append((hk, h))
            }
        }
        guard opened.count == 1 else { throw SwellProtocolError.crypto("header") }
        let (hk, hbytes) = opened[0]
        let h = try SPWire.Header.decode(hbytes)
        // Counters a peer chose: bounded before any arithmetic, so `n + 1` and the gaps below can never overflow (review N1).
        guard h.n < policy.maxChain, h.pn < policy.maxChain else { throw SwellProtocolError.limit("chain") }

        // Step 3: a stored skipped key first, then the current chain (HKr), then a new DH step (NHKr).
        enum Which { case skipped(Int), current, next }
        let which: Which
        if let i = s.skipped.firstIndex(where: { SP.ctEqual($0.hk, hk) && $0.n == h.n }) { which = .skipped(i) }
        else if s.hkr.count == 32, SP.ctEqual(hk, s.hkr) { which = .current }
        else if SP.ctEqual(hk, s.nhkr) { which = .next }
        else { throw SwellProtocolError.duplicate } // an old header key whose key for this n is gone
        let mkDR: [UInt8]
        switch which {
        case .skipped(let i):
            mkDR = s.skipped[i].mk
            s.skipped.remove(at: i)
        case .current:
            guard SP.ctEqual(h.dhPub, s.dhr) else { throw SwellProtocolError.crypto("dh_pub") }
            if h.n < s.nr { throw SwellProtocolError.duplicate }
            guard h.n - s.nr <= policy.maxSkip else { throw SwellProtocolError.limit("skip") }
            try s.skip(until: h.n, now: now, policy: policy)
            let step = Self.kdfCK(s.ckr)
            s.ckr = step.ck; s.nr = h.n + 1; mkDR = step.mk
        case .next:
            guard !SP.ctEqual(h.dhPub, s.dhr) else { throw SwellProtocolError.crypto("dh_pub") }
            if s.hkr.count == 32 {
                guard h.pn >= s.nr, h.pn - s.nr <= policy.maxSkip else { throw SwellProtocolError.limit("skip") }
                try s.skip(until: h.pn, now: now, policy: policy)
            }
            try s.dhRatchet(h.dhPub)
            guard h.n <= policy.maxSkip else { throw SwellProtocolError.limit("skip") }
            try s.skip(until: h.n, now: now, policy: policy)
            let step = Self.kdfCK(s.ckr)
            s.ckr = step.ck; s.nr = h.n + 1; mkDR = step.mk
        }

        // Step 4: the epoch key named in the header; an epoch no longer (or not yet) held cannot be read.
        guard let epochKey = s.pq.key(h.epoch) else { throw SwellProtocolError.crypto("epoch") }
        var mk = Self.combine(mkDR, pq: epochKey, epoch: h.epoch)
        let padded = try SP.open(key: mk.key, nonce: mk.nonce, ad: Self.bodyAD(transcript: s.transcript, prefix: env.prefix, hnonce: env.hnonce, hct: env.hct), env.body)
        SP.wipe(&mk.key)
        let (field, inner) = try SPWire.unpad(padded)
        try s.pq.received(headerEpoch: h.epoch, field: field, inviter: inviter, now: now, policy: policy, entropy: entropy)
        return (s, inner)
    }

    /// The DH ratchet step of the published section 4.4 (header-encryption variant).
    mutating func dhRatchet(_ dhPub: [UInt8]) throws {
        pn = ns; ns = 0; nr = 0
        hks = nhks; hkr = nhkr
        dhr = dhPub
        let r1 = Self.kdfRK(rk, try SP.dh(dhsSK, dhr))
        rk = r1.rk; ckr = r1.ck; nhkr = r1.nhk
        let fresh = try SP.x25519(entropy)
        dhsSK = fresh.sk; dhsPK = fresh.pk // spec 12: the previous ratchet private key leaves the stored state at this step
        let r2 = Self.kdfRK(rk, try SP.dh(dhsSK, dhr))
        rk = r2.rk; cks = r2.ck; nhks = r2.nhk
    }

    /// Stores skipped keys of the current receiving chain up to (not including) `until` (8.1, 8.3).
    mutating func skip(until: Int32, now: Int64, policy: SPPolicy) throws {
        guard ckr.count == 32 else { return }
        while nr < until {
            let step = Self.kdfCK(ckr)
            skipped.append(SPSkipped(hk: hkr, n: nr, mk: step.mk, at: now))
            ckr = step.ck; nr += 1
        }
        // Full store: the oldest keys go, so the ratchet keeps moving (8.1).
        if skipped.count > policy.maxStoredSkipped { skipped.removeFirst(skipped.count - policy.maxStoredSkipped) }
    }

    /// Skipped keys expire 15 days after they were stored. A clock moved backward only delays this.
    mutating func pruneSkipped(now: Int64, policy: SPPolicy) {
        skipped.removeAll { SP.sat($0.at, policy.skippedLifetimeMillis) < now }
    }

    // MARK: storage (one record per relationship, written in the message's transaction)

    static let recordVersion = 3 // 3: PQ state has `repeatOwed` (review N3)

    public func encode() -> [UInt8] {
        let o = SPOut().u8(Self.recordVersion).u8(inviter ? 1 : 0).raw(transcript).raw(idSelf).raw(idPeer).raw(dhsSK).raw(dhsPK)
            .bytes(dhr).raw(rk).bytes(cks).bytes(ckr).bytes(hks).bytes(hkr).bytes(nhks).bytes(nhkr)
            .i32(ns).i32(nr).i32(pn).i32(Int32(skipped.count))
        for k in skipped { o.raw(k.hk).i32(k.n).raw(k.mk).i64(k.at) }
        pq.encode(o)
        return o.done()
    }

    public static func decode(_ b: [UInt8]) throws -> SPSession {
        let r = SPIn(b)
        guard try r.u8() == recordVersion else { throw SwellProtocolError.format("session version") }
        let inviter = try r.u8() == 1
        let t = try r.raw(32), idS = try r.raw(32), idP = try r.raw(32), sk = try r.raw(32), pk = try r.raw(32)
        func opt() throws -> [UInt8] {
            let v = try r.bytes(max: 32)
            guard v.isEmpty || v.count == 32 else { throw SwellProtocolError.format("session key") }
            return v
        }
        let dhr = try opt(), rk = try r.raw(32), cks = try opt(), ckr = try opt()
        let hks = try opt(), hkr = try opt(), nhks = try opt(), nhkr = try opt()
        let ns = try r.i32(), nr = try r.i32(), pn = try r.i32()
        guard (0...(1 << 24)).contains(ns), (0...(1 << 24)).contains(nr), (0...(1 << 24)).contains(pn) else { throw SwellProtocolError.format("counters") }
        let count = Int(try r.i32())
        guard count >= 0, count <= 100_000 else { throw SwellProtocolError.format("skipped") }
        let skipped = try (0..<count).map { _ in SPSkipped(hk: try r.raw(32), n: try r.i32(), mk: try r.raw(32), at: try r.i64()) }
        let pq = try SPPQState.decode(r)
        try r.end()
        var s = SPSession(inviter: inviter, transcript: t, idSelf: idS, idPeer: idP, dhsSK: sk, dhsPK: pk, rk: rk, pq: pq)
        s.dhr = dhr; s.cks = cks; s.ckr = ckr; s.hks = hks; s.hkr = hkr; s.nhks = nhks; s.nhkr = nhkr
        s.ns = ns; s.nr = nr; s.pn = pn; s.skipped = skipped
        return s
    }

    /// `SHA256Tagged("session", T)`: names this session in SYNC (spec 6.4) without revealing anything secret.
    public var sessionHash: [UInt8] { SP.tagged("session", transcript) }
}
