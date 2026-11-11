// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

// Swell Protocol draft 3 (ratchet unchanged from draft 2), spec sections 7 (ratchet) and 8 (send and receive).
//
// The Double Ratchet with header encryption as published (revision 4, public domain), with the Swell differences of spec
// section 7. All operations work on a copy and return it; the caller stores the result only on success (8.3 step 4), in the
// same database transaction as the message (8.2, 8.3 step 5).

/** One stored skipped message key (spec 8.1): its header key, number, chain-step key and when it was stored. */
class SPSkipped(val hk: ByteArray, val n: Int, val mk: ByteArray, val at: Long)

/** Result of [SPSession.encrypt]: the new state and the exact envelope bytes. */
class SPSent(val session: SPSession, val envelope: ByteArray)

/** Result of [SPSession.decrypt]: the new state and the inner message. */
class SPReceived(val session: SPSession, val inner: ByteArray)

/**
 * The full state of one Swell Protocol session (spec 7.1 fields plus 7.6 PQ state). Never logged.
 * Empty arrays mean None (as in the published text). Arrays are replaced, never changed in place.
 */
class SPSession(
    /** True for I (inviter, "Bob" role), false for J (joiner, "Alice" role). */
    val inviter: Boolean,
    /** Transcript hash T (6.1), bound into every AD. */
    val transcript: ByteArray,
    /** The two public identity keys kept for the safety number (11). */
    val idSelf: ByteArray,
    val idPeer: ByteArray,
    var dhsSK: ByteArray,
    var dhsPK: ByteArray,
    var rk: ByteArray,
    var pq: SPPQState,
) {
    var dhr = ByteArray(0)
    var cks = ByteArray(0)
    var ckr = ByteArray(0)
    var hks = ByteArray(0)
    var hkr = ByteArray(0)
    var nhks = ByteArray(0)
    var nhkr = ByteArray(0)
    var ns = 0
    var nr = 0
    var pn = 0
    var skipped: MutableList<SPSkipped> = mutableListOf()

    fun copy(): SPSession = SPSession(inviter, transcript, idSelf, idPeer, dhsSK, dhsPK, rk, pq.copy()).also {
        it.dhr = dhr; it.cks = cks; it.ckr = ckr; it.hks = hks; it.hkr = hkr; it.nhks = nhks; it.nhkr = nhkr
        it.ns = ns; it.nr = nr; it.pn = pn; it.skipped = skipped.toMutableList()
    }

    // ---- 8.2 send ----------------------------------------------------------------------------------------------------------

    /**
     * Encrypts one inner message. The caller commits the returned state and bytes in one transaction and retries the same bytes,
     * never re-encrypting. [helloKeys] non-empty makes a HELLO (J's message 0). [allowPQ] is false for best-effort frames
     * (review F5).
     */
    fun encrypt(inner: ByteArray, now: Long, policy: SPPolicy = SPPolicy.STANDARD, helloKeys: ByteArray = ByteArray(0),
                allowPQ: Boolean = true): SPSent {
        val s = copy()
        if (s.cks.size != 32 || s.hks.size != 32) throw SwellProtocolError.NoSession()
        if (s.ns >= policy.maxChain) throw SwellProtocolError.Limit("chain")
        s.pruneSkipped(now, policy)
        val plain = SPWire.bucket(4 + 1 + inner.size)
        val field = s.pq.prepareSend(inviter, s.ns == 0, now, policy) { len ->
            val with = SPWire.bucket(4 + len + inner.size)
            if (!allowPQ || plain == null || with == null) false else with == plain || plain <= SPWire.PQ_BUCKET_CAP
        }
        val epochKey = s.pq.key(s.pq.sendEpoch) ?: throw SwellProtocolError.NoSession()
        val step = kdfCK(s.cks)
        val mk = combine(step.mk, epochKey, s.pq.sendEpoch)
        val header = SPWire.Header(s.dhsPK, s.pn, s.ns, s.pq.sendEpoch).encode()
        val kind = if (helloKeys.isEmpty()) SPWire.KIND_DATA else SPWire.KIND_HELLO
        val prefix = byteArrayOf(SPWire.VER.toByte(), kind.toByte()) + helloKeys
        val hk = headerKeys(s.hks)
        val hnonce = headerNonce(hk.iv, header)
        val hct = SP.seal(hk.enc, hnonce, headerAD(prefix, s.transcript), header)
        val body = SP.seal(mk.key, mk.nonce, bodyAD(s.transcript, prefix, hnonce, hct), SPWire.pad(field, inner))
        SP.wipe(mk.key)
        s.cks = step.ck // the old chain key leaves the stored state with this step
        s.ns += 1
        if (s.pq.sentInEpoch < Int.MAX_VALUE) s.pq.sentInEpoch += 1
        return SPSent(s, prefix + hnonce + hct + body)
    }

    // ---- 8.3 receive -------------------------------------------------------------------------------------------------------

    /**
     * Opens one envelope on a copy of the state. Throws without any state change on every failure (8.4).
     * [allowHello] is set only by the inviter's handshake (6.2); everywhere else a HELLO is dropped.
     */
    fun decrypt(bytes: ByteArray, now: Long, policy: SPPolicy = SPPolicy.STANDARD, allowHello: Boolean = false): SPReceived {
        val s = copy()
        val env = SPWire.Envelope.decode(bytes)
        if (!(env.kind == SPWire.KIND_DATA || (allowHello && env.kind == SPWire.KIND_HELLO))) throw SwellProtocolError.Format("kind")
        s.pruneSkipped(now, policy)
        val hAD = headerAD(env.prefix, s.transcript)

        // Step 2: every distinct candidate header key (those of stored skipped keys, HKr, NHKr); exactly one must open the header.
        val candidates = mutableListOf<ByteArray>()
        for (k in s.skipped.map { it.hk } + listOf(s.hkr, s.nhkr)) {
            if (k.size == 32 && candidates.none { SP.ctEqual(it, k) }) candidates.add(k)
        }
        val opened = mutableListOf<Pair<ByteArray, ByteArray>>()
        for (hk in candidates) {
            val keys = headerKeys(hk)
            val h = try { SP.open(keys.enc, env.hnonce, hAD, env.hct) } catch (e: SwellProtocolError) { continue }
            // The nonce must be the one derived from this header (spec 7.3).
            if (!SP.ctEqual(headerNonce(keys.iv, h), env.hnonce)) continue
            opened.add(hk to h)
        }
        if (opened.size != 1) throw SwellProtocolError.Crypto("header")
        val (hk, hbytes) = opened[0]
        val h = SPWire.Header.decode(hbytes)
        // Counters a peer chose: bounded before any arithmetic, so `n + 1` and the gaps below can never overflow (review N1).
        if (h.n >= policy.maxChain || h.pn >= policy.maxChain) throw SwellProtocolError.Limit("chain")

        // Step 3: a stored skipped key first, then the current chain (HKr), then a new DH step (NHKr).
        val mkDR: ByteArray
        val skippedIndex = s.skipped.indexOfFirst { SP.ctEqual(it.hk, hk) && it.n == h.n }
        if (skippedIndex >= 0) {
            mkDR = s.skipped[skippedIndex].mk
            s.skipped.removeAt(skippedIndex)
        } else if (s.hkr.size == 32 && SP.ctEqual(hk, s.hkr)) {
            if (!SP.ctEqual(h.dhPub, s.dhr)) throw SwellProtocolError.Crypto("dh_pub")
            if (h.n < s.nr) throw SwellProtocolError.Duplicate()
            if (h.n - s.nr > policy.maxSkip) throw SwellProtocolError.Limit("skip")
            s.skip(h.n, now, policy)
            val step = kdfCK(s.ckr)
            s.ckr = step.ck; s.nr = h.n + 1; mkDR = step.mk
        } else if (SP.ctEqual(hk, s.nhkr)) {
            if (SP.ctEqual(h.dhPub, s.dhr)) throw SwellProtocolError.Crypto("dh_pub")
            if (s.hkr.size == 32) {
                if (h.pn < s.nr || h.pn - s.nr > policy.maxSkip) throw SwellProtocolError.Limit("skip")
                s.skip(h.pn, now, policy)
            }
            s.dhRatchet(h.dhPub)
            if (h.n > policy.maxSkip) throw SwellProtocolError.Limit("skip")
            s.skip(h.n, now, policy)
            val step = kdfCK(s.ckr)
            s.ckr = step.ck; s.nr = h.n + 1; mkDR = step.mk
        } else {
            throw SwellProtocolError.Duplicate() // an old header key whose key for this n is gone
        }

        // Step 4: the epoch key named in the header; an epoch no longer (or not yet) held cannot be read.
        val epochKey = s.pq.key(h.epoch) ?: throw SwellProtocolError.Crypto("epoch")
        val mk = combine(mkDR, epochKey, h.epoch)
        val padded = SP.open(mk.key, mk.nonce, bodyAD(s.transcript, env.prefix, env.hnonce, env.hct), env.body)
        SP.wipe(mk.key)
        val u = SPWire.unpad(padded)
        s.pq.received(h.epoch, u.pq, inviter, now, policy)
        return SPReceived(s, u.inner)
    }

    /** The DH ratchet step of the published section 4.4 (header-encryption variant). */
    private fun dhRatchet(dhPub: ByteArray) {
        pn = ns; ns = 0; nr = 0
        hks = nhks; hkr = nhkr
        dhr = dhPub
        val r1 = kdfRK(rk, SP.dh(dhsSK, dhr))
        rk = r1.rk; ckr = r1.ck; nhkr = r1.nhk
        val fresh = SP.x25519()
        dhsSK = fresh.sk; dhsPK = fresh.pk // spec 12: the previous ratchet private key leaves the stored state at this step
        val r2 = kdfRK(rk, SP.dh(dhsSK, dhr))
        rk = r2.rk; cks = r2.ck; nhks = r2.nhk
    }

    /** Stores skipped keys of the current receiving chain up to (not including) [until] (8.1, 8.3). */
    private fun skip(until: Int, now: Long, policy: SPPolicy) {
        if (ckr.size != 32) return
        while (nr < until) {
            val step = kdfCK(ckr)
            skipped.add(SPSkipped(hkr, nr, step.mk, now))
            ckr = step.ck; nr += 1
        }
        // Full store: the oldest keys go, so the ratchet keeps moving (8.1).
        while (skipped.size > policy.maxStoredSkipped) skipped.removeAt(0)
    }

    /** Skipped keys expire 15 days after they were stored. A clock moved backward only delays this. */
    private fun pruneSkipped(now: Long, policy: SPPolicy) {
        skipped.removeAll { SP.sat(it.at, policy.skippedLifetimeMillis) < now }
    }

    /**
     * A copy in which a PQ field already handed to a frame that never left (the send failed before any answer) is owed again, so the
     * next frame that may carry one repeats it. Repeating is harmless: a receiver ignores a field that does not fit its state (7.6).
     */
    fun withPQRepeatOwed(): SPSession = copy().also { if (it.pq.ctTarget != 0 || it.pq.pendingTarget != 0) it.pq.repeatOwed = true }

    /** The serialized (33-byte) identity key of the other person. */
    val peerIdentity: ByteArray get() = byteArrayOf(SPIdentity.TYPE_BYTE) + idPeer

    // ---- storage (one record per relationship, written in the message's transaction) ---------------------------------------

    fun encode(): ByteArray {
        val o = SPOut().u8(RECORD_VERSION).u8(if (inviter) 1 else 0).raw(transcript).raw(idSelf).raw(idPeer).raw(dhsSK).raw(dhsPK)
            .bytes(dhr).raw(rk).bytes(cks).bytes(ckr).bytes(hks).bytes(hkr).bytes(nhks).bytes(nhkr)
            .i32(ns).i32(nr).i32(pn).i32(skipped.size)
        for (k in skipped) o.raw(k.hk).i32(k.n).raw(k.mk).i64(k.at)
        pq.encode(o)
        return o.done()
    }

    /** `SHA256Tagged("session", T)`: names this session in SYNC (spec 6.4) without revealing anything secret. */
    val sessionHash: ByteArray get() = SP.tagged("session", transcript)

    /** Safety number of this relationship (spec 11): 12 groups of 5 digits, from the two serialized identity keys. */
    val safetyNumber: String get() = SPHandshake.safetyNumber(byteArrayOf(SPIdentity.TYPE_BYTE) + idSelf, peerIdentity)

    companion object {
        /** 3: PQ state has `repeatOwed` (review N3). Must equal the Swift record version. */
        const val RECORD_VERSION = 3

        class Step(val ck: ByteArray, val mk: ByteArray)
        class RootStep(val rk: ByteArray, val ck: ByteArray, val nhk: ByteArray)
        class Combined(val key: ByteArray, val nonce: ByteArray)
        class HeaderKeys(val enc: ByteArray, val iv: ByteArray)

        /** `KDF_RK(RK, dh) = HKDF(salt = RK, ikm = dh, info = Info("root"), 96) -> RK' | CK | NHK`. */
        fun kdfRK(rk: ByteArray, dh: ByteArray): RootStep {
            val o = SP.hkdf(rk, dh, SP.info("root"), 96)
            return RootStep(o.copyOfRange(0, 32), o.copyOfRange(32, 64), o.copyOfRange(64, 96)).also { SP.wipe(o) }
        }

        /** `KDF_CK(CK)`: `CK' = Expand(CK, Info("chain"), 32)`, chain-step key `mk_dr = Expand(CK, Info("message"), 32)`. */
        fun kdfCK(ck: ByteArray): Step = Step(SP.expand(ck, SP.info("chain"), 32), SP.expand(ck, SP.info("message"), 32))

        /** Spec 7.2 / 7.6: `mk | body_nonce = HKDF(salt = PQ_epoch, ikm = mk_dr, info = Info("pq-message", i32 epoch), 44)`. */
        fun combine(mkDR: ByteArray, pq: ByteArray, epoch: Int): Combined {
            val o = SP.hkdf(pq, mkDR, SP.info("pq-message", SP.be32(epoch)), 44)
            return Combined(o.copyOfRange(0, 32), o.copyOfRange(32, 44)).also { SP.wipe(o) }
        }

        /** `hk_enc = Expand(hk, Info("header-enc"), 32)`, `hk_iv = Expand(hk, Info("header-iv"), 32)`. */
        fun headerKeys(hk: ByteArray): HeaderKeys = HeaderKeys(SP.expand(hk, SP.info("header-enc"), 32), SP.expand(hk, SP.info("header-iv"), 32))

        /** `hnonce = Expand(hk_iv, Info("header-nonce", header), 12)`. */
        fun headerNonce(iv: ByteArray, header: ByteArray): ByteArray = SP.expand(iv, SP.info("header-nonce", header), 12)

        fun headerAD(prefix: ByteArray, transcript: ByteArray): ByteArray = "SWL2-H".toByteArray(Charsets.US_ASCII) + prefix + transcript
        fun bodyAD(transcript: ByteArray, prefix: ByteArray, hnonce: ByteArray, hct: ByteArray): ByteArray =
            "SWL2-M".toByteArray(Charsets.US_ASCII) + transcript + prefix + hnonce + hct

        fun decode(b: ByteArray): SPSession {
            val r = SPIn(b)
            if (r.u8() != RECORD_VERSION) throw SwellProtocolError.Format("session version")
            val inviter = r.u8() == 1
            val t = r.raw(32); val idS = r.raw(32); val idP = r.raw(32); val sk = r.raw(32); val pk = r.raw(32)
            fun opt(): ByteArray {
                val v = r.bytes(32)
                if (!(v.isEmpty() || v.size == 32)) throw SwellProtocolError.Format("session key")
                return v
            }
            val dhr = opt(); val rk = r.raw(32); val cks = opt(); val ckr = opt()
            val hks = opt(); val hkr = opt(); val nhks = opt(); val nhkr = opt()
            val ns = r.i32(); val nr = r.i32(); val pn = r.i32()
            val limit = 1 shl 24
            if (ns !in 0..limit || nr !in 0..limit || pn !in 0..limit) throw SwellProtocolError.Format("counters")
            val count = r.i32()
            if (count < 0 || count > 100_000) throw SwellProtocolError.Format("skipped")
            val skipped = MutableList(count) { SPSkipped(r.raw(32), r.i32(), r.raw(32), r.i64()) }
            val pq = SPPQState.decode(r)
            r.end()
            return SPSession(inviter, t, idS, idP, sk, pk, rk, pq).also {
                it.dhr = dhr; it.cks = cks; it.ckr = ckr; it.hks = hks; it.hkr = hkr; it.nhks = nhks; it.nhkr = nhkr
                it.ns = ns; it.nr = nr; it.pn = pn; it.skipped = skipped
            }
        }
    }
}
