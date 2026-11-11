package com.jijilabsdigital.swell.protocol

// Swell Protocol draft 2, spec section 7.6: the post-quantum ratchet (an ML-KEM-768 epoch ratchet mixed into message keys).
// Byte-for-byte compatible with the Swift implementation. Designed from the public descriptions in the spec and FIPS 203.

/** Pacing and window parameters (spec 7.6, 8.1). Tests may shorten them; the app uses [STANDARD]. */
data class SPPolicy(
    /** A keygen side starts the next epoch after it has sent this many messages in the current one... */
    val epochMessages: Int,
    /** ...or this long after the current epoch was confirmed, whichever comes first. Epoch 1 starts at once. */
    val epochMillis: Long,
    /** Epoch keys kept for late messages: the current one and this many older ones. */
    val keptOldEpochs: Int,
    val maxSkip: Int,
    val maxStoredSkipped: Int,
    val skippedLifetimeMillis: Long,
    val maxChain: Int,
) {
    companion object {
        val STANDARD = SPPolicy(25, 6L * 3600 * 1000, 3, 1000, 2000, 15L * 86400 * 1000, 1 shl 16)
    }
}

/** The PQ part of one relationship's state. Byte arrays are never changed in place, so [copy] is a safe snapshot. */
class SPPQState private constructor() {
    /** Highest epoch whose key this side knows. */
    var epoch = 0
    /** Epoch used for sending: [epoch], or `epoch - 1` while this side encapsulated and waits for proof the peer has the new key. */
    var sendEpoch = 0
    /** (epoch, key), oldest first; at most `keptOldEpochs + 1` entries. */
    var keys: MutableList<Pair<Int, ByteArray>> = mutableListOf()
    /** Keygen side: the ML-KEM seed (private), its EK and the target epoch, until CT(target) arrives. Target 0 = none. */
    var pendingSeed = ByteArray(0)
    var pendingEK = ByteArray(0)
    var pendingTarget = 0
    var ekSent = false
    /** Encapsulating side: CT(ctTarget) (public), sent until a message under [ctTarget] arrives. Target 0 = none. */
    var pendingCT = ByteArray(0)
    var ctTarget = 0
    var ctSent = false
    /** Messages sent since [sendEpoch] was confirmed, and when that was (local clock, ms). */
    var sentInEpoch = 0
    var confirmedAt = 0L
    /** A new sending chain began while an EK or CT was pending: the next frame that may carry a field repeats it (review N3). */
    var repeatOwed = false

    constructor(pq0: ByteArray, now: Long) : this() {
        keys = mutableListOf(0 to pq0)
        confirmedAt = now
    }

    fun copy(): SPPQState = SPPQState().also {
        it.epoch = epoch; it.sendEpoch = sendEpoch; it.keys = keys.toMutableList()
        it.pendingSeed = pendingSeed; it.pendingEK = pendingEK; it.pendingTarget = pendingTarget; it.ekSent = ekSent
        it.pendingCT = pendingCT; it.ctTarget = ctTarget; it.ctSent = ctSent
        it.sentInEpoch = sentInEpoch; it.confirmedAt = confirmedAt; it.repeatOwed = repeatOwed
    }

    fun key(e: Int): ByteArray? = keys.firstOrNull { it.first == e }?.second

    private fun adopt(t: Int, k: ByteArray, policy: SPPolicy) {
        keys.add(t to k)
        epoch = t
        while (keys.isNotEmpty() && keys[0].first < epoch - policy.keptOldEpochs) keys.removeAt(0) // removed from the stored state (spec 12)
    }

    /**
     * Spec 7.6 "Send": which PQ field this message carries. May start a new epoch (makes an ML-KEM key).
     * [firstOfChain]: the message is number 0 of its sending chain. [carry] says whether this frame may take a field of that many
     * bytes (false for best-effort frames, review F5, and when it would grow a frame above 16 KiB, F14). Nothing changes on "no".
     */
    fun prepareSend(inviter: Boolean, firstOfChain: Boolean, now: Long, policy: SPPolicy, carry: (Int) -> Boolean): SPWire.PQField {
        if (firstOfChain && (ctTarget != 0 || pendingTarget != 0)) repeatOwed = true
        if (ctTarget != 0) {
            if ((!ctSent || repeatOwed) && carry(CT_FIELD_LEN)) { ctSent = true; repeatOwed = false; return SPWire.PQField.Ct(ctTarget, pendingCT) }
            return SPWire.PQField.None
        }
        if (pendingTarget != 0) {
            if ((!ekSent || repeatOwed) && carry(EK_FIELD_LEN)) { ekSent = true; repeatOwed = false; return SPWire.PQField.Ek(pendingTarget, pendingEK) }
            return SPWire.PQField.None
        }
        val t = epoch + 1
        if (!(carry(EK_FIELD_LEN) && isKeygen(t, inviter) && sendEpoch == epoch &&
                (epoch == 0 || sentInEpoch >= policy.epochMessages || !SP.within(confirmedAt, now, policy.epochMillis)))) return SPWire.PQField.None
        val k = SP.kemGenerate()
        pendingSeed = k.seed; pendingEK = k.ek; pendingTarget = t; ekSent = true
        return SPWire.PQField.Ek(t, k.ek)
    }

    /**
     * Spec 7.6 "Receive", after the body opened under the key of [headerEpoch]. Fields that do not fit the state are ignored
     * (the message itself authenticated, so it is still delivered).
     */
    fun received(headerEpoch: Int, field: SPWire.PQField, inviter: Boolean, now: Long, policy: SPPolicy) {
        // Confirmation: the peer sends under the epoch we encapsulated for, so it holds that key.
        if (headerEpoch == epoch && sendEpoch < epoch) {
            sendEpoch = epoch; confirmedAt = now; sentInEpoch = 0
            pendingCT = ByteArray(0); ctTarget = 0; ctSent = false; repeatOwed = false
        }
        when (field) {
            is SPWire.PQField.None -> {}
            is SPWire.PQField.Ek -> {
                val t = field.target
                val prev = key(epoch)
                if (!(t == epoch + 1 && !isKeygen(t, inviter) && sendEpoch == epoch && ctTarget == 0 && prev != null)) return
                // An encapsulation key that fails the FIPS 203 check is ignored like any field that does not fit; the message is delivered (F9).
                val r = try { SP.kemEncapsulate(field.ek) } catch (e: SwellProtocolError) { return }
                adopt(t, nextKey(prev, r.ss, t, field.ek, r.ct), policy)
                pendingCT = r.ct; ctTarget = t; ctSent = false
            }
            is SPWire.PQField.Ct -> {
                val t = field.target
                val prev = key(epoch)
                if (!(t == epoch + 1 && t == pendingTarget && isKeygen(t, inviter) && prev != null)) return
                val ss = SP.kemDecapsulate(pendingSeed, field.ct)
                adopt(t, nextKey(prev, ss, t, pendingEK, field.ct), policy)
                pendingSeed = ByteArray(0); pendingEK = ByteArray(0); pendingTarget = 0; ekSent = false; repeatOwed = false // the seed leaves the stored state (spec 12)
                sendEpoch = t; confirmedAt = now; sentInEpoch = 0
            }
        }
    }

    // ---- storage -----------------------------------------------------------------------------------------------------------

    fun encode(o: SPOut) {
        o.i32(epoch).i32(sendEpoch).i32(keys.size)
        for ((e, k) in keys) o.i32(e).raw(k)
        o.bytes(pendingSeed).bytes(pendingEK).i32(pendingTarget).u8(if (ekSent) 1 else 0)
        o.bytes(pendingCT).i32(ctTarget).u8(if (ctSent) 1 else 0).i32(sentInEpoch).i64(confirmedAt).u8(if (repeatOwed) 1 else 0)
    }

    companion object {
        /** Encoded sizes of the two PQ fields (kind, target, key or ciphertext). */
        const val EK_FIELD_LEN = 1 + 4 + SP.KEM_EK_LEN
        const val CT_FIELD_LEN = 1 + 4 + SP.KEM_CT_LEN

        /** Keygen side for epoch t: I (inviter) for odd t, J for even t. */
        fun isKeygen(t: Int, inviter: Boolean): Boolean = (t % 2 == 1) == inviter

        /** `PQ_t = HKDF(salt = PQ_{t-1}, ikm = ss, info = Info("pq-epoch", i32 t, SHA256Tagged("pq-kem", ek | ct)), 32)`. */
        fun nextKey(prev: ByteArray, ss: ByteArray, target: Int, ek: ByteArray, ct: ByteArray): ByteArray =
            SP.hkdf(prev, ss, SP.info("pq-epoch", SP.be32(target), SP.tagged("pq-kem", ek + ct)), 32)

        fun decode(r: SPIn): SPPQState {
            val s = SPPQState()
            s.epoch = r.i32(); s.sendEpoch = r.i32()
            val n = r.i32()
            if (n < 1 || n > 64) throw SwellProtocolError.Format("pq keys")
            s.keys = MutableList(n) { r.i32() to r.raw(32) }
            s.pendingSeed = r.bytes(SP.KEM_SEED_LEN); s.pendingEK = r.bytes(SP.KEM_EK_LEN)
            s.pendingTarget = r.i32(); s.ekSent = r.u8() == 1
            s.pendingCT = r.bytes(SP.KEM_CT_LEN); s.ctTarget = r.i32(); s.ctSent = r.u8() == 1
            s.sentInEpoch = r.i32(); s.confirmedAt = r.i64(); s.repeatOwed = r.u8() == 1
            // Bounds first, so the arithmetic can never overflow on a damaged record (review N1).
            if (s.epoch < 0 || s.epoch >= 1 shl 30 || s.sendEpoch < 0 || s.sentInEpoch < 0 || s.pendingTarget < 0 || s.ctTarget < 0)
                throw SwellProtocolError.Format("pq state")
            if (s.sendEpoch > s.epoch || s.sendEpoch < s.epoch - 1 || s.key(s.epoch) == null || s.key(s.sendEpoch) == null ||
                (s.pendingTarget != 0 && !(s.pendingSeed.size == SP.KEM_SEED_LEN && s.pendingEK.size == SP.KEM_EK_LEN)) ||
                (s.ctTarget != 0 && s.pendingCT.size != SP.KEM_CT_LEN)) throw SwellProtocolError.Format("pq state")
            return s
        }
    }
}
