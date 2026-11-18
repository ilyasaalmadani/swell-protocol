// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPPolicy
import com.jijilabsdigital.swell.protocol.SPSession
import com.jijilabsdigital.swell.protocol.SPWire
import com.jijilabsdigital.swell.protocol.SwellProtocolError

/**
 * The Double Ratchet with header encryption and the PQ epoch ratchet (spec 7, 8), driven as a conversation between I and J.
 * The input is a program: send (any size, PQ allowed or not), deliver any queued envelope (in or out of order, again, or with one
 * bit changed), let the clock jump forward or back, store and reload a state, mark a PQ field as owed again, or forge a frame as a
 * malicious peer that holds the session keys (any header counters, epoch, DH key, PQ field and padding, under real header keys).
 *
 * Invariants:
 *  - every refusal is a SwellProtocolError, and a send is refused only for a limit;
 *  - an envelope with a changed bit never opens; an envelope never opens twice; an opened envelope gives exactly what was sent;
 *  - liveness: the oldest undelivered envelope of a sender, all earlier ones delivered and none later, opens (unless the receiver
 *    accepted a forged frame, which legitimately changes its state);
 *  - a stored state reloads to the same bytes.
 */
object RatchetFuzzer {
    /** Small limits, so epochs turn, chains end and skip limits bite within a short input. */
    private val SMALL = SPPolicy(epochMessages = 2, epochMillis = 60_000, keptOldEpochs = 1, maxSkip = 8, maxStoredSkipped = 6,
        skippedLifetimeMillis = 3_600_000, maxChain = 40)

    private class Sent(val from: Int, val index: Int, val inner: ByteArray, val bytes: ByteArray) { var delivered = false }

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val f = FuzzIn(data)
        val policy = if (f.bool()) SMALL else SPPolicy.STANDARD
        val queue = ArrayList<Sent>()
        val next = IntArray(2)
        val sessions: Array<SPSession>
        var now: Long
        if (f.bool()) {
            val ex = Fixtures.exchange
            sessions = arrayOf(ex.iState, ex.jState)
            // The last two I -> J envelopes of the exchange are unread.
            for (k in 0 until 2) queue += Sent(0, k, "unread $k".toByteArray(), ex.toJ[ex.toJ.size - 2 + k])
            next[0] = 2
            now = Fixtures.BUNDLE_NOW + 40_000
        } else {
            val (i, j) = Fixtures.start
            sessions = arrayOf(i, j)
            now = Fixtures.BUNDLE_NOW + 1000
        }
        /** Per sender: how many of its envelopes were delivered in order from the first, and whether a later one went first. */
        val prefix = IntArray(2)
        val skippedAhead = BooleanArray(2)
        val tainted = BooleanArray(2)

        SP.withEntropy(DetEntropy.of("ratchet", f.bytes(8))) {
            var ops = 0
            while (f.left > 0 && ops++ < 48) {
                when (f.u8() % 8) {
                    0, 1 -> {
                        val side = f.u8() and 1
                        val inner = if (f.u8() < 16) ByteArray(f.u16() * 5) { 0x5A } else f.chunk(2000) // up to 327 KB: every bucket and too large
                        val allowPQ = f.bool()
                        val r = try {
                            sessions[side].encrypt(inner, now, policy, allowPQ = allowPQ)
                        } catch (e: SwellProtocolError) {
                            invariant(e is SwellProtocolError.Limit) { "send refused with ${e.message}" }
                            null
                        }
                        if (r != null) {
                            sessions[side] = r.session
                            queue += Sent(side, next[side]++, inner, r.envelope)
                        }
                    }
                    2, 3 -> {
                        if (queue.isEmpty()) continue
                        val m = queue[f.u8() % queue.size]
                        val to = 1 - m.from
                        val tamper = f.u8() < 40
                        val pos = f.u16(); val bit = f.u8() % 8
                        val bytes = if (tamper) m.bytes.copyOf().also { it[pos % it.size] = (it[pos % it.size].toInt() xor (1 shl bit)).toByte() } else m.bytes
                        val r = refusedOrValue { sessions[to].decrypt(bytes, now, policy) }
                        if (tamper) {
                            invariant(r == null) { "an envelope with byte ${pos % bytes.size} changed opened" }
                            continue
                        }
                        val mustOpen = !tainted[to] && !m.delivered && m.index == prefix[m.from] && !skippedAhead[m.from]
                        if (r == null) {
                            invariant(!mustOpen) { "in-order envelope ${m.index} from ${"IJ"[m.from]} did not open" }
                            continue
                        }
                        invariant(!m.delivered || tainted[to]) { "envelope ${m.index} from ${"IJ"[m.from]} opened twice" }
                        invariant(r.inner.contentEquals(m.inner)) { "opened envelope gives another message" }
                        if (!m.delivered) {
                            m.delivered = true
                            if (m.index == prefix[m.from]) {
                                prefix[m.from]++
                                while (queue.any { it.from == m.from && it.index == prefix[m.from] && it.delivered }) prefix[m.from]++
                            } else skippedAhead[m.from] = true
                        }
                        sessions[to] = r.session
                    }
                    4 -> {
                        val from = f.u8() and 1
                        val to = 1 - from
                        val forged = forge(sessions[from], f)
                        val r = refusedOrValue { sessions[to].decrypt(forged.first, now, policy) }
                        if (r != null) {
                            val expected = refusedOrValue { SPWire.unpad(forged.second).inner }
                            invariant(expected != null && r.inner.contentEquals(expected)) { "forged frame opened to another message" }
                            sessions[to] = r.session
                            tainted[to] = true
                        }
                    }
                    5 -> now = SP.sat(now, f.u16().toShort() * 200L) // about +-1.8 hours
                    6 -> {
                        val side = f.u8() and 1
                        val e1 = sessions[side].encode()
                        val d = SPSession.decode(e1)
                        invariant(d.encode().contentEquals(e1)) { "stored state does not reload to the same bytes" }
                        sessions[side] = d
                    }
                    else -> { val side = f.u8() and 1; sessions[side] = sessions[side].withPQRepeatOwed() }
                }
            }
        }
    }

    /**
     * A DATA envelope made by a peer that holds [s] (the sender's state) but does not follow the rules: fuzzer-chosen header fields,
     * PQ field and padding, sealed under the sender's real header key and, where it can, the real message key. Returns the envelope
     * and the padded plaintext.
     */
    private fun forge(s: SPSession, f: FuzzIn): Pair<ByteArray, ByteArray> {
        val useNext = f.u8() < 32
        val hkey = if (useNext) s.nhks else s.hks
        val skip = f.u16() % 1300
        val rawN = f.u8() == 0xFF
        val n = if (rawN) f.i32() else s.ns + skip
        val pn = if (f.bool()) s.pn else if (f.bool()) s.pn + (f.u8() % 16) - 4 else f.i32()
        val epoch = when (f.u8() % 5) {
            0, 1 -> s.pq.sendEpoch
            2 -> s.pq.epoch
            3 -> s.pq.sendEpoch - 1
            else -> f.i32()
        }
        val dhPub = when (f.u8() % 8) {
            0 -> f.bytes(32)
            1 -> SP.x25519().pk
            else -> s.dhsPK
        }
        val mkDR = if (!useNext && !rawN && s.cks.size == 32) {
            var ck = s.cks
            repeat(skip) { ck = SPSession.kdfCK(ck).ck }
            SPSession.kdfCK(ck).mk
        } else f.bytes(32)
        val epochKey = s.pq.key(epoch) ?: f.bytes(32)
        val padded = when (f.u8() % 3) {
            0, 1 -> {
                val target = if (f.bool()) s.pq.epoch + (f.u8() % 4) - 1 else f.i32()
                val field = when (f.u8() % 4) {
                    0 -> SPWire.PQField.None
                    1 -> SPWire.PQField.Ek(target, when (f.u8() % 3) {
                        0 -> if (s.pq.pendingEK.size == SP.KEM_EK_LEN) s.pq.pendingEK else SP.kemGenerate().ek
                        1 -> SP.kemGenerate().ek
                        else -> f.bytes(SP.KEM_EK_LEN)
                    })
                    2 -> SPWire.PQField.Ct(target, if (s.pq.pendingCT.size == SP.KEM_CT_LEN && f.bool()) s.pq.pendingCT else f.bytes(SP.KEM_CT_LEN))
                    else -> SPWire.PQField.None
                }
                // PQField.encode() writes any target, so negative and zero targets reach the receiver's check.
                val content = field.encode() + f.chunk(1500)
                SPWire.bucket(4 + content.size)?.let { SP.be32(content.size) + content + ByteArray(it - 4 - content.size) } ?: SPWire.padRaw(byteArrayOf(0))
            }
            else -> {
                val size = SPWire.BUCKETS[f.u8() % 3]
                val content = f.chunk(size)
                val len = if (f.u8() < 16) f.i32() else content.size
                val p = SP.be32(len) + content + ByteArray(size - 4 - content.size)
                if (f.u8() < 16) p[p.size - 1 - (f.u8() % 8)] = 1
                p
            }
        }
        val header = SPWire.Header(dhPub, pn, n, epoch).encode()
        val prefix = byteArrayOf(SPWire.VER.toByte(), SPWire.KIND_DATA.toByte())
        if (hkey.size != 32) return (prefix + ByteArray(12 + SPWire.HCT_LEN + 1024 + 16)) to padded
        val hk = SPSession.headerKeys(hkey)
        val hnonce = SPSession.headerNonce(hk.iv, header)
        val hct = SP.seal(hk.enc, hnonce, SPSession.headerAD(prefix, s.transcript), header)
        val mk = SPSession.combine(mkDR, epochKey, epoch)
        val body = SP.seal(mk.key, mk.nonce, SPSession.bodyAD(s.transcript, prefix, hnonce, hct), padded)
        return (prefix + hnonce + hct + body) to padded
    }
}
