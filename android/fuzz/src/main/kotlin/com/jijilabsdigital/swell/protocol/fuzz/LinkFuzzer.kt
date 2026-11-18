// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPIdentity
import com.jijilabsdigital.swell.protocol.SPInvite
import com.jijilabsdigital.swell.protocol.SPLink
import com.jijilabsdigital.swell.protocol.SPReport
import com.jijilabsdigital.swell.protocol.SPWire

/**
 * The sealed formats a contact or a stranger can send: link frames (spec 6.4), the report seal (19) and the version 5 sealed bundle (5.4).
 *  - mode 0: a hostile link ciphertext to J from I (keys of link.json).
 *  - mode 1: a link frame sealed with the real link key around a fuzzer-chosen plaintext, so the time window, padding and frame
 *    decoders are reached after the AEAD. An accepted frame must re-seal to exactly the same ciphertext (canonical plaintext).
 *  - mode 2: a link ciphertext opened with a fuzzer-chosen "their identity" (33 bytes): the key derivation must refuse bad keys.
 *  - mode 3: a hostile report envelope for the report inbox; mode 4: one sealed with the real key around a fuzzer-chosen plaintext.
 *  - mode 5: a hostile sealed bundle for a version 5 invite.
 */
object LinkFuzzer {
    private val now = Fixtures.LINK_SENT_AT + 5000
    /** The report inbox of report.json and the version 5 invite of invite.json, so their recorded envelopes open. */
    private val inboxSecret = rep(0x61, 32)
    private val inboxPublic by lazy { SP.x25519Public(inboxSecret) }
    private val mailbox by lazy {
        SPInvite.Mailbox("swellmbxabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop", rep(0x51, 32), rep(0x52, 32),
            SPIdentity.derive(rep(0x41, 16)).serialized)
    }

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val f = FuzzIn(data)
        val idI = Fixtures.idI; val idJ = Fixtures.idJ
        when (f.u8() % 6) {
            0 -> refusedOrValue { SPLink.open(f.rest(), idJ, idI.serialized, Fixtures.channel, now) }
            1 -> {
                val nonce = f.bytes(12)
                val atNow = SP.sat(now, f.i32().toLong() * 1000)
                val padded = when (f.u8() % 3) {
                    0 -> SPWire.padRaw(SP.be64(f.i64()) + f.chunk(3000))
                    1 -> SPWire.padRaw(SP.be64(Fixtures.LINK_SENT_AT) + f.chunk(3000))
                    else -> f.rest().let { if (it.isEmpty()) ByteArray(1024) else it }
                }
                val lk = SPLink.key(idI, idJ.serialized, Fixtures.channel)
                val ad = "SWL3-L".toByteArray(Charsets.US_ASCII) + byteArrayOf(SPLink.VERSION.toByte()) + Fixtures.channel + idI.serialized + idJ.serialized
                val ct = byteArrayOf(SPLink.VERSION.toByte()) + nonce + SP.seal(lk, nonce, ad, padded)
                val o = refusedOrValue { SPLink.open(ct, idJ, idI.serialized, Fixtures.channel, atNow) } ?: return
                val again = SPLink.seal(o.frame, o.sentAtMs, idI, idJ.serialized, Fixtures.channel, nonce)
                invariant(again.size <= ct.size) { "re-sealed link frame is larger" }
                if (again.size == ct.size) invariant(again.contentEquals(ct)) { "accepted a link plaintext that is not canonical" }
                invariant(SP.within(o.sentAtMs, atNow, SPLink.MAX_AGE_MILLIS) || (o.sentAtMs > atNow && o.sentAtMs <= SP.sat(atNow, SPLink.MAX_AHEAD_MILLIS))) {
                    "link frame outside its time window"
                }
            }
            2 -> {
                val theirs = f.bytes(33)
                refusedOrValue { SPLink.open(f.rest(), idJ, theirs, Fixtures.channel, now) }
                refusedOrValue { SPLink.key(idJ, theirs, Fixtures.channel) }
            }
            3 -> refusedOrValue { SPReport.open(inboxSecret, f.rest()) }
            4 -> {
                val eph = f.bytes(32); val nonce = f.bytes(12)
                val plain = f.rest()
                val env = refusedOrValue { SPReport.seal(inboxPublic, plain, eph, nonce) } ?: return
                val opened = SPReport.open(inboxSecret, env)
                invariant(opened.contentEquals(plain)) { "report seal does not open to its plaintext" }
                val bad = env.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
                invariant(refusedOrValue { SPReport.open(inboxSecret, bad) } == null) { "changed report envelope opened" }
            }
            else -> refusedOrValue { mailbox.open(SPInvite.sealedBundle(f.rest())) }
        }
    }
}
