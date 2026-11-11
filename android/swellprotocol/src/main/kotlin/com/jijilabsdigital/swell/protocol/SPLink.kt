// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

// Swell Protocol draft 3, spec section 6.4 (link frames).
//
// Two contacts hold each other's identity keys. A link frame is sealed with a key only those two keys can make (static-static X25519),
// so it starts or repairs a session without any other channel: after the update that removed libsignal, after a restore, after a lost state.
// It carries OFFER, HELLO, RESET and SYNC (SPUpgradeFrame); READY travels inside the new session.
//
//   LK         = HKDF(salt = channelId, ikm = DH(my identity secret, their identity public), info = Info("link", lo, hi), L = 32)
//   ciphertext = u8 3 | raw12 nonce | AEAD(LK, nonce, ad = "SWL3-L" | u8 3 | channelId | sender33 | receiver33, padded)
//   padded     = SPWire.padRaw(i64 sentAtMs | frame)

object SPLink {
    const val VERSION = 3
    /** A frame whose `sentAtMs` is more than this before now is ignored. */
    const val MAX_AGE_MILLIS = 15L * 86_400_000
    /** ...or more than this after now (clock skew). */
    const val MAX_AHEAD_MILLIS = 3_600_000L

    /** The link key between [identity] and the serialized identity key [theirs] on [channelId]. */
    fun key(identity: SPIdentity, theirs: ByteArray, channelId: ByteArray): ByteArray {
        if (channelId.size != 16) throw SwellProtocolError.Format("channel")
        val peer = SPIdentity.publicKey(theirs)
        val shared = SP.dh(identity.secret, peer)
        val mine = identity.serialized
        val (lo, hi) = if (SP.lexLess(mine, theirs)) mine to theirs else theirs to mine
        return SP.hkdf(channelId, shared, SP.info("link", lo, hi), 32).also { SP.wipe(shared) }
    }

    private fun ad(channelId: ByteArray, sender: ByteArray, receiver: ByteArray): ByteArray =
        "SWL3-L".toByteArray(Charsets.US_ASCII) + byteArrayOf(VERSION.toByte()) + channelId + sender + receiver

    /** Seals [frame] from [identity] to [theirs]. [nonce] is 12 random bytes (fixed only by tests). */
    fun seal(frame: SPUpgradeFrame, sentAtMs: Long, identity: SPIdentity, theirs: ByteArray, channelId: ByteArray,
             nonce: ByteArray = SP.random(12)): ByteArray {
        if (nonce.size != 12) throw SwellProtocolError.Format("nonce")
        val lk = key(identity, theirs, channelId)
        val padded = SPWire.padRaw(SP.be64(sentAtMs) + frame.encode())
        return byteArrayOf(VERSION.toByte()) + nonce + SP.seal(lk, nonce, ad(channelId, identity.serialized, theirs), padded)
    }

    class Opened(val sentAtMs: Long, val frame: SPUpgradeFrame)

    /** Opens a frame that [theirs] sent to [identity]. Throws when it does not open, is malformed, or is too old or too new. */
    fun open(ciphertext: ByteArray, identity: SPIdentity, theirs: ByteArray, channelId: ByteArray, now: Long): Opened {
        if (ciphertext.size < 1 + 12 + SPWire.BUCKETS[0] + 16 || (ciphertext[0].toInt() and 0xFF) != VERSION) throw SwellProtocolError.Format("link version")
        val lk = key(identity, theirs, channelId)
        val padded = SP.open(lk, ciphertext.copyOfRange(1, 13), ad(channelId, theirs, identity.serialized), ciphertext.copyOfRange(13, ciphertext.size))
        val r = SPIn(SPWire.unpadRaw(padded))
        val sentAt = r.i64()
        if (!(SP.within(sentAt, now, MAX_AGE_MILLIS) || (sentAt > now && sentAt <= SP.sat(now, MAX_AHEAD_MILLIS)))) throw SwellProtocolError.Format("link time")
        if (r.u8() != SPUpgradeFrame.INNER_TYPE) throw SwellProtocolError.Format("link frame")
        val frame = SPUpgradeFrame.decode(r)
        r.end()
        return Opened(sentAt, frame)
    }
}
