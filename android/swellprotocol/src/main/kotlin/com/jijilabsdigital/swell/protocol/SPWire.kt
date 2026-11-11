// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

// Swell Protocol draft 3, byte layouts. Spec sections: 5.3 (bundle), 7.3 (header), 7.4 (body and padding), 7.5 (envelopes),
// 7.6 (PQ field), 6.4 (link frame content, inner type 26), 5.6 (MSG ciphertext types 34 and 35).

object SPWire {
    /** Envelope version byte of draft 2. */
    const val VER = 2
    const val KIND_BUNDLE = 0
    const val KIND_HELLO = 1
    const val KIND_DATA = 2

    /** Header plaintext (spec 7.3): `raw32 dh_pub | i32 pn | i32 n | i32 epoch` = 44 bytes; hct adds the 16-byte tag. */
    const val HEADER_LEN = 44
    const val HCT_LEN = 60
    /** HELLO prefix after `ver | kind`: `raw32 ID_J | raw32 E | raw1088 ct`. */
    const val HELLO_KEYS_LEN = 32 + 32 + SP.KEM_CT_LEN
    /** Bundle (spec 5): `u8 2 | raw32 ID_I | raw32 EPK | raw1184 EK | i64 expiresAtMs` = 1257 bytes. */
    const val BUNDLE_LEN = 1 + 32 + 32 + SP.KEM_EK_LEN + 8

    /** Padding buckets, the same as PROTOCOL.md section 1 (spec 7.4). Draft 3: always the full sizes (no outer layer). */
    val BUCKETS = intArrayOf(1024, 4096, 16384, 65536, 262144)
    /** A PQ field never moves a frame whose bucket is above 16 KiB into a larger bucket (spec 7.6, review F14). */
    const val PQ_BUCKET_CAP = 16384
    /** MSG ciphertext type of a bare DATA envelope (spec 5.6). */
    const val CT_DATA = 34
    /** MSG ciphertext type of a link frame (spec 5.6, 6.4). */
    const val CT_LINK = 35
    /** Ciphertext types of the removed libsignal library (2, 3) and build 26's wrapped envelopes (32, 33): an older app (spec 6.5). Never sent. */
    val LEGACY_TYPES = setOf(2, 3, 32, 33)

    /** The bucket a padded content of [need] bytes (4-byte length included) uses, or null when too large. */
    fun bucket(need: Int): Int? = BUCKETS.firstOrNull { it >= need }

    // ---- header (7.3) ------------------------------------------------------------------------------------------------------

    class Header(val dhPub: ByteArray, val pn: Int, val n: Int, val epoch: Int) {
        fun encode(): ByteArray = dhPub + SP.be32(pn) + SP.be32(n) + SP.be32(epoch)

        companion object {
            fun decode(b: ByteArray): Header {
                if (b.size != HEADER_LEN) throw SwellProtocolError.Format("header length")
                val r = SPIn(b)
                val h = Header(r.raw(32), r.i32(), r.i32(), r.i32())
                if (h.pn < 0 || h.n < 0 || h.epoch < 0) throw SwellProtocolError.Format("header values")
                return h
            }
        }
    }

    // ---- PQ field and padding (7.4, 7.6) -----------------------------------------------------------------------------------

    /** The PQ ratchet field at the start of the padded content: none, an encapsulation key, or a ciphertext. */
    sealed class PQField {
        object None : PQField()
        class Ek(val target: Int, val ek: ByteArray) : PQField()
        class Ct(val target: Int, val ct: ByteArray) : PQField()

        fun encode(): ByteArray = when (this) {
            is None -> byteArrayOf(0)
            is Ek -> byteArrayOf(1) + SP.be32(target) + ek
            is Ct -> byteArrayOf(2) + SP.be32(target) + ct
        }
    }

    /** `padded = i32 length | content | zero bytes up to the bucket`, `content = pq field | inner message`. */
    fun pad(pq: PQField, inner: ByteArray): ByteArray = padRaw(pq.encode() + inner)

    /** The padding of 7.4 for any content (the link frames of 6.4 use it too). */
    fun padRaw(content: ByteArray): ByteArray {
        val need = 4 + content.size
        val size = bucket(need) ?: throw SwellProtocolError.Limit("message too large")
        return SP.be32(content.size) + content + ByteArray(size - need)
    }

    /** Strict inverse of [padRaw]: the size must be a bucket, the length in range, every padding byte zero (checked in constant time). */
    fun unpadRaw(p: ByteArray): ByteArray {
        if (BUCKETS.none { it == p.size }) throw SwellProtocolError.Format("bucket")
        val r = SPIn(p)
        val n = r.i32()
        if (n < 1 || n > p.size - 4) throw SwellProtocolError.Format("padding length")
        if (!SP.isZero(p.copyOfRange(4 + n, p.size))) throw SwellProtocolError.Format("padding bytes")
        return p.copyOfRange(4, 4 + n)
    }

    class Unpadded(val pq: PQField, val inner: ByteArray)

    /** Strict inverse of [pad]. */
    fun unpad(p: ByteArray): Unpadded {
        val content = unpadRaw(p)
        val n = content.size
        val c = SPIn(content)
        val pq: PQField = when (c.u8()) {
            0 -> PQField.None
            1 -> { val t = c.i32(); if (t <= 0) throw SwellProtocolError.Format("pq target"); PQField.Ek(t, c.raw(SP.KEM_EK_LEN)) }
            2 -> { val t = c.i32(); if (t <= 0) throw SwellProtocolError.Format("pq target"); PQField.Ct(t, c.raw(SP.KEM_CT_LEN)) }
            else -> throw SwellProtocolError.Format("pq kind")
        }
        return Unpadded(pq, content.copyOfRange(n - c.remaining, n))
    }

    // ---- envelopes (7.5) ---------------------------------------------------------------------------------------------------

    class Envelope(val kind: Int, val helloKeys: ByteArray, val hnonce: ByteArray, val hct: ByteArray, val body: ByteArray) {
        /** `u8 ver | u8 kind` and, for HELLO, the three keys: the `prefix` of spec 7.3, bound into both ADs. */
        val prefix: ByteArray get() = byteArrayOf(VER.toByte(), kind.toByte()) + helloKeys
        fun encode(): ByteArray = prefix + hnonce + hct + body

        companion object {
            fun decode(b: ByteArray): Envelope {
                if (b.size < 2 || (b[0].toInt() and 0xFF) != VER) throw SwellProtocolError.Format("version")
                val kind = b[1].toInt() and 0xFF
                val keys = when (kind) {
                    KIND_DATA -> 0
                    KIND_HELLO -> HELLO_KEYS_LEN
                    else -> throw SwellProtocolError.Format("kind")
                }
                val start = 2 + keys
                val bodyStart = start + 12 + HCT_LEN
                // Smallest body: the 1 KiB bucket plus the tag.
                if (b.size < bodyStart + BUCKETS[0] + 16) throw SwellProtocolError.Format("envelope length")
                return Envelope(kind, b.copyOfRange(2, start), b.copyOfRange(start, start + 12),
                    b.copyOfRange(start + 12, bodyStart), b.copyOfRange(bodyStart, b.size))
            }
        }
    }

    // ---- bundle (5.3) --------------------------------------------------------------------------------------------------------

    class Bundle(val idI: ByteArray, val epk: ByteArray, val ek: ByteArray, val expiresAtMs: Long) {
        fun encode(): ByteArray = byteArrayOf(VER.toByte()) + idI + epk + ek + SP.be64(expiresAtMs)
        /** `bundleCommit = SHA256Tagged("bundle", bundle)`. */
        val commit: ByteArray get() = SP.tagged("bundle", encode())

        companion object {
            fun decode(b: ByteArray): Bundle {
                if (b.size != BUNDLE_LEN || (b[0].toInt() and 0xFF) != VER) throw SwellProtocolError.Format("bundle")
                val r = SPIn(b); r.u8()
                return Bundle(r.raw(32), r.raw(32), r.raw(SP.KEM_EK_LEN), r.i64())
            }
        }
    }
}

/** Link handshake frames, inner message type 26 (spec 6.4): OFFER, HELLO, RESET, SYNC travel in link frames, READY inside a session. */
sealed class SPUpgradeFrame {
    /** I offers a Swell handshake. */
    class Offer(val offerId: ByteArray, val bundle: ByteArray) : SPUpgradeFrame()
    /** J answers with the HELLO envelope. */
    class Hello(val offerId: ByteArray, val envelope: ByteArray) : SPUpgradeFrame()
    /** Inside the first Swell messages in each direction: the session for this offer works. */
    class Ready(val offerId: ByteArray) : SPUpgradeFrame()
    /** "I hold no Swell session for this contact." The receiver drops its Swell state. */
    object Reset : SPUpgradeFrame()
    /** `SHA256Tagged("session", T)` of the session the sender holds, or 32 zero bytes for none. */
    class Sync(val sessionHash: ByteArray) : SPUpgradeFrame()

    fun encode(): ByteArray {
        val o = SPOut().u8(INNER_TYPE)
        when (this) {
            is Offer -> o.u8(1).raw(offerId).bytes(bundle)
            is Hello -> o.u8(2).raw(offerId).bytes(envelope)
            is Ready -> o.u8(3).raw(offerId)
            is Reset -> o.u8(4)
            is Sync -> o.u8(5).raw(sessionHash)
        }
        return o.done()
    }

    companion object {
        const val INNER_TYPE = 26

        /** Reads the frame after its inner type byte. Unknown ops are refused (the caller ignores the frame). */
        fun decode(r: SPIn): SPUpgradeFrame = when (r.u8()) {
            1 -> Offer(r.raw(16), r.bytes(SPWire.BUNDLE_LEN))
            2 -> Hello(r.raw(16), r.bytes(8192))
            3 -> Ready(r.raw(16))
            4 -> Reset
            5 -> Sync(r.raw(32))
            else -> throw SwellProtocolError.Format("upgrade op")
        }
    }
}
