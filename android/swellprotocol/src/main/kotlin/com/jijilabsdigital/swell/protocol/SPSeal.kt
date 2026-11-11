// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

// Swell Protocol draft 3, spec sections 19 (report seal) and 20 (backup format). Both formats are those of build 26; neither used
// the libsignal library removed in build 27. Only the cryptography is here; the report body and the backup item stream are the app's.

/**
 * Report seal (spec 19): only the holder of the inbox private key opens it.
 *   key      = HKDF(salt = ephPublic | inboxPublic, ikm = DH(eph secret, inboxPublic), info = ASCII "swell report v1" (raw), 32)
 *   envelope = u8 1 | raw32 ephPublic | raw12 nonce | bytes(AES-256-GCM(key, nonce, no AD, plain))
 */
object SPReport {
    private val INFO = "swell report v1".toByteArray(Charsets.US_ASCII)

    fun key(shared: ByteArray, ephPublic: ByteArray, inboxPublic: ByteArray): ByteArray = SP.hkdf(ephPublic + inboxPublic, shared, INFO, 32)

    /** [ephemeralSecret] and [nonce] are fresh random values except in tests. */
    fun seal(inboxPublic: ByteArray, plain: ByteArray, ephemeralSecret: ByteArray = SP.random(32), nonce: ByteArray = SP.random(12)): ByteArray {
        if (inboxPublic.size != 32 || nonce.size != 12) throw SwellProtocolError.Format("report seal")
        val ephPublic = SP.x25519Public(ephemeralSecret)
        val shared = SP.dh(ephemeralSecret, inboxPublic)
        val key = key(shared, ephPublic, inboxPublic)
        SP.wipe(shared)
        return SPOut().u8(1).raw(ephPublic).raw(nonce).bytes(SP.seal(key, nonce, ByteArray(0), plain)).done()
    }

    fun open(inboxSecret: ByteArray, envelope: ByteArray): ByteArray {
        val r = SPIn(envelope)
        if (r.u8() != 1) throw SwellProtocolError.Format("report version")
        val ephPublic = r.raw(32); val nonce = r.raw(12); val ct = r.bytes(16 * 1024 * 1024)
        r.end()
        val shared = SP.dh(inboxSecret, ephPublic)
        val key = key(shared, ephPublic, SP.x25519Public(inboxSecret))
        return SP.open(key, nonce, ByteArray(0), ct)
    }
}

/**
 * Backup file format (spec 20):
 *   file  = "SWBK" | u8 1 | raw32 salt | chunk*         chunk = u8 last | u32 length | AES-256-GCM ciphertext | tag
 *   key   = HKDF(salt = file salt, ikm = account entropy (16 bytes), info = ASCII "swell backup v1" (raw), 32)
 *   nonce = 00 00 00 00 | u64 chunk index           ad = header | u64 chunk index | u8 last
 */
object SPBackupFormat {
    val MAGIC = "SWBK".toByteArray(Charsets.US_ASCII)
    const val VERSION = 1
    const val SALT_LEN = 32
    const val HEADER_LEN = 4 + 1 + SALT_LEN
    /** At most this much plaintext in one chunk. */
    const val CHUNK_PLAIN = 1 shl 20

    fun header(salt: ByteArray): ByteArray = MAGIC + byteArrayOf(VERSION.toByte()) + salt

    fun key(entropy: ByteArray, salt: ByteArray): ByteArray = SP.hkdf(salt, entropy, "swell backup v1".toByteArray(Charsets.US_ASCII), 32)

    fun nonce(index: Long): ByteArray {
        if (index < 0) throw SwellProtocolError.Format("chunk index")
        return ByteArray(4) + SP.be64(index)
    }

    fun authenticated(header: ByteArray, index: Long, last: Boolean): ByteArray = header + SP.be64(index) + byteArrayOf(if (last) 1 else 0)

    /** One sealed chunk with its 5-byte prefix: `u8 last | u32 length | ciphertext | tag`. */
    fun sealChunk(key: ByteArray, header: ByteArray, index: Long, last: Boolean, plain: ByteArray): ByteArray {
        if (plain.size > CHUNK_PLAIN) throw SwellProtocolError.Limit("chunk")
        val ct = SP.seal(key, nonce(index), authenticated(header, index, last), plain)
        return byteArrayOf(if (last) 1 else 0) + SP.be32(ct.size) + ct
    }

    fun openChunk(key: ByteArray, header: ByteArray, index: Long, last: Boolean, sealed: ByteArray): ByteArray =
        SP.open(key, nonce(index), authenticated(header, index, last), sealed)
}
