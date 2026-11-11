// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

import java.math.BigInteger

// Swell Protocol draft 3, spec section 5.1 (identity keys).
//
// One identity per person, derived from the 16 bytes of account entropy (the 12-word recovery phrase). It is an X25519 key; the
// 33-byte form `0x05 | public` is what contacts, group rosters and safety numbers carry. The type byte 0x05 is historical: it keeps
// every identity a phone already stores valid. The same scalar also signs (SPSignature).

/** The account's identity key pair. [secret] never leaves the device and is never logged. */
class SPIdentity(val secret: ByteArray) {
    /** The X25519 public key (32 bytes). */
    val publicKey: ByteArray = SP.x25519Public(secret)

    /** `0x05 | publicKey` (33 bytes). */
    val serialized: ByteArray get() = byteArrayOf(TYPE_BYTE) + publicKey

    companion object {
        const val TYPE_BYTE: Byte = 0x05
        const val SERIALIZED_LEN = 33
        private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

        /** `secret = HKDF-SHA-256(ikm = entropy, salt = 32 zero bytes, info = ASCII "swell identity v1", L = 32)` (no Info encoder). */
        fun derive(entropy: ByteArray): SPIdentity {
            if (entropy.size != 16) throw SwellProtocolError.Format("entropy")
            return SPIdentity(SP.hkdf(ByteArray(32), entropy, "swell identity v1".toByteArray(Charsets.US_ASCII), 32))
        }

        /** The 32-byte public key inside a serialized identity key; refuses a wrong length or type byte and any key that is not valid. */
        fun publicKey(serialized: ByteArray): ByteArray {
            if (serialized.size != SERIALIZED_LEN || serialized[0] != TYPE_BYTE) throw SwellProtocolError.Format("identity key")
            val u = serialized.copyOfRange(1, SERIALIZED_LEN)
            if (!isValidPublic(u)) throw SwellProtocolError.Format("identity key")
            return u
        }

        /** True for a valid serialized identity key (spec 5.1). */
        fun isValidSerialized(serialized: ByteArray): Boolean = runCatching { publicKey(serialized) }.isSuccess

        /**
         * Spec 5.1: valid when the 32 bytes are canonical (top bit clear, little-endian value below 2^255 - 19) and the point is not of
         * small order (a DH with a non-zero scalar is not all zero).
         */
        fun isValidPublic(u: ByteArray): Boolean {
            if (u.size != 32 || (u[31].toInt() and 0x80) != 0) return false
            if (leInt(u) >= P) return false
            return runCatching { SP.dh(ByteArray(32) { 0x42 }, u) }.isSuccess
        }

        internal fun leInt(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())
    }
}
