// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.math.BigInteger

// Swell Protocol draft 3, spec section 5.2: SwellSig, signatures by the X25519 identity key.
//
// An RFC 8032 Ed25519 signature that verifies under the Edwards form A of the X25519 identity key (RFC 7748 section 4.1 map), made
// with the X25519 scalar itself and a deterministic nonce. Written from RFC 8032, RFC 7748 and the spec text only. The verification is
// BouncyCastle's RFC 8032 section 5.1.7 check (lightweight API); the scalar arithmetic here uses BigInteger and is not constant time
// (signing is rare and happens on the owner's own phone, spec D15, O17).

object SPSignature {
    const val SIGNATURE_LEN = 64
    /** Context of a signed group state (spec 18). */
    const val GROUP_STATE_CONTEXT = "swell-group-state-v1"

    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    /** `L = 2^252 + 27742317777372353535851937790883648493`, the order of the Ed25519 base point. */
    val L: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))

    private fun le(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())
    private fun le32(v: BigInteger): ByteArray {
        val be = v.toByteArray()
        val out = ByteArray(32)
        // BigInteger's big-endian form may carry a leading 0x00 sign byte.
        val start = if (be.size > 32) be.size - 32 else 0
        for (i in start until be.size) out[be.size - 1 - i] = be[i]
        return out
    }

    private fun clamp(b: ByteArray): ByteArray = b.copyOf(32).also {
        it[0] = (it[0].toInt() and 248).toByte()
        it[31] = (it[31].toInt() and 127).toByte()
        it[31] = (it[31].toInt() or 64).toByte()
    }

    /** `A`: `y = (u - 1) * (u + 1)^-1 mod p`, 32 bytes little endian, sign bit 0 (the top bit of `u` is ignored, RFC 7748). */
    fun edwards(u: ByteArray): ByteArray {
        if (u.size != 32) throw SwellProtocolError.Format("x25519 key")
        val m = u.copyOf().also { it[31] = (it[31].toInt() and 0x7F).toByte() }
        val uu = le(m).mod(P)
        val den = uu.add(BigInteger.ONE).mod(P)
        if (den.signum() == 0) throw SwellProtocolError.Format("x25519 key")
        val y = uu.subtract(BigInteger.ONE).mod(P).multiply(den.modInverse(P)).mod(P)
        return le32(y) // y < p < 2^255: the top bit (sign of x) is 0
    }

    /** `"swell-sig-v3" | 0x00 | u8 len(context) | context | message`. */
    fun message(context: String, message: ByteArray): ByteArray {
        val c = context.toByteArray(Charsets.US_ASCII)
        require(c.size < 256 && context.all { it.code < 0x80 }) { "context is short ASCII" }
        return "swell-sig-v3".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, c.size.toByte()) + c + message
    }

    /** SwellSig by the identity [secret] (32 bytes, the X25519 private key). Deterministic: the same input gives the same 64 bytes. */
    fun sign(secret: ByteArray, context: String, message: ByteArray): ByteArray {
        if (secret.size != 32) throw SwellProtocolError.Format("identity secret")
        val u = SP.x25519Public(secret)
        val a = edwards(u)
        val msg = message(context, message)
        val rseed = SP.sha512("swell-sig-nonce".toByteArray(Charsets.US_ASCII), byteArrayOf(0), secret, msg).copyOf(32)
        val bigR = ByteArray(32)
        Ed25519.generatePublicKey(rseed, 0, bigR, 0)
        val r = le(clamp(SP.sha512(rseed).copyOf(32)))
        val k = le(SP.sha512(bigR, a, msg)).mod(L)
        val aMod = le(clamp(secret)).mod(L)
        // The sign of x of a*B is not visible from u: try both; exactly one verifies under A (spec 5.2), which doubles as a self-test.
        for (a0 in listOf(aMod, L.subtract(aMod).mod(L))) {
            val s = r.add(k.multiply(a0)).mod(L)
            val sig = bigR + le32(s)
            if (Ed25519.verify(sig, 0, a, 0, msg, 0, msg.size)) {
                SP.wipe(rseed)
                return sig
            }
        }
        throw SwellProtocolError.Crypto("signature self-test")
    }

    /**
     * Strict SwellSig verification (spec 5.2, CHANGED in draft 3): (1) 64 bytes and S below L; (2) u valid and A of order exactly L;
     * (3) R decodes strictly (y below p, no x = 0 with the sign bit set) to a point of order exactly L; (4) only then the RFC 8032
     * equation, handed to Bouncy Castle. Under 1 to 3 the plain and the cofactored equation agree, so every verifier gives one answer.
     */
    fun verify(u: ByteArray, context: String, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != SIGNATURE_LEN || !SPIdentity.isValidPublic(u)) return false
        if (le(signature.copyOfRange(32, 64)) >= L) return false // 1: S must be below L
        val a = try { edwards(u) } catch (e: SwellProtocolError) { return false }
        if (!primeOrderKey(a)) return false // 2
        val r = Edwards.decode(signature.copyOfRange(0, 32)) ?: return false // 3: strict decoding
        if (!Edwards.hasOrderL(r)) return false
        val msg = message(context, message)
        return try { Ed25519.verify(signature, 0, a, 0, msg, 0, msg.size) } catch (e: RuntimeException) { false }
    }

    /** Order checks of identity keys are remembered per key (public values only). */
    private val keyOrder = java.util.Collections.synchronizedMap(object : LinkedHashMap<String, Boolean>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?) = size > 256
    })

    private fun primeOrderKey(a: ByteArray): Boolean {
        val k = a.joinToString("") { "%02x".format(it) }
        keyOrder[k]?.let { return it }
        val ok = Edwards.decode(a)?.let { Edwards.hasOrderL(it) } ?: false
        keyOrder[k] = ok
        return ok
    }

    /**
     * Point arithmetic on edwards25519 (RFC 8032 section 5.1), affine coordinates with BigInteger, for the order checks of steps 2 and 3
     * only. Not constant time: it handles public values.
     */
    internal object Edwards {
        private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
        private val D = BigInteger.valueOf(-121665).mod(P).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
        private val SQRT_M1 = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)

        class Point(val x: BigInteger, val y: BigInteger) {
            val isIdentity: Boolean get() = x.signum() == 0 && y == BigInteger.ONE
        }

        private val IDENTITY = Point(BigInteger.ZERO, BigInteger.ONE)

        /** RFC 8032 5.1.3, strict: the y value below p, the square root exists, and x = 0 with the sign bit set is refused. */
        fun decode(b: ByteArray): Point? {
            if (b.size != 32) return null
            val sign = (b[31].toInt() ushr 7) and 1
            val yb = b.copyOf().also { it[31] = (it[31].toInt() and 0x7F).toByte() }
            val y = BigInteger(1, yb.reversedArray())
            if (y >= P) return null
            val y2 = y.multiply(y).mod(P)
            val num = y2.subtract(BigInteger.ONE).mod(P)
            val den = D.multiply(y2).add(BigInteger.ONE).mod(P)
            val x2 = num.multiply(den.modInverse(P)).mod(P)
            var x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
            if (x.multiply(x).mod(P) != x2) {
                x = x.multiply(SQRT_M1).mod(P)
                if (x.multiply(x).mod(P) != x2) return null
            }
            if (x.signum() == 0 && sign == 1) return null
            if (x.testBit(0) != (sign == 1)) x = P.subtract(x)
            return Point(x, y)
        }

        fun add(p: Point, q: Point): Point {
            val t = D.multiply(p.x).multiply(q.x).multiply(p.y).multiply(q.y).mod(P)
            val x = p.x.multiply(q.y).add(p.y.multiply(q.x)).multiply(BigInteger.ONE.add(t).modInverse(P)).mod(P)
            // a = -1: y3 = (y1 y2 + x1 x2) / (1 - t)
            val y = p.y.multiply(q.y).add(p.x.multiply(q.x)).multiply(BigInteger.ONE.subtract(t).mod(P).modInverse(P)).mod(P)
            return Point(x, y)
        }

        fun mul(k: BigInteger, p: Point): Point {
            var r = IDENTITY; var q = p
            for (i in 0 until k.bitLength()) {
                if (k.testBit(i)) r = add(r, q)
                q = add(q, q)
            }
            return r
        }

        /** Order exactly L: not the identity, and [L]P is the identity (L is prime). */
        fun hasOrderL(p: Point): Boolean = !p.isIdentity && mul(L, p).isIdentity
    }

    /** Verification by a serialized (33-byte) identity key; false for an invalid key. */
    fun verifySerialized(identity: ByteArray, context: String, message: ByteArray, signature: ByteArray): Boolean {
        val u = try { SPIdentity.publicKey(identity) } catch (e: SwellProtocolError) { return false }
        return verify(u, context, message, signature)
    }
}
