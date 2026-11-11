package com.jijilabsdigital.swell.protocol

import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital
//
// Swell Protocol, draft 3 (docs/SWELL-PROTOCOL-SPEC.md). Clean-room Kotlin port of the Swell Protocol written from that
// specification and the public documents it lists (docs/CLEAN-ROOM.md); the Swift implementation in the iOS app is Swell's own
// code and was the byte-level reference, the shared vectors in docs/protocol-vectors/ the test. No source of the removed libsignal library or of a Signal app was read.
//
// This file: spec section 4 (encoding and primitive boundaries). Primitives: X25519, Ed25519 verification and ML-KEM-768 from
// BouncyCastle (MIT, lightweight API), HKDF-SHA-256, SHA-512 and AES-256-GCM from the JDK / Android platform provider.

/** Errors of the Swell Protocol. The kinds say only what failed, never a key or a byte of plaintext. */
sealed class SwellProtocolError(msg: String) : Exception(msg) {
    /** A length, version, kind or field is wrong. */
    class Format(what: String) : SwellProtocolError("format: $what")
    /** An AEAD did not open, a DH output was all zero, or a commitment did not match. */
    class Crypto(what: String) : SwellProtocolError("crypto: $what")
    /** A duplicate or replay, or a key already deleted. */
    class Duplicate : SwellProtocolError("duplicate")
    /** A limit of spec 8.1 was hit. */
    class Limit(what: String) : SwellProtocolError("limit: $what")
    /** No session (or no pending handshake) exists for this relationship. */
    class NoSession : SwellProtocolError("no session")
}

/**
 * Where the protocol's randomness comes from (spec 4). The platform source in the app; tests replace it with recorded bytes to replay
 * the shared vectors ([SP.withEntropy]). ML-KEM encapsulation is randomised inside the KEM, so it is part of the source as well.
 */
interface SPEntropy {
    fun bytes(n: Int): ByteArray
    /** `KEM.Enc(ek)` for an `ek` that already passed the FIPS 203 check. */
    fun encapsulate(ek: ByteArray): SP.KemEncapsulation
}

/** The platform cryptographic source. A failure throws and stops the operation; there is no fallback (spec 4). */
object SPSystemEntropy : SPEntropy {
    private val random = SecureRandom()
    override fun bytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }
    override fun encapsulate(ek: ByteArray): SP.KemEncapsulation = SP.kemEncapsulateSystem(ek, random)
}

object SP {
    /** Domain version, in every `Info` and every tagged hash. Draft 3 keeps the 2 of draft 2 (spec 1, 4). */
    const val VERSION = 2

    const val X25519_LEN = 32
    const val KEM_EK_LEN = 1184
    const val KEM_CT_LEN = 1088
    const val KEM_SS_LEN = 32
    const val KEM_SEED_LEN = 64

    private val random = SecureRandom()
    private val override = ThreadLocal<SPEntropy?>()

    /** The source used by this thread: the platform one, or the one a test put in place with [withEntropy]. */
    val entropy: SPEntropy get() = override.get() ?: SPSystemEntropy

    /** Runs [block] with [e] as this thread's randomness (tests that replay recorded vectors). */
    fun <T> withEntropy(e: SPEntropy, block: () -> T): T {
        val old = override.get()
        override.set(e)
        try { return block() } finally { override.set(old) }
    }

    // ---- 4 encoders -------------------------------------------------------------------------------------------------------

    private fun domain(label: String): ByteArray {
        val l = label.toByteArray(Charsets.US_ASCII)
        require(l.size < 256 && label.all { it.code < 0x80 }) { "labels are short ASCII" }
        return "Swell".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, VERSION.toByte(), l.size.toByte()) + l
    }

    /** `Info(label, f1..fn) = "Swell" | 0x00 | u8 2 | u8 len(label) | label | (u16 len(f) | f)*`. */
    fun info(label: String, vararg fields: ByteArray): ByteArray {
        var out = domain(label)
        for (f in fields) {
            require(f.size <= 0xFFFF)
            out += byteArrayOf((f.size shr 8).toByte(), (f.size and 0xFF).toByte()) + f
        }
        return out
    }

    /** `SHA256Tagged(tag, data) = SHA-256("Swell" | 0x00 | u8 2 | u8 len(tag) | tag | data)`. */
    fun tagged(tag: String, data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").run { update(domain(tag)); update(data); digest() }

    /** Saturating addition for times and counters: never overflows, whatever a peer sent (review N1). */
    fun sat(a: Long, b: Long): Long {
        val r = a + b
        return if (((a xor r) and (b xor r)) < 0) (if (b > 0) Long.MAX_VALUE else Long.MIN_VALUE) else r
    }

    /** True when [then] is less than [gap] before [now] (a clock that went back counts as "not recent"). */
    fun within(then: Long, now: Long, gap: Long): Boolean = then <= now && now < sat(then, gap)

    fun be32(v: Int): ByteArray = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    fun be64(v: Long): ByteArray = be32((v ushr 32).toInt()) + be32(v.toInt())

    // ---- HKDF-SHA-256 (RFC 5869) -------------------------------------------------------------------------------------------

    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        // An empty key is legal in HKDF (it means 32 zero bytes); SecretKeySpec refuses zero length.
        m.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        for (p in parts) m.update(p)
        return m.doFinal()
    }

    /** `HKDF(salt, ikm, info, L)`: Extract then Expand. */
    fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        return expandRaw(prk, info, length)
    }

    /** `Expand(prk, info, L)` alone, with a 32-byte `prk`. */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(prk.size == 32)
        return expandRaw(prk, info, length)
    }

    private fun expandRaw(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var i = 1
        while (pos < length) {
            t = hmac(prk, t, info, byteArrayOf(i.toByte()))
            val n = minOf(32, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            i++
        }
        return out
    }

    // ---- AES-256-GCM -------------------------------------------------------------------------------------------------------

    /** `AEAD(key, nonce, ad, pt)` = AES-256-GCM, output `ciphertext | 16-byte tag`. */
    fun seal(key: ByteArray, nonce: ByteArray, ad: ByteArray, pt: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(ad)
        return c.doFinal(pt)
    }

    fun open(key: ByteArray, nonce: ByteArray, ad: ByteArray, ct: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != 12 || ct.size < 16) throw SwellProtocolError.Crypto("aead")
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            c.updateAAD(ad)
            return c.doFinal(ct)
        } catch (e: java.security.GeneralSecurityException) {
            throw SwellProtocolError.Crypto("aead")
        }
    }

    // ---- X25519 (RFC 7748) -------------------------------------------------------------------------------------------------

    class KeyPair(val sk: ByteArray, val pk: ByteArray)

    /** A fresh X25519 key pair. */
    fun x25519(): KeyPair {
        val sk = random(32)
        return KeyPair(sk, x25519Public(sk))
    }

    fun x25519Public(sk: ByteArray): ByteArray {
        if (sk.size != 32) throw SwellProtocolError.Format("x25519 key")
        val pk = ByteArray(32)
        X25519.scalarMultBase(sk, 0, pk, 0)
        return pk
    }

    /** `DH(sk, pk)`. An all-zero output (low-order peer key) is refused, for every DH (spec 4). */
    fun dh(sk: ByteArray, pk: ByteArray): ByteArray {
        if (sk.size != 32 || pk.size != 32) throw SwellProtocolError.Format("x25519 length")
        val out = ByteArray(32)
        // BouncyCastle returns false for an all-zero result; the explicit check below does not rely on that.
        X25519.calculateAgreement(sk, 0, pk, 0, out, 0)
        if (isZero(out)) throw SwellProtocolError.Crypto("dh zero")
        return out
    }

    // ---- ML-KEM-768 (FIPS 203) ---------------------------------------------------------------------------------------------

    private val kemParams = MLKEMParameters.ml_kem_768

    class KemKey(val seed: ByteArray, val ek: ByteArray)
    class KemEncapsulation(val ct: ByteArray, val ss: ByteArray)

    private fun kemPrivate(seed: ByteArray): MLKEMPrivateKeyParameters {
        if (seed.size != KEM_SEED_LEN) throw SwellProtocolError.Format("kem seed")
        val gen = MLKEMKeyPairGenerator()
        gen.init(MLKEMKeyGenerationParameters(random, kemParams)) // the random source is not used: the seed is given
        val pair = gen.internalGenerateKeyPair(seed.copyOfRange(0, 32), seed.copyOfRange(32, 64))
        return pair.private as MLKEMPrivateKeyParameters
    }

    /** A fresh ML-KEM-768 key: the 64-byte seed `d | z` (the private form kept on the device) and the 1184-byte encapsulation key. */
    fun kemGenerate(): KemKey {
        val seed = random(KEM_SEED_LEN)
        return KemKey(seed, kemPublic(seed))
    }

    /** The encapsulation key of a stored seed. */
    fun kemPublic(seed: ByteArray): ByteArray = kemPrivate(seed).publicKey

    /**
     * FIPS 203 section 7.2 encapsulation-key check: the length, and every 12-bit coefficient of the polynomial part below q = 3329
     * (decode then re-encode must give the same bytes; here: no coefficient is 3329 or more).
     */
    fun kemValidEK(ek: ByteArray): Boolean {
        if (ek.size != KEM_EK_LEN) return false
        // 3 polynomial vectors of 256 coefficients, 12 bits each: 3 * 384 = 1152 bytes, then the 32-byte rho.
        var i = 0
        while (i < 1152) {
            val b0 = ek[i].toInt() and 0xFF
            val b1 = ek[i + 1].toInt() and 0xFF
            val b2 = ek[i + 2].toInt() and 0xFF
            val c0 = b0 or ((b1 and 0x0F) shl 8)
            val c1 = (b1 shr 4) or (b2 shl 4)
            if (c0 >= 3329 || c1 >= 3329) return false
            i += 3
        }
        return true
    }

    /** `KEM.Enc(ek)`: validates `ek` as FIPS 203 requires; returns (ct 1088, ss 32). The randomness comes from [entropy]. */
    fun kemEncapsulate(ek: ByteArray): KemEncapsulation {
        if (ek.size != KEM_EK_LEN) throw SwellProtocolError.Format("kem ek")
        if (!kemValidEK(ek)) throw SwellProtocolError.Crypto("kem ek")
        val r = entropy.encapsulate(ek)
        if (r.ct.size != KEM_CT_LEN || r.ss.size != KEM_SS_LEN) throw SwellProtocolError.Crypto("kem enc")
        return r
    }

    internal fun kemEncapsulateSystem(ek: ByteArray, rnd: SecureRandom): KemEncapsulation {
        try {
            val pub: AsymmetricKeyParameter = MLKEMPublicKeyParameters(kemParams, ek)
            val r = MLKEMGenerator(rnd).generateEncapsulated(pub)
            return KemEncapsulation(r.encapsulation, r.secret)
        } catch (e: RuntimeException) {
            throw SwellProtocolError.Crypto("kem ek")
        }
    }

    /** `KEM.Dec(dk, ct)`. A wrong `ct` gives a pseudo-random secret (implicit rejection), so a later AEAD fails. */
    fun kemDecapsulate(seed: ByteArray, ct: ByteArray): ByteArray {
        if (seed.size != KEM_SEED_LEN || ct.size != KEM_CT_LEN) throw SwellProtocolError.Format("kem ct")
        try {
            return MLKEMExtractor(kemPrivate(seed)).extractSecret(ct)
        } catch (e: RuntimeException) {
            throw SwellProtocolError.Crypto("kem dec")
        }
    }

    // ---- randomness, comparison, wiping ------------------------------------------------------------------------------------

    /** Random bytes from [entropy] (the platform source). A failure throws and stops the operation (spec 4); there is no fallback. */
    fun random(n: Int): ByteArray = entropy.bytes(n).also { if (it.size != n) throw SwellProtocolError.Crypto("entropy") }

    /** SHA-512 (FIPS 180-4), used only by SwellSig (spec 5.2). */
    fun sha512(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").run { parts.forEach { update(it) }; digest() }

    /** SHA-256 of [parts]. */
    fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }

    /** Unsigned byte order (spec 6.4, 11, 18): true when [a] comes before [b]. */
    fun lexLess(a: ByteArray, b: ByteArray): Boolean {
        for (i in 0 until minOf(a.size, b.size)) {
            val x = a[i].toInt() and 0xFF; val y = b[i].toInt() and 0xFF
            if (x != y) return x < y
        }
        return a.size < b.size
    }

    /** Constant-time equality: the time depends only on the lengths, never on where the bytes differ. */
    fun ctEqual(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /** Constant-time all-zero check. */
    fun isZero(a: ByteArray): Boolean {
        var d = 0
        for (x in a) d = d or x.toInt()
        return d == 0
    }

    /** Best-effort wipe of a buffer the caller made and holds alone. It never promises erasure (spec 12). */
    fun wipe(b: ByteArray) { b.fill(0) }
}
