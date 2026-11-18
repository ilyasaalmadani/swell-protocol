// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPEntropy
import com.jijilabsdigital.swell.protocol.SPHandshake
import com.jijilabsdigital.swell.protocol.SPIdentity
import com.jijilabsdigital.swell.protocol.SPInviterSecrets
import com.jijilabsdigital.swell.protocol.SPSession
import com.jijilabsdigital.swell.protocol.SPWire
import com.jijilabsdigital.swell.protocol.SwellProtocolError
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom

// Shared pieces of the fuzz targets. Rule of every target: the library may refuse any input with a SwellProtocolError (or, for
// invite codes, SPInvite.Refused); any other exception, and any broken invariant (thrown as FuzzFinding), is a finding.

/** A broken invariant: the library accepted something it must refuse, or refused something it must accept. */
class FuzzFinding(what: String) : AssertionError(what)

fun invariant(ok: Boolean, what: () -> String) { if (!ok) throw FuzzFinding(what()) }

/** Runs [block]; a SwellProtocolError (an orderly refusal) gives null. Everything else propagates to the fuzzer. */
inline fun <T> refusedOrValue(block: () -> T): T? = try { block() } catch (e: SwellProtocolError) { null }

/** Reads structured values from fuzzer bytes. Past the end every read gives zeros, so a target never fails on short input. */
class FuzzIn(private val d: ByteArray) {
    private var pos = 0
    val left: Int get() = d.size - pos
    fun u8(): Int = if (pos < d.size) d[pos++].toInt() and 0xFF else 0
    fun bool(): Boolean = (u8() and 1) == 1
    fun u16(): Int = (u8() shl 8) or u8()
    fun i32(): Int = (u16() shl 16) or u16()
    fun i64(): Long = (i32().toLong() shl 32) or (i32().toLong() and 0xFFFFFFFFL)
    /** Exactly [n] bytes, zero-filled past the end. */
    fun bytes(n: Int): ByteArray {
        val k = minOf(n, left)
        val out = ByteArray(n)
        System.arraycopy(d, pos, out, 0, k)
        pos += k
        return out
    }
    /** Up to [max] bytes, the length taken from the input. */
    fun chunk(max: Int): ByteArray {
        val n = minOf(u16() % (max + 1), left)
        return d.copyOfRange(pos, pos + n).also { pos += n }
    }
    fun rest(): ByteArray = d.copyOfRange(pos, d.size).also { pos = d.size }
}

/** A SecureRandom that is a pure function of its seed (fuzzing must be deterministic). */
class SeededRandom(seed: ByteArray) : SecureRandom() {
    private val stream = Stream(seed)
    override fun nextBytes(bytes: ByteArray) { stream.fill(bytes) }
    override fun setSeed(seed: Long) {}
    override fun setSeed(seed: ByteArray) {}
}

/** SHA-256 in counter mode over a seed. */
class Stream(private val seed: ByteArray) {
    private var counter = 0L
    fun fill(out: ByteArray) {
        var pos = 0
        while (pos < out.size) {
            val block = MessageDigest.getInstance("SHA-256").run { update(seed); update(SP.be64(counter++)); digest() }
            val n = minOf(32, out.size - pos)
            System.arraycopy(block, 0, out, pos, n)
            pos += n
        }
    }
    fun bytes(n: Int): ByteArray = ByteArray(n).also { fill(it) }
}

/** Deterministic protocol randomness: the same seed gives the same keys, nonces and ML-KEM encapsulations. */
class DetEntropy(seed: ByteArray) : SPEntropy {
    private val stream = Stream(seed)
    override fun bytes(n: Int): ByteArray = stream.bytes(n)
    override fun encapsulate(ek: ByteArray): SP.KemEncapsulation {
        try {
            val r = MLKEMGenerator(SeededRandom(stream.bytes(32))).generateEncapsulated(MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, ek))
            return SP.KemEncapsulation(r.encapsulation, r.secret)
        } catch (e: RuntimeException) {
            throw SwellProtocolError.Crypto("kem ek")
        }
    }

    companion object {
        fun of(label: String, extra: ByteArray = ByteArray(0)): DetEntropy = DetEntropy(label.toByteArray(Charsets.US_ASCII) + extra)
    }
}

fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
fun rep(v: Int, n: Int): ByteArray = ByteArray(n) { v.toByte() }

/**
 * Fixed keys and states the targets work against. The identities, bundle inputs, binding and times are those of
 * docs/protocol-vectors/handshake-conversation.json and link.json, so the recorded HELLO and link ciphertexts of those files
 * open against these fixtures and make good seeds.
 */
object Fixtures {
    val idI = SPIdentity.derive(rep(0x21, 16))
    val idJ = SPIdentity.derive(rep(0x22, 16))
    val binding = rep(0x33, 32)
    const val EXPIRES = 1_800_000_000_000L
    const val BUNDLE_NOW = 1_799_990_000_000L
    val channel = rep(0x0c, 16)
    const val LINK_SENT_AT = 1_799_990_000_000L

    /** I's open bundle of handshake-conversation.json. */
    val secrets: SPInviterSecrets by lazy {
        val epk = hex("d5047d7366519f6b8ffb2d63872ddbc65d15cfcc239fa7982ddaf5dc7b15007f")
        val seed = hex("35da49293b89acafee2a1774fca797e7bd4211e1fb0b8b44fcab7c58c582cf38503e973e84f12359f91c37bbe53e266a62c9a23827539281cffc665e7ae224d1")
        SPInviterSecrets(epk, seed, SPWire.Bundle(idI.publicKey, SP.x25519Public(epk), SP.kemPublic(seed), EXPIRES))
    }

    /** A finished handshake: (I after accepting the HELLO, J after sending it), made with deterministic randomness. */
    val start: Pair<SPSession, SPSession> by lazy {
        val h = SP.withEntropy(DetEntropy.of("fixture J")) {
            SPHandshake.joinerStart(secrets.bundle, idI.publicKey, idJ, binding, "hello".toByteArray(), BUNDLE_NOW)
        }
        val a = SP.withEntropy(DetEntropy.of("fixture I")) { SPHandshake.inviterAccept(secrets, idI, h.hello, binding, BUNDLE_NOW + 500) }
        a.session to h.session
    }

    /** The HELLO envelope J sent in [start]. */
    val hello: ByteArray by lazy {
        SP.withEntropy(DetEntropy.of("fixture J")) {
            SPHandshake.joinerStart(secrets.bundle, idI.publicKey, idJ, binding, "hello".toByteArray(), BUNDLE_NOW).hello
        }
    }

    /** A few envelopes I -> J and J -> I after [start], and the states after them (seeds and decrypt inputs). */
    class Exchange(val iState: SPSession, val jState: SPSession, val toJ: List<ByteArray>, val toI: List<ByteArray>)

    val exchange: Exchange by lazy {
        var (i, j) = start
        val toJ = ArrayList<ByteArray>(); val toI = ArrayList<ByteArray>()
        val e = DetEntropy.of("fixture exchange")
        SP.withEntropy(e) {
            var now = BUNDLE_NOW + 1000
            for (round in 0 until 3) {
                val a = i.encrypt("from I $round".toByteArray(), now); i = a.session; toJ += a.envelope
                j = j.decrypt(a.envelope, now + 1).session
                val b = j.encrypt("from J $round".toByteArray(), now + 2); j = b.session; toI += b.envelope
                i = i.decrypt(b.envelope, now + 3).session
                now += 10_000
            }
            // Two more from I that J has not read yet.
            repeat(2) { k -> val a = i.encrypt("unread $k".toByteArray(), now + k); i = a.session; toJ += a.envelope }
        }
        Exchange(i, j, toJ, toI)
    }
}
