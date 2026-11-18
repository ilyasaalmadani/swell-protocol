// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPSignature
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * SwellSig (spec 5.2), the signature on group states and other signed statements, verified under the X25519 identity key.
 *  - mode 0: hostile (key, signature, message) for [SPSignature.verify] and [SPSignature.verifySerialized]. Differential check: when
 *    SwellSig accepts, the JDK's own RFC 8032 Ed25519 must accept the same signature under the Edwards form of the key, and S must
 *    be below L (the strict rules only ever remove signatures, never add one).
 *  - mode 1: any identity secret signs any message; the signature must verify, be deterministic, and fail for another context.
 */
object SignatureFuzzer {
    private val contexts = arrayOf(SPSignature.GROUP_STATE_CONTEXT, "test", "")
    private val X509_ED25519 = hex("302a300506032b6570032100")
    private val L = SPSignature.L

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val f = FuzzIn(data)
        val mode = f.u8()
        val context = contexts[(mode shr 1) % contexts.size]
        if ((mode and 1) == 0) hostile(f, context) else roundTrip(f, context)
    }

    private fun hostile(f: FuzzIn, context: String) {
        val serialized = f.bool()
        val key = f.bytes(if (serialized) 33 else 32)
        val sig = f.chunk(80).let { if (it.size >= 64 && f.bool()) it.copyOf(64) else it }
        val msg = f.rest()
        val ok = if (serialized) SPSignature.verifySerialized(key, context, msg, sig) else SPSignature.verify(key, context, msg, sig)
        // The verdict is a pure function of the input (the order-check cache must never change it).
        val again = if (serialized) SPSignature.verifySerialized(key, context, msg, sig) else SPSignature.verify(key, context, msg, sig)
        invariant(ok == again) { "verify is not deterministic" }
        // The Edwards map must never throw anything but its own refusal.
        refusedOrValue { SPSignature.edwards(if (serialized) key.copyOfRange(1, 33) else key) }
        if (!ok) return
        invariant(sig.size == 64) { "accepted a signature of ${sig.size} bytes" }
        invariant(BigInteger(1, sig.copyOfRange(32, 64).reversedArray()) < L) { "accepted S >= L" }
        val u = if (serialized) key.copyOfRange(1, 33) else key
        invariant(jdkVerify(SPSignature.edwards(u), SPSignature.message(context, msg), sig)) { "SwellSig accepted what RFC 8032 refuses" }
    }

    private fun roundTrip(f: FuzzIn, context: String) {
        val secret = f.bytes(32)
        val msg = f.rest()
        val sig = SPSignature.sign(secret, context, msg) // a SwellProtocolError here is a finding: every 32-byte secret can sign
        val u = SP.x25519Public(secret)
        invariant(sig.size == 64) { "signature size" }
        invariant(SPSignature.verify(u, context, msg, sig)) { "own signature does not verify" }
        invariant(SPSignature.sign(secret, context, msg).contentEquals(sig)) { "signing is not deterministic" }
        invariant(!SPSignature.verify(u, context + "x", msg, sig)) { "signature verifies under another context" }
        invariant(jdkVerify(SPSignature.edwards(u), SPSignature.message(context, msg), sig)) { "own signature fails RFC 8032" }
    }

    private fun jdkVerify(a: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = try {
        val pub = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(X509_ED25519 + a))
        Signature.getInstance("Ed25519").run { initVerify(pub); update(msg); verify(sig) }
    } catch (e: Exception) {
        false // the reference refusing a key or signature in any way counts as "refused"
    }
}
