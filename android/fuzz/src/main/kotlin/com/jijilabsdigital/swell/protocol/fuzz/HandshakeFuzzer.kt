// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPHandshake
import com.jijilabsdigital.swell.protocol.SPIdentity
import com.jijilabsdigital.swell.protocol.SPWire
import com.jijilabsdigital.swell.protocol.SwellProtocolError

/**
 * The handshake (spec 6.1, 6.2).
 *  - mode 0: a hostile HELLO envelope given to the inviter (fixture bundle of handshake-conversation.json). Accepting one means the
 *    sender knew J's identity secret, so an accepted HELLO must name the identity that [SPHandshake.helloIdentity] shows.
 *  - mode 1: a real joiner (fuzzer-chosen identity, inner message, time and randomness) builds a HELLO; with no change the inviter
 *    must accept it and see the same inner message and identity; with any one byte changed the inviter must refuse it.
 *  - mode 2: a hostile bundle given to the joiner: the bundle decoder, the FIPS 203 key check and the identity checks.
 */
object HandshakeFuzzer {
    private val inviterNow = Fixtures.BUNDLE_NOW + 500

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val f = FuzzIn(data)
        when (f.u8() % 3) {
            0 -> hostileHello(f.rest())
            1 -> realJoiner(f)
            else -> hostileBundle(f)
        }
    }

    private fun hostileHello(hello: ByteArray) {
        val a = refusedOrValue {
            SP.withEntropy(DetEntropy.of("hostile hello")) {
                SPHandshake.inviterAccept(Fixtures.secrets, Fixtures.idI, hello, Fixtures.binding, inviterNow)
            }
        } ?: return
        invariant(a.session.peerIdentity.contentEquals(SPHandshake.helloIdentity(hello))) { "accepted HELLO names another identity" }
        invariant(SPIdentity.isValidSerialized(a.session.peerIdentity)) { "accepted HELLO from an invalid identity" }
    }

    private fun realJoiner(f: FuzzIn) {
        val joiner = SPIdentity.derive(f.bytes(16))
        val inner = f.chunk(1500)
        val now = Fixtures.BUNDLE_NOW + (f.u16() % 10_001) * 1000L // up to expiresAtMs, which is 10 000 s after BUNDLE_NOW
        val seed = f.bytes(16)
        val flip = f.u8() == 0xA5 // about 1 in 256 runs keep the HELLO intact
        val at = f.u16(); val bit = f.u8() % 8
        val h = try {
            SP.withEntropy(DetEntropy.of("joiner", seed)) {
                SPHandshake.joinerStart(Fixtures.secrets.bundle, Fixtures.idI.publicKey, joiner, Fixtures.binding, inner, now)
            }
        } catch (e: SwellProtocolError.Limit) {
            invariant(SPWire.bucket(4 + 1 + inner.size) == null) { "joiner refused a small message" }
            return
        }
        var hello = h.hello
        val changed = !flip
        if (changed) hello = hello.copyOf().also { it[at % it.size] = (it[at % it.size].toInt() xor (1 shl bit)).toByte() }
        val a = refusedOrValue {
            SP.withEntropy(DetEntropy.of("inviter", seed)) { SPHandshake.inviterAccept(Fixtures.secrets, Fixtures.idI, hello, Fixtures.binding, now) }
        }
        if (changed) {
            invariant(a == null) { "inviter accepted a HELLO with byte ${at % hello.size} changed" }
        } else {
            invariant(a != null) { "inviter refused an intact HELLO" }
            invariant(a!!.inner.contentEquals(inner)) { "HELLO inner message differs" }
            invariant(a.session.peerIdentity.contentEquals(joiner.serialized)) { "HELLO identity differs" }
            invariant(a.session.sessionHash.contentEquals(h.session.sessionHash)) { "the two sides hold different transcripts" }
        }
    }

    private fun hostileBundle(f: FuzzIn) {
        val now = f.i64()
        val bytes = f.rest()
        val b = refusedOrValue { SPWire.Bundle.decode(bytes) } ?: return
        val h = refusedOrValue {
            SP.withEntropy(DetEntropy.of("hostile bundle")) {
                SPHandshake.joinerStart(b, b.idI, Fixtures.idJ, Fixtures.binding, "x".toByteArray(), now)
            }
        } ?: return
        invariant(SP.kemValidEK(b.ek)) { "joiner used an encapsulation key that fails the FIPS 203 check" }
        // Spec 4: only identity keys must be canonical and of large order; EPK is an ephemeral key (its DH must not be all zero).
        invariant(SPIdentity.isValidPublic(b.idI)) { "joiner used an invalid inviter identity" }
        invariant(now <= b.expiresAtMs) { "joiner used an expired bundle" }
        invariant(h.hello.size == 2 + SPWire.HELLO_KEYS_LEN + 12 + SPWire.HCT_LEN + 1024 + 16) { "HELLO size ${h.hello.size}" }
    }
}
