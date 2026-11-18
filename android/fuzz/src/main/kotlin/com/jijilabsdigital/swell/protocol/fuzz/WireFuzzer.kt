// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPHandshake
import com.jijilabsdigital.swell.protocol.SPIdentity
import com.jijilabsdigital.swell.protocol.SPIn
import com.jijilabsdigital.swell.protocol.SPInvite
import com.jijilabsdigital.swell.protocol.SPInviterSecrets
import com.jijilabsdigital.swell.protocol.SPUpgradeFrame
import com.jijilabsdigital.swell.protocol.SPWire

/**
 * The wire decoders an attacker reaches before any key is involved (spec 5.3, 5.5, 6.4, 7.3 to 7.6): envelope, header plaintext,
 * padding and PQ field, bundle, upgrade (link) frame, inviter secrets record, the clear HELLO identity and the invite queue envelope.
 * Every accepted input must re-encode to exactly the bytes it came from (the decoders are strict inverses of the encoders).
 * The first byte picks the decoder, the rest is its input.
 */
object WireFuzzer {
    private fun padTo(content: ByteArray, size: Int): ByteArray = SP.be32(content.size) + content + ByteArray(size - 4 - content.size)

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        if (data.isEmpty()) return
        val b = data.copyOfRange(1, data.size)
        when ((data[0].toInt() and 0xFF) % 9) {
            0 -> refusedOrValue { SPWire.Envelope.decode(b) }?.let { e ->
                invariant(e.encode().contentEquals(b)) { "envelope does not re-encode" }
                invariant(e.kind == SPWire.KIND_DATA || e.kind == SPWire.KIND_HELLO) { "envelope kind ${e.kind}" }
                invariant(e.hnonce.size == 12 && e.hct.size == SPWire.HCT_LEN) { "envelope field sizes" }
            }
            1 -> refusedOrValue { SPWire.Header.decode(b) }?.let { h ->
                invariant(h.encode().contentEquals(b)) { "header does not re-encode" }
                invariant(h.pn >= 0 && h.n >= 0 && h.epoch >= 0) { "negative header counter accepted" }
            }
            // Spec 7.4 lets a receiver accept a larger bucket than the smallest one (only the sender must pick the smallest), so the
            // inverse is checked at the size of the input.
            2 -> refusedOrValue { SPWire.unpad(b) }?.let { u ->
                invariant(padTo(u.pq.encode() + u.inner, b.size).contentEquals(b)) { "unpad is not the inverse of pad" }
                invariant(SPWire.bucket(4 + u.pq.encode().size + u.inner.size)!! <= b.size) { "content larger than its bucket" }
            }
            3 -> refusedOrValue { SPWire.unpadRaw(b) }?.let { c ->
                invariant(padTo(c, b.size).contentEquals(b)) { "unpadRaw is not the inverse of padRaw" }
                if (SPWire.bucket(4 + c.size) == b.size) invariant(SPWire.padRaw(c).contentEquals(b)) { "padRaw differs at the smallest bucket" }
            }
            4 -> refusedOrValue { SPWire.Bundle.decode(b) }?.let { x ->
                invariant(x.encode().contentEquals(b)) { "bundle does not re-encode" }
            }
            5 -> {
                val r = SPIn(b)
                refusedOrValue { SPUpgradeFrame.decode(r) }?.let { f ->
                    val used = b.size - r.remaining
                    val enc = f.encode()
                    // encode() starts with the inner type byte (26), decode() reads after it.
                    invariant(enc[0].toInt() == SPUpgradeFrame.INNER_TYPE && enc.copyOfRange(1, enc.size).contentEquals(b.copyOfRange(0, used))) {
                        "upgrade frame does not re-encode"
                    }
                }
            }
            6 -> refusedOrValue { SPInviterSecrets.decode(b) }?.let { s ->
                invariant(s.encode().contentEquals(b)) { "inviter secrets do not re-encode" }
            }
            7 -> SPHandshake.helloIdentity(b)?.let { id ->
                invariant(id.size == SPIdentity.SERIALIZED_LEN && id[0] == SPIdentity.TYPE_BYTE) { "hello identity form" }
                invariant(id.copyOfRange(1, 33).contentEquals(b.copyOfRange(2, 34))) { "hello identity bytes" }
                // Validity is the caller's job; it must never throw.
                SPIdentity.isValidSerialized(id)
            }
            else -> refusedOrValue { SPInvite.sealedBundle(b) }?.let { sealed ->
                invariant(sealed.size <= 80 * 1024) { "sealed bundle over its limit" }
            }
        }
    }
}
