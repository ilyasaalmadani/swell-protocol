// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SPInvite
import com.jijilabsdigital.swell.protocol.SwellProtocolError

/**
 * Invite codes (spec 5.4): the strict code decoder, the text finder that reads a code out of any pasted text or link, and the strict
 * base64url reader. An accepted code is canonical (it re-encodes to the same text); the text finder only ever returns a code the strict
 * decoder accepts; base64url accepts only canonical text. Refusals are SPInvite.Refused (codes) or SwellProtocolError (base64).
 */
object InviteFuzzer {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        if (data.isEmpty()) return
        val text = String(data, 1, data.size - 1, Charsets.UTF_8)
        when ((data[0].toInt() and 0xFF) % 4) {
            0 -> try {
                val c = SPInvite.decode(text)
                invariant(c.encode() == text.trim()) { "accepted a non-canonical code" }
                invariant(c.identityKey.size == 33) { "identity key size" }
                invariant(c.binding.size == 32) { "binding size" }
            } catch (e: SPInvite.Refused) {
                invariant(e.message == SPInvite.NOT_A_CODE || (e.olderVersion && e.message == SPInvite.OLDER_VERSION_MESSAGE)) { "refusal text" }
            }
            1 -> try {
                val c = SPInvite.parse(text)
                val code = c.encode()
                invariant(SPInvite.decode(code).encode() == code) { "text finder returned a code the decoder refuses" }
            } catch (e: SPInvite.Refused) {
            }
            2 -> try {
                val b = SPInvite.unb64(text)
                invariant(SPInvite.b64(b) == text) { "accepted non-canonical base64url" }
            } catch (e: SwellProtocolError) {
                invariant(e is SwellProtocolError.Format) { "base64 refusal kind" }
            }
            else -> {
                val v = SPInvite.versionOf(text)
                invariant(v in -1..255) { "version out of range" }
            }
        }
    }
}
