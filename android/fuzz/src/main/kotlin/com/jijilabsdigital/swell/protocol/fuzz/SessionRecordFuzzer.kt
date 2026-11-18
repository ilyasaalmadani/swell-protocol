// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPSession

/**
 * The stored session record (record version 3: ratchet state, skipped keys and PQ state). A record comes from the phone's own
 * database, but a damaged or restored one must still be refused in an orderly way, never crash the app later. A record that decodes
 * must re-encode to a record that decodes to the same bytes, and every operation on the decoded state (send, receive of a real and
 * of a garbage envelope, PQ repeat) may refuse only with a SwellProtocolError.
 */
object SessionRecordFuzzer {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        if (data.isEmpty()) return
        val mode = data[0].toInt() and 0xFF
        val record = data.copyOfRange(1, data.size)
        val s = refusedOrValue { SPSession.decode(record) } ?: return
        val e1 = s.encode()
        val again = SPSession.decode(e1)
        invariant(again.encode().contentEquals(e1)) { "decoded record does not re-encode stably" }
        // Booleans are the only fields with more than one accepted encoding (any byte other than 1 reads as false).
        invariant(e1.size == record.size) { "re-encoded record has another length" }

        SP.withEntropy(DetEntropy.of("record", byteArrayOf(mode.toByte()))) {
            val now = Fixtures.BUNDLE_NOW + 50_000
            refusedOrValue { s.encrypt("x".toByteArray(), now, allowPQ = (mode and 1) == 1) }?.let { r ->
                refusedOrValue { SPSession.decode(r.session.encode()) }
                    ?: throw FuzzFinding("state after a send does not reload")
            }
            val ex = Fixtures.exchange
            val envelope = when ((mode shr 1) % 3) {
                0 -> ex.toJ[ex.toJ.size - 1]
                1 -> ex.toI[ex.toI.size - 1]
                else -> ex.toJ[0]
            }
            refusedOrValue { s.decrypt(envelope, now) }?.let { r ->
                refusedOrValue { SPSession.decode(r.session.encode()) }
                    ?: throw FuzzFinding("state after a receive does not reload")
            }
            s.withPQRepeatOwed()
            s.sessionHash
            s.safetyNumber
        }
    }
}
