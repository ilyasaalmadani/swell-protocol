// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SPIn
import com.jijilabsdigital.swell.protocol.SPOut
import com.jijilabsdigital.swell.protocol.SwellProtocolError

/**
 * The length-prefixed codec of spec 4 (SPIn / SPOut: big-endian integers, `i32 length | data` fields, strict end).
 * Mode 0 reads hostile bytes with a fuzzer-chosen sequence of reads: only SwellProtocolError.Format may come out, and a field is
 * never longer than its maximum or than the input. Mode 1 writes fuzzer-chosen values and must read back exactly the same values.
 */
object CodecFuzzer {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val f = FuzzIn(data)
        if (f.bool()) roundTrip(f) else hostile(f)
    }

    private fun hostile(f: FuzzIn) {
        val ops = f.chunk(64)
        val input = f.rest()
        val r = SPIn(input)
        try {
            for (op in ops) {
                val before = r.remaining
                when ((op.toInt() and 0xFF) % 7) {
                    0 -> r.u8()
                    1 -> r.i32()
                    2 -> r.i64()
                    3 -> { val n = (op.toInt() and 0xFF) shr 3; invariant(r.raw(n).size == n) { "raw size" } }
                    4 -> { val max = ((op.toInt() and 0xFF) shr 3) * 97; val v = r.bytes(max); invariant(v.size <= max) { "bytes over max" } }
                    5 -> r.str(1 shl 20)
                    else -> r.end()
                }
                invariant(r.remaining in 0..before) { "reader moved backward or past the end" }
            }
        } catch (e: SwellProtocolError) {
            invariant(e is SwellProtocolError.Format) { "codec threw ${e::class.simpleName}" }
        }
    }

    private sealed class V {
        class U8(val v: Int) : V()
        class I32(val v: Int) : V()
        class I64(val v: Long) : V()
        class Raw(val v: ByteArray) : V()
        class Bytes(val v: ByteArray) : V()
    }

    private fun roundTrip(f: FuzzIn) {
        val values = ArrayList<V>()
        val o = SPOut()
        while (f.left > 0 && values.size < 64) {
            val v = when (f.u8() % 5) {
                0 -> V.U8(f.u8())
                1 -> V.I32(f.i32())
                2 -> V.I64(f.i64())
                3 -> V.Raw(f.chunk(300))
                else -> V.Bytes(f.chunk(300))
            }
            values += v
            when (v) {
                is V.U8 -> o.u8(v.v)
                is V.I32 -> o.i32(v.v)
                is V.I64 -> o.i64(v.v)
                is V.Raw -> o.raw(v.v)
                is V.Bytes -> o.bytes(v.v)
            }
        }
        val r = SPIn(o.done())
        for (v in values) {
            when (v) {
                is V.U8 -> invariant(r.u8() == v.v) { "u8" }
                is V.I32 -> invariant(r.i32() == v.v) { "i32" }
                is V.I64 -> invariant(r.i64() == v.v) { "i64" }
                is V.Raw -> invariant(r.raw(v.v.size).contentEquals(v.v)) { "raw" }
                is V.Bytes -> invariant(r.bytes(300).contentEquals(v.v)) { "bytes" }
            }
        }
        r.end()
    }
}
