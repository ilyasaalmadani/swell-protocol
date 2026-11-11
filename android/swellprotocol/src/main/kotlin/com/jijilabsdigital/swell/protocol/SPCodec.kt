package com.jijilabsdigital.swell.protocol

import java.io.ByteArrayOutputStream

// Spec 4 encoding: integers big-endian, `bytes` is `i32 length | data`, `str` is `bytes` holding UTF-8.

/** Writer. */
class SPOut {
    private val bos = ByteArrayOutputStream()
    fun u8(v: Int) = apply { bos.write(v and 0xFF) }
    fun i32(v: Int) = apply { bos.write(SP.be32(v)) }
    fun i64(v: Long) = apply { bos.write(SP.be64(v)) }
    fun raw(b: ByteArray) = apply { bos.write(b) }
    fun bytes(b: ByteArray) = apply { i32(b.size); bos.write(b) }
    fun str(s: String) = bytes(s.toByteArray(Charsets.UTF_8))
    fun done(): ByteArray = bos.toByteArray()
}

/** Reader. Every read is bounds-checked and fails with [SwellProtocolError.Format]; trailing bytes are an error ([end]). */
class SPIn(private val b: ByteArray) {
    private var pos = 0
    val remaining: Int get() = b.size - pos

    private fun need(n: Int) { if (n < 0 || n > remaining) throw SwellProtocolError.Format("short input") }
    fun u8(): Int { need(1); return b[pos++].toInt() and 0xFF }
    fun i32(): Int { need(4); var v = 0; repeat(4) { v = (v shl 8) or (b[pos++].toInt() and 0xFF) }; return v }
    fun i64(): Long { val hi = i32().toLong() and 0xFFFFFFFFL; val lo = i32().toLong() and 0xFFFFFFFFL; return (hi shl 32) or lo }
    fun raw(n: Int): ByteArray { need(n); return b.copyOfRange(pos, pos + n).also { pos += n } }
    fun bytes(max: Int): ByteArray {
        val n = i32()
        if (n < 0 || n > max) throw SwellProtocolError.Format("field size")
        return raw(n)
    }
    fun str(max: Int): String = String(bytes(max), Charsets.UTF_8)
    fun end() { if (remaining != 0) throw SwellProtocolError.Format("trailing bytes") }
}
