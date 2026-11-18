// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import com.jijilabsdigital.swell.protocol.SP
import com.jijilabsdigital.swell.protocol.SPOut
import com.jijilabsdigital.swell.protocol.SPWire
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * Writes one seed directory per target from the shared vectors (docs/protocol-vectors) and the fixture states.
 * Usage: SeedCorpus <protocol-vectors dir> <output dir>. Each seed is a complete fuzz input (mode byte included).
 */
object SeedCorpus {
    private lateinit var out: File

    private fun put(target: String, bytes: ByteArray) {
        val d = File(out, target).also { it.mkdirs() }
        val name = MessageDigest.getInstance("SHA-1").digest(bytes).joinToString("") { "%02x".format(it) }
        File(d, name).writeBytes(bytes)
    }

    private fun JSONObject.h(k: String): ByteArray = hex(getString(k))
    private fun JSONArray.objs(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
    private fun u16(n: Int) = byteArrayOf((n shr 8).toByte(), n.toByte())
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @JvmStatic
    fun main(args: Array<String>) {
        val vec = File(args[0]); out = File(args[1])
        out.deleteRecursively()
        fun load(n: String) = JSONObject(File(vec, n).readText())
        val conv = load("handshake-conversation.json"); val link = load("link.json"); val invite = load("invite.json")
        val sig = load("signature.json"); val group = load("group-state.json"); val report = load("report.json"); val kdf = load("kdf.json")

        // ---- WireFuzzer ----------------------------------------------------------------------------------------------------
        val envelopes = conv.getJSONArray("steps").objs().filter { it.has("envelope") }.map { it.h("envelope") }
        envelopes.forEach { put("WireFuzzer", b(0) + it) }
        kdf.getJSONArray("items").objs().filter { it.getString("name") == "header" }.forEach { put("WireFuzzer", b(1) + it.getJSONObject("out").h("header")) }
        put("WireFuzzer", b(2) + SPWire.pad(SPWire.PQField.None, "hi".toByteArray()))
        put("WireFuzzer", b(2) + SPWire.pad(SPWire.PQField.Ek(1, Fixtures.secrets.bundle.ek), "x".toByteArray()))
        put("WireFuzzer", b(2) + SPWire.pad(SPWire.PQField.Ct(2, ByteArray(SP.KEM_CT_LEN) { 7 }), ByteArray(0)))
        put("WireFuzzer", b(3) + report.h("padded"))
        put("WireFuzzer", b(4) + conv.h("bundle"))
        put("WireFuzzer", b(4) + invite.getJSONObject("bundle").h("bundle"))
        link.getJSONArray("frames").objs().forEach { put("WireFuzzer", b(5) + it.h("frame").copyOfRange(1, it.h("frame").size)) }
        put("WireFuzzer", b(6) + Fixtures.secrets.encode())
        put("WireFuzzer", b(7) + envelopes[0])
        put("WireFuzzer", b(8) + invite.getJSONObject("sealedBundle").h("envelope"))

        // ---- CodecFuzzer ---------------------------------------------------------------------------------------------------
        put("CodecFuzzer", b(0) + u16(6) + b(0, 1, 2, 4 + 7 * 8, 5, 6) + report.h("body"))
        put("CodecFuzzer", b(0) + u16(3) + b(4 + 7 * 40, 4 + 7 * 40, 6) + Fixtures.secrets.encode().copyOf(200))
        put("CodecFuzzer", b(1, 0, 7, 1, 0, 0, 1, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 4, 0, 3, 0x61, 0x62, 0x63, 3, 0, 2, 9, 9))

        // ---- HandshakeFuzzer -----------------------------------------------------------------------------------------------
        put("HandshakeFuzzer", b(0) + envelopes[0])
        put("HandshakeFuzzer", b(0) + Fixtures.hello)
        put("HandshakeFuzzer", b(1) + ByteArray(16) { 0x22 } + u16(5) + "hello".toByteArray() + u16(1) + ByteArray(16) + b(0xA5, 0, 0, 0))
        put("HandshakeFuzzer", b(1) + ByteArray(16) { 0x44 } + u16(0) + u16(500) + ByteArray(16) { 1 } + b(0x00, 0, 7, 3))
        put("HandshakeFuzzer", b(2) + SP.be64(Fixtures.BUNDLE_NOW) + conv.h("bundle"))
        put("HandshakeFuzzer", b(2) + SP.be64(1_799_999_000_000L) + invite.getJSONObject("bundle").h("bundle"))

        // ---- RatchetFuzzer: short programs (policy, start, entropy seed, then ops) ----------------------------------------------
        val send = { side: Int, msg: String, pq: Int -> b(0, side, 0x40) + u16(msg.length) + msg.toByteArray() + b(pq) }
        val deliver = { idx: Int -> b(2, idx, 0x80, 0, 0, 0) }
        val programs = listOf(
            b(0, 0) + ByteArray(8) + send(0, "a", 1) + deliver(0) + send(1, "b", 1) + deliver(1) + send(0, "c", 1) + deliver(2),
            b(1, 0) + ByteArray(8) { 1 } + send(0, "a", 1) + send(0, "b", 1) + deliver(1) + deliver(0) + send(1, "c", 1) + deliver(2) + b(6, 0) + b(6, 1),
            b(1, 1) + ByteArray(8) { 2 } + deliver(1) + deliver(0) + send(1, "x", 1) + deliver(2) + b(5, 0x40, 0) + send(0, "y", 1) + deliver(3),
            b(0, 1) + ByteArray(8) { 3 } + deliver(0) + b(4, 0, 0x80) + ByteArray(40) + send(1, "z", 0) + b(7, 1) + send(1, "w", 1),
            b(1, 0) + ByteArray(8) { 4 } + (0 until 6).fold(ByteArray(0)) { acc, k -> acc + send(k and 1, "m$k", 1) + deliver(k) },
        )
        programs.forEach { put("RatchetFuzzer", it) }

        // ---- SessionRecordFuzzer -------------------------------------------------------------------------------------------
        val (i0, j0) = Fixtures.start
        val ex = Fixtures.exchange
        for ((k, s) in listOf(i0, j0, ex.iState, ex.jState).withIndex()) put("SessionRecordFuzzer", b(k) + s.encode())

        // ---- SignatureFuzzer: u8 mode | bool serialized | key | u16 len | signature | bool | message ---------------------------
        fun ctxMode(c: String) = when (c) { "swell-group-state-v1" -> 0; "test" -> 2; else -> 4 }
        for (c in sig.getJSONArray("sign").objs()) {
            val s = c.h("signature")
            put("SignatureFuzzer", b(ctxMode(c.getString("context")), 0) + c.h("public") + u16(64) + s + b(1) + c.h("message"))
            put("SignatureFuzzer", b(ctxMode(c.getString("context")) or 1) + c.h("secret") + c.h("message"))
        }
        for (c in sig.getJSONArray("negative").objs()) put("SignatureFuzzer", b(0, 0) + sig.h("negativePublic") + u16(c.h("signature").size) + c.h("signature") + b(0) + sig.h("negativeMessage"))
        for (c in sig.getJSONArray("strict").objs()) put("SignatureFuzzer", b(ctxMode(c.getString("context")), 0) + c.h("public") + u16(64) + c.h("signature") + b(1) + c.h("message"))
        for (k in listOf("v1", "v2")) {
            val s = group.getJSONObject(k)
            put("SignatureFuzzer", b(0, 1) + s.h("signer") + u16(64) + s.h("signature") + b(1) + s.h("state"))
        }
        for (c in group.getJSONArray("invalid").objs()) {
            val signer = c.h("signer").copyOf(33)
            put("SignatureFuzzer", b(0, 1) + signer + u16(c.h("signature").size) + c.h("signature") + b(0) + c.h("state"))
        }

        // ---- InviteFuzzer --------------------------------------------------------------------------------------------------
        val codes = listOf(invite.getJSONObject("v5").getString("code"), invite.getJSONObject("v6").getString("code"))
        for (c in codes) {
            put("InviteFuzzer", b(0) + c.toByteArray())
            put("InviteFuzzer", b(1) + "Join me on Swell:\nhttps://jijilabsdigital.com/swell/i#$c\nsee you".toByteArray())
            put("InviteFuzzer", b(2) + c.removePrefix("swell:").toByteArray())
            put("InviteFuzzer", b(3) + c.toByteArray())
        }
        for (c in invite.getJSONArray("refused").objs()) {
            put("InviteFuzzer", b(0) + c.getString("code").toByteArray())
            put("InviteFuzzer", b(1) + c.getString("code").toByteArray())
        }
        put("InviteFuzzer", b(0) + invite.getString("badIdentity").toByteArray())

        // ---- LinkFuzzer ----------------------------------------------------------------------------------------------------
        for (c in link.getJSONArray("frames").objs()) {
            put("LinkFuzzer", b(0) + c.h("ciphertext"))
            put("LinkFuzzer", b(1) + c.h("nonce") + SP.be32(0) + b(1) + u16(c.h("frame").size) + c.h("frame"))
            put("LinkFuzzer", b(2) + hex(link.getJSONObject("identityI").getString("serialized")) + c.h("ciphertext"))
        }
        put("LinkFuzzer", b(3) + report.h("envelope"))
        put("LinkFuzzer", b(3) + report.h("envelopePadded"))
        put("LinkFuzzer", b(4) + report.h("ephSecret") + report.h("nonce") + report.h("body"))
        put("LinkFuzzer", b(5) + invite.getJSONObject("sealedBundle").h("envelope"))
        put("LinkFuzzer", b(1) + ByteArray(12) + SP.be32(0) + b(1) + SPOut().u8(26).u8(4).done().let { u16(it.size) + it })

        for (d in out.listFiles()!!.sorted()) println("${d.name}: ${d.listFiles()!!.size} seeds")
    }
}
