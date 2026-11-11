package com.jijilabsdigital.swell.protocol

import com.jijilabsdigital.swell.protocol.Vectors.b
import com.jijilabsdigital.swell.protocol.Vectors.hx
import com.jijilabsdigital.swell.protocol.Vectors.objects
import com.jijilabsdigital.swell.protocol.Vectors.strings
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The standard vectors of each primitive, every Swell vector of spec appendix A, and all ten shared vector files in
 * docs/protocol-vectors/ (spec 13), replayed byte for byte. The engine-level parts of invite, group-state, report and backup
 * (the codes' finder, the group state layout, the report body, the backup writer) are checked again in core's EngineVectorTest.
 */
class SPVectorTest {
    companion object {
        fun hex(s: String): ByteArray = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
        fun rep(b: Int, n: Int): ByteArray = ByteArray(n) { b.toByte() }
    }

    // ---- standard vectors --------------------------------------------------------------------------------------------------

    @Test fun rfc7748X25519() {
        val sk = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val pk = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        assertEquals("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", SP.dh(sk, pk).hex())
        // Section 6.1 key agreement.
        val a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", SP.x25519Public(a).hex())
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", SP.x25519Public(b).hex())
        val k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(k, SP.dh(a, SP.x25519Public(b)).hex())
        assertEquals(k, SP.dh(b, SP.x25519Public(a)).hex())
    }

    @Test fun allZeroDhRefused() {
        val sk = SP.x25519().sk
        assertFailsWith<SwellProtocolError.Crypto> { SP.dh(sk, ByteArray(32)) }
    }

    @Test fun rfc5869Case1() {
        val ikm = rep(0x0b, 22)
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            SP.hkdf(salt, ikm, info, 42).hex())
    }

    @Test fun aesGcmZeroKeyCases() {
        val key = ByteArray(32); val nonce = ByteArray(12)
        // McGrew and Viega test case 13 (empty) and 14 (one zero block).
        assertEquals("530f8afbc74536b9a963b4f1c4cb738b", SP.seal(key, nonce, ByteArray(0), ByteArray(0)).hex())
        assertEquals("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919", SP.seal(key, nonce, ByteArray(0), ByteArray(16)).hex())
        assertContentEquals(ByteArray(16), SP.open(key, nonce, ByteArray(0), hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")))
        assertFailsWith<SwellProtocolError.Crypto> { SP.open(key, nonce, byteArrayOf(1), hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")) }
    }

    @Test fun mlKem768Boundary() {
        val k = SP.kemGenerate()
        assertEquals(SP.KEM_EK_LEN, k.ek.size)
        assertEquals(SP.KEM_SEED_LEN, k.seed.size)
        assertContentEquals(k.ek, SP.kemPublic(k.seed)) // seed determinism
        val e = SP.kemEncapsulate(k.ek)
        assertEquals(SP.KEM_CT_LEN, e.ct.size)
        assertEquals(SP.KEM_SS_LEN, e.ss.size)
        assertContentEquals(e.ss, SP.kemDecapsulate(k.seed, e.ct))
        // Implicit rejection: a changed ciphertext decapsulates to a different, pseudo-random secret and does not throw.
        val bad = e.ct.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        val ss2 = SP.kemDecapsulate(k.seed, bad)
        assertEquals(32, ss2.size)
        assertFalse(ss2.contentEquals(e.ss))
        assertContentEquals(ss2, SP.kemDecapsulate(k.seed, bad)) // deterministic
        // An encapsulation key with a coefficient >= 3329 is refused (FIPS 203 modulus check); so is a wrong length.
        val invalid = k.ek.copyOf().also { it[0] = 0xFF.toByte(); it[1] = 0xFF.toByte() }
        assertFailsWith<SwellProtocolError.Crypto> { SP.kemEncapsulate(invalid) }
        assertFailsWith<SwellProtocolError.Format> { SP.kemEncapsulate(k.ek.copyOf(100)) }
        assertTrue(SP.kemValidEK(k.ek))
    }

    // ---- appendix A --------------------------------------------------------------------------------------------------------

    @Test fun a1a2a3() {
        assertEquals("5377656c6c000204726f6f74", SP.info("root").hex())
        assertEquals("5377656c6c00020a70712d6d657373616765000400000005", SP.info("pq-message", SP.be32(5)).hex())
        assertEquals("292e76d917b207cc9f3bd135f323609c7b110b321705a8f47012bc47b7fbaca6", SP.tagged("bundle", ByteArray(4)).hex())
    }

    @Test fun a4a5a6() {
        val r = SPSession.kdfRK(rep(1, 32), rep(2, 32))
        assertEquals("867d297231be8e1dd34dbd9ad0b6a6355b2feb9ab7f24e444c78779626ae69ba", r.rk.hex())
        assertEquals("f1ebe66a8309a8712f86f3b3e11891bb02087bce91b2ae4a0a084d9b76a082cf", r.ck.hex())
        assertEquals("80e4c12cadf0acdaa48a1765a63f9224a43f8a2ccfca60271c5c13eb3939224e", r.nhk.hex())
        val s = SPSession.kdfCK(rep(3, 32))
        assertEquals("70fc6d94291a0e4dbc5af3839301772646620faaeb2733d7d9f54b4e8c80c53f", s.ck.hex())
        assertEquals("d3d194ab575909331c94c2cf10090ec36b9daf94038bb5077b005a0a3ef2fa0e", s.mk.hex())
        val c = SPSession.combine(rep(4, 32), rep(5, 32), 1)
        assertEquals("c4cd9ed26fbd4c361a29c64fcc01604b1e043fc88939a44b0b610d7654e93cfb", c.key.hex())
        assertEquals("f50bc14935410b17ca9212da", c.nonce.hex())
    }

    @Test fun a7header() {
        val header = SPWire.Header(rep(7, 32), 1, 2, 3).encode()
        assertEquals(rep(7, 32).hex() + "00000001" + "00000002" + "00000003", header.hex())
        val hk = SPSession.headerKeys(rep(6, 32))
        assertEquals("036f00d2bd4b7cdeafe6e423fa85b7072545c6ead718d123d828a2bc61784197", hk.enc.hex())
        assertEquals("4ff5aa6aa18eaddb7fb90b3d4423f29a344c80555ccaac8e6e3e5218c552836d", hk.iv.hex())
        assertEquals("fb5351a08626fcca5d921060", SPSession.headerNonce(hk.iv, header).hex())
    }

    @Test fun a8handshake() {
        // Private keys 11*32 (id_I), 12*32 (epk), 13*32 (id_J), 14*32 (e); EK 15*1184, ct 16*1088, binding 17*32, ss_kem 18*32.
        val idI = SP.x25519Public(rep(0x11, 32)); val epk = SP.x25519Public(rep(0x12, 32))
        val idJ = SP.x25519Public(rep(0x13, 32)); val e = SP.x25519Public(rep(0x14, 32))
        val b = SPWire.Bundle(idI, epk, rep(0x15, SP.KEM_EK_LEN), 1_800_000_000_000L)
        assertEquals("932c74e147a28b35236af22ee822cbdb726722e70a0c539a6fc3b00ff5c6fcd9", b.commit.hex())
        val t = SPHandshake.transcript(b, idJ, e, rep(0x16, SP.KEM_CT_LEN), rep(0x17, 32))
        assertEquals("3490cc2321d9e8a39a7d55f84bf7a8e6999f005897d2fc1289baa776666befa0", t.hex())
        val dh1 = SP.dh(rep(0x13, 32), epk); val dh2 = SP.dh(rep(0x14, 32), idI); val dh3 = SP.dh(rep(0x14, 32), epk)
        // I's side computes the same three values from the other halves.
        assertContentEquals(dh1, SP.dh(rep(0x12, 32), idJ)); assertContentEquals(dh2, SP.dh(rep(0x11, 32), e)); assertContentEquals(dh3, SP.dh(rep(0x12, 32), e))
        val k = SPHandshake.keys(t, dh1, dh2, dh3, rep(0x18, 32))
        assertEquals("add2d1531c5d153e495c91787d6515ae641fb66ebe5a3e4756ce5ad431d14d9b", k.rk0.hex())
        assertEquals("90f60e5471d21011fd3c87e24fb813844066b59bbd88c9eab661fe84b9a15626", k.hka.hex())
        assertEquals("14a82ce5c49aa99ed7f2754d83ee99ceb5abf4a364ce0c82ff7c0090af1e0996", k.nhkb.hex())
        assertEquals("5fb047f9baae785bea365c7b296f73480e38c62a7497927f2bfb983bf0a644c6", k.pq0.hex())
    }

    @Test fun a9a10a11() {
        assertEquals("58fd84d676c909bec66b6998ace3d9659ccdc03c5d1f1f55d0e0df057929aeff",
            SPPQState.nextKey(rep(8, 32), rep(9, 32), 1, rep(0x0a, SP.KEM_EK_LEN), rep(0x0b, SP.KEM_CT_LEN)).hex())
        val idA = byteArrayOf(5) + rep(0x0d, 32); val idB = byteArrayOf(5) + rep(0x0e, 32)
        assertEquals("7bf5c11a10049b2be0d07b6acc141c7a41b32635176574b373e1ff51f57f96a0",
            SPHandshake.upgradeBinding(rep(0x0c, 16), idA, idB, rep(0x0f, 16)).hex())
        assertEquals("7bf5c11a10049b2be0d07b6acc141c7a41b32635176574b373e1ff51f57f96a0",
            SPHandshake.upgradeBinding(rep(0x0c, 16), idB, idA, rep(0x0f, 16)).hex()) // order of the two keys does not matter
        assertEquals("803464028e6feb306761fe119327684c7e93105265959a185d8326964b758a6088f0ac7eea029ac69efc7211cc6ea1d2fb928e35c03890896d7ae822",
            SPHandshake.safetyBytes(rep(0x0c, 32), rep(0x0d, 32)).hex())
        assertEquals("83374 87809 49736 81682 00861 99701 74092 18534 66860 61298 45872 90914",
            SPHandshake.safetyNumber(rep(0x0c, 32), rep(0x0d, 32)))
    }

    // ---- docs/protocol-vectors (all ten files) --------------------------------------------------------------------------

    @Test fun allTenFilesArePresent() {
        assertEquals(Vectors.FILES.sorted(), Vectors.dir.listFiles()!!.map(File::getName).filter { it.endsWith(".json") }.sorted())
    }

    @Test fun mlkem768Json() {
        val v = Vectors.load("mlkem768.json")
        val cases = v.getJSONArray("cases").objects()
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            val seed = c.b("seed")
            assertEquals(c.getString("ek"), SP.kemPublic(seed).hx(), "seed -> ek")
            assertTrue(SP.kemValidEK(c.b("ek")))
            assertEquals(c.getString("ss"), SP.kemDecapsulate(seed, c.b("ct")).hx(), "decapsulate")
            assertEquals(c.getString("tamperedSs"), SP.kemDecapsulate(seed, c.b("tamperedCt")).hx(), "implicit rejection")
            // The recorded encapsulation goes through the same boundary as a fresh one.
            val e = SP.withEntropy(Vectors.Replay(emptyList(), listOf(SP.KemEncapsulation(c.b("ct"), c.b("ss"))))) { SP.kemEncapsulate(c.b("ek")) }
            assertEquals(c.getString("ct"), e.ct.hx())
            // And a fresh BouncyCastle encapsulation to this ek opens with the CryptoKit-made key.
            val fresh = SP.kemEncapsulate(c.b("ek"))
            assertContentEquals(fresh.ss, SP.kemDecapsulate(seed, fresh.ct))
        }
        for (bad in v.getJSONArray("invalidEk").strings()) {
            assertFalse(SP.kemValidEK(Vectors.hex(bad)))
            assertFailsWith<SwellProtocolError> { SP.kemEncapsulate(Vectors.hex(bad)) }
        }
    }

    @Test fun identityJson() {
        val v = Vectors.load("identity.json")
        for (c in v.getJSONArray("derive").objects()) {
            val id = SPIdentity.derive(c.b("entropy"))
            assertEquals(c.getString("secret"), id.secret.hx())
            assertEquals(c.getString("public"), id.publicKey.hx())
            assertEquals(c.getString("serialized"), id.serialized.hx())
            assertTrue(SPIdentity.isValidPublic(id.publicKey))
            assertContentEquals(id.publicKey, SPIdentity.publicKey(id.serialized))
        }
        for (c in v.getJSONArray("invalidPublic").objects()) {
            val u = c.b("public")
            assertFalse(SPIdentity.isValidPublic(u), c.getString("why"))
            assertFailsWith<SwellProtocolError>(c.getString("why")) { SPIdentity.publicKey(byteArrayOf(5) + u) }
        }
        // The type byte must be 0x05 and the length 33.
        val good = SPIdentity.derive(ByteArray(16)).serialized
        assertFailsWith<SwellProtocolError> { SPIdentity.publicKey(good.copyOf().also { it[0] = 6 }) }
        assertFailsWith<SwellProtocolError> { SPIdentity.publicKey(good.copyOf(32)) }
    }

    @Test fun signatureJson() {
        val v = Vectors.load("signature.json")
        for (c in v.getJSONArray("edwardsMap").objects()) assertEquals(c.getString("edwards"), SPSignature.edwards(c.b("x25519")).hx())
        for (c in v.getJSONArray("sign").objects()) {
            val secret = c.b("secret")
            assertEquals(c.getString("public"), SP.x25519Public(secret).hx())
            val sig = SPSignature.sign(secret, c.getString("context"), c.b("message"))
            assertEquals(c.getString("signature"), sig.hx(), "deterministic signature")
            assertTrue(SPSignature.verify(c.b("public"), c.getString("context"), c.b("message"), sig))
            assertFalse(SPSignature.verify(c.b("public"), c.getString("context") + "x", c.b("message"), sig))
        }
        val pub = v.b("negativePublic"); val msg = v.b("negativeMessage")
        for (c in v.getJSONArray("negative").objects()) {
            assertFalse(SPSignature.verify(pub, SPSignature.GROUP_STATE_CONTEXT, msg, c.b("signature")), c.getString("why"))
        }
        // Strict rules (spec 5.2 steps 1 to 3): hostile signatures on which RFC 8032 verifiers can differ are all refused.
        val strict = v.getJSONArray("strict").objects()
        assertEquals(4, strict.size)
        for (c in strict) assertFalse(SPSignature.verify(c.b("public"), c.getString("context"), c.b("message"), c.b("signature")), c.getString("why"))
    }

    @Test fun kdfJson() {
        val v = Vectors.load("kdf.json")
        val seen = mutableSetOf<String>()
        for (it in v.getJSONArray("items").objects()) {
            val name = it.getString("name"); seen += name
            val i = it.getJSONObject("in"); val o = it.getJSONObject("out")
            when (name) {
                "Info" -> assertEquals(o.getString("info"), SP.info(i.getString("label"), *i.getJSONArray("fields").strings().map(Vectors::hex).toTypedArray()).hx())
                "SHA256Tagged" -> assertEquals(o.getString("hash"), SP.tagged(i.getString("tag"), i.b("data")).hx())
                "KDF_RK" -> {
                    val r = SPSession.kdfRK(i.b("rk"), i.b("dh"))
                    assertEquals(o.getString("rk"), r.rk.hx()); assertEquals(o.getString("ck"), r.ck.hx()); assertEquals(o.getString("nhk"), r.nhk.hx())
                }
                "KDF_CK" -> {
                    val r = SPSession.kdfCK(i.b("ck"))
                    assertEquals(o.getString("ck"), r.ck.hx()); assertEquals(o.getString("mk"), r.mk.hx())
                }
                "combine" -> {
                    val r = SPSession.combine(i.b("mkDR"), i.b("pq"), i.getInt("epoch"))
                    assertEquals(o.getString("key"), r.key.hx()); assertEquals(o.getString("nonce"), r.nonce.hx())
                }
                "header" -> {
                    val h = SPWire.Header(i.b("dhPub"), i.getInt("pn"), i.getInt("n"), i.getInt("epoch")).encode()
                    val k = SPSession.headerKeys(i.b("hk"))
                    assertEquals(o.getString("header"), h.hx()); assertEquals(o.getString("enc"), k.enc.hx()); assertEquals(o.getString("iv"), k.iv.hx())
                    assertEquals(o.getString("hnonce"), SPSession.headerNonce(k.iv, h).hx())
                }
                "handshake" -> {
                    val b = SPWire.Bundle(i.b("idI"), i.b("epk"), i.b("ek"), i.getLong("expiresAtMs"))
                    val t = SPHandshake.transcript(b, i.b("idJ"), i.b("e"), i.b("ct"), i.b("binding"))
                    val k = SPHandshake.keys(t, i.b("dh1"), i.b("dh2"), i.b("dh3"), i.b("ssKem"))
                    assertEquals(o.getString("bundleCommit"), b.commit.hx()); assertEquals(o.getString("T"), t.hx())
                    assertEquals(o.getString("RK0"), k.rk0.hx()); assertEquals(o.getString("sharedHka"), k.hka.hx())
                    assertEquals(o.getString("sharedNhkb"), k.nhkb.hx()); assertEquals(o.getString("PQ0"), k.pq0.hx())
                }
                "pq-epoch" -> assertEquals(o.getString("PQ1"), SPPQState.nextKey(i.b("prev"), i.b("ss"), i.getInt("target"), i.b("ek"), i.b("ct")).hx())
                "upgrade-binding" -> assertEquals(o.getString("binding"),
                    SPHandshake.upgradeBinding(i.b("channelId"), i.b("identityA"), i.b("identityB"), i.b("offerId")).hx())
                "direct-binding" -> assertEquals(o.getString("binding"), SPHandshake.directBinding(i.b("secret")).hx())
                "safety-32", "safety-33" -> {
                    assertEquals(o.getString("okm"), SPHandshake.safetyBytes(i.b("a"), i.b("b")).hx())
                    assertEquals(o.getString("digits"), SPHandshake.safetyNumber(i.b("a"), i.b("b")))
                    assertEquals(o.getString("digits"), SPHandshake.safetyNumber(i.b("b"), i.b("a")))
                    if (o.has("qr")) assertEquals(o.getString("qr"), SPHandshake.safetyQRText(i.b("a"), i.b("b")))
                }
                else -> error("unknown kdf item $name")
            }
        }
        assertEquals(setOf("Info", "SHA256Tagged", "KDF_RK", "KDF_CK", "combine", "header", "handshake", "pq-epoch", "upgrade-binding",
            "direct-binding", "safety-32", "safety-33"), seen)
    }

    @Test fun handshakeConversationJson() {
        val v = Vectors.load("handshake-conversation.json")
        val idI = SPIdentity.derive(v.getJSONObject("identityI").b("entropy"))
        val idJ = SPIdentity.derive(v.getJSONObject("identityJ").b("entropy"))
        assertEquals(v.getJSONObject("identityI").getString("serialized"), idI.serialized.hx())
        assertEquals(v.getJSONObject("identityJ").getString("serialized"), idJ.serialized.hx())
        val ent = v.getJSONObject("entropy")
        val entI = Vectors.Replay.of(ent.getJSONObject("I")); val entJ = Vectors.Replay.of(ent.getJSONObject("J"))
        val binding = v.b("binding"); val t0 = v.getLong("bundleNow")
        val secrets = SP.withEntropy(entI) { SPHandshake.makeBundle(idI.publicKey, v.getLong("expiresAtMs")) }
        assertEquals(v.getString("bundle"), secrets.bundle.encode().hx())
        assertEquals(v.getString("inviterEpkSecret"), secrets.epkSK.hx())
        assertEquals(v.getString("inviterKemSeed"), secrets.kemSeed.hx())

        val steps = v.getJSONArray("steps").objects()
        val hello0 = steps[0]
        assertEquals("hello", hello0.getString("op"))
        val h = SP.withEntropy(entJ) { SPHandshake.joinerStart(secrets.bundle, idI.publicKey, idJ, binding, hello0.b("inner"), hello0.getLong("now")) }
        assertEquals(hello0.getString("envelope"), h.hello.hx(), "HELLO envelope")
        assertEquals(hello0.getInt("bytes"), h.hello.size)
        val a = SP.withEntropy(entI) { SPHandshake.inviterAccept(secrets, idI, h.hello, binding, t0 + 500) }
        assertContentEquals(hello0.b("inner"), a.inner)
        assertContentEquals(idJ.publicKey, a.session.idPeer)
        assertEquals(v.getString("transcript"), a.session.transcript.hx())
        assertEquals(v.getString("sessionHash"), a.session.sessionHash.hx())
        assertContentEquals(a.session.transcript, h.session.transcript)

        val sess = mutableMapOf("I" to a.session, "J" to h.session)
        val ents = mapOf("I" to entI, "J" to entJ)
        val sent = mutableListOf("J" to h.hello)
        for ((n, st) in steps.withIndex().drop(1)) {
            when (st.getString("op")) {
                "send" -> {
                    val from = st.getString("from")
                    val r = SP.withEntropy(ents.getValue(from)) { sess.getValue(from).encrypt(st.b("inner"), st.getLong("now"), allowPQ = st.getBoolean("allowPQ")) }
                    sess[from] = r.session
                    assertEquals(st.getString("envelope"), r.envelope.hx(), "step $n: envelope")
                    assertEquals(st.getInt("bytes"), r.envelope.size, "step $n: size")
                    sent += from to r.envelope
                }
                "recv", "recvTampered" -> {
                    val to = st.getString("to")
                    var bytes = sent[st.getInt("send")].second
                    assertEquals(if (sent[st.getInt("send")].first == "I") "J" else "I", to)
                    if (st.optBoolean("flipLastByte")) bytes = bytes.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
                    if (st.getString("expect") == "ok") {
                        val r = SP.withEntropy(ents.getValue(to)) { sess.getValue(to).decrypt(bytes, st.getLong("now")) }
                        sess[to] = r.session
                        assertEquals(st.getString("inner"), r.inner.hx(), "step $n: plaintext")
                    } else {
                        assertFailsWith<SwellProtocolError>("step $n: ${st.getString("expect")}") {
                            SP.withEntropy(ents.getValue(to)) { sess.getValue(to).decrypt(bytes, st.getLong("now")) }
                        }
                    }
                }
                else -> error("unknown op")
            }
        }
        assertEquals(0, entI.left, "every recorded chunk of I was used")
        assertEquals(0, entJ.left, "every recorded chunk of J was used")
        assertContentEquals(sess.getValue("I").sessionHash, sess.getValue("J").sessionHash)
        assertEquals(2, sess.getValue("I").pq.epoch)
    }

    @Test fun linkJson() {
        val v = Vectors.load("link.json")
        val idI = SPIdentity.derive(v.getJSONObject("identityI").b("entropy"))
        val idJ = SPIdentity.derive(v.getJSONObject("identityJ").b("entropy"))
        val channel = v.b("channelId"); val sentAt = v.getLong("sentAtMs")
        assertEquals(v.getString("linkKey"), SPLink.key(idI, idJ.serialized, channel).hx())
        assertEquals(v.getString("linkKey"), SPLink.key(idJ, idI.serialized, channel).hx())
        val bi = v.getJSONObject("bundleInputs")
        val secrets = SP.withEntropy(Vectors.Replay(listOf(bi.b("epkSecret"), bi.b("kemSeed")))) { SPHandshake.makeBundle(idI.publicKey, bi.getLong("expiresAtMs")) }
        assertEquals(bi.getString("bundle"), secrets.bundle.encode().hx())
        val names = mutableListOf<String>()
        for (c in v.getJSONArray("frames").objects()) {
            names += c.getString("name")
            val (from, to) = if (c.getString("from") == "I") idI to idJ else idJ to idI
            val r = SPIn(c.b("frame")); assertEquals(SPUpgradeFrame.INNER_TYPE, r.u8())
            val frame = SPUpgradeFrame.decode(r); r.end()
            if (c.getString("name") == "offer") assertContentEquals(secrets.bundle.encode(), (frame as SPUpgradeFrame.Offer).bundle)
            val ct = SPLink.seal(frame, sentAt, from, to.serialized, channel, c.b("nonce"))
            assertEquals(c.getString("ciphertext"), ct.hx(), c.getString("name"))
            assertEquals(c.getInt("bytes"), ct.size)
            val opened = SPLink.open(ct, to, from.serialized, channel, sentAt + 5000)
            assertEquals(sentAt, opened.sentAtMs)
            assertContentEquals(c.b("frame"), opened.frame.encode())
            assertFailsWith<SwellProtocolError>("reflection") { SPLink.open(ct, from, to.serialized, channel, sentAt) }
            assertFailsWith<SwellProtocolError>("other channel") { SPLink.open(ct, to, from.serialized, Vectors.rep(0x0d, 16), sentAt) }
            assertFailsWith<SwellProtocolError>("too old") { SPLink.open(ct, to, from.serialized, channel, sentAt + 16L * 86_400_000) }
            assertFailsWith<SwellProtocolError>("too far ahead") { SPLink.open(ct, to, from.serialized, channel, sentAt - 2 * 3_600_000L) }
        }
        assertEquals(listOf("offer", "hello", "reset", "sync"), names)
    }

    @Test fun inviteJson() {
        val v = Vectors.load("invite.json")
        val inviter = SPIdentity.derive(v.getJSONObject("inviter").b("entropy"))
        val joiner = SPIdentity.derive(v.getJSONObject("joiner").b("entropy"))
        assertEquals(v.getJSONObject("inviter").getString("serialized"), inviter.serialized.hx())
        assertEquals(v.getJSONObject("joiner").getString("serialized"), joiner.serialized.hx())
        // Codes 5 and 6.
        val j5 = v.getJSONObject("v5"); val j6 = v.getJSONObject("v6")
        val v5 = SPInvite.Mailbox(j5.getString("mailboxOnion"), j5.b("queueId"), j5.b("sealKey"), inviter.serialized)
        val v6 = SPInvite.Direct(j6.getString("onion"), j6.b("secret"), inviter.serialized, j6.b("authKey"))
        assertEquals(j5.getString("payload"), v5.payload().hx()); assertEquals(j5.getString("code"), v5.encode())
        assertEquals(j6.getString("payload"), v6.payload().hx()); assertEquals(j6.getString("code"), v6.encode())
        assertEquals(6 + 216, v5.encode().length); assertEquals(6 + 216, v6.encode().length)
        assertEquals(j5.getString("binding"), v5.binding.hx()); assertEquals(j6.getString("binding"), v6.binding.hx())
        for (code in listOf(v5.encode(), v6.encode())) {
            val d = SPInvite.decode(code)
            assertEquals(code, d.encode())
            assertEquals(code, SPInvite.parse("Join me on Swell:\n${SPInvite.LINK_PREFIX}${code}\nsee you").encode())
            assertEquals(code, SPInvite.parse("  $code  ").encode())
        }
        assertTrue(SPInvite.decode(v5.encode()) is SPInvite.Mailbox)
        assertTrue(SPInvite.decode(v6.encode()) is SPInvite.Direct)
        // Refused codes.
        for (c in v.getJSONArray("refused").objects()) {
            val why = c.getString("why")
            val e = assertFailsWith<SPInvite.Refused>(why) { SPInvite.decode(c.getString("code")) }
            if (c.has("message")) {
                assertEquals(c.getString("message"), e.message, why)
                assertTrue(e.olderVersion)
                assertEquals(c.getString("message"), assertFailsWith<SPInvite.Refused>(why) { SPInvite.parse(c.getString("code")) }.message)
            }
            if (c.getBoolean("textFinderRefuses")) assertFailsWith<SPInvite.Refused>(why) { SPInvite.parse(c.getString("code")) }
            else assertEquals(v5.encode(), SPInvite.parse(c.getString("code")).encode(), why)
        }
        // A code with an invalid identity key parses, but the key is refused before anything is sent (spec 5.1).
        val bad = SPInvite.decode(v.getString("badIdentity"))
        assertFalse(SPIdentity.isValidSerialized(bad.identityKey))
        // The bundle: epk_sk, then the ML-KEM seed.
        val jb = v.getJSONObject("bundle")
        val ent = jb.getJSONArray("entropy").strings().map(Vectors::hex)
        val secrets = SP.withEntropy(Vectors.Replay(ent)) { SPHandshake.makeBundle(inviter.publicKey, jb.getLong("expiresAtMs")) }
        val bundle = secrets.bundle.encode()
        assertEquals(jb.getString("bundle"), bundle.hx())
        assertEquals(1257, bundle.size)
        // Version 5: the sealed bundle envelope in the invite queue.
        val js = v.getJSONObject("sealedBundle")
        val sealed = v5.seal(bundle, js.b("nonce"))
        assertEquals(js.getString("sealed"), sealed.hx())
        assertEquals(js.getString("envelope"), SPInvite.bundleEnvelope(sealed).hx())
        assertContentEquals(bundle, v5.open(SPInvite.sealedBundle(js.b("envelope"))))
        // Version 6: GET_BUNDLE and its answer.
        val jg = v.getJSONObject("getBundle")
        assertEquals(jg.getString("request"), SPOut().u8(2).u8(1).raw(v6.secret).done().hx())
        assertEquals(jg.getString("answer"), SPOut().u8(0x81).bytes(bundle).done().hx())
        // HELLO of each version.
        val inner = v.getJSONObject("innerHello").b("bytes")
        val now = 1_800_000_000_000L
        for (c in v.getJSONArray("hello").objects()) {
            val version = c.getInt("version")
            val (binding, frameSecret) = if (version == 5) v5.binding to v5.sealKey else v6.binding to v6.secret
            assertEquals(c.getString("binding"), binding.hx())
            val replay = Vectors.Replay(c.getJSONArray("entropy").strings().map(Vectors::hex),
                listOf(SP.KemEncapsulation(c.getJSONObject("kem").b("ct"), c.getJSONObject("kem").b("ss"))))
            val h = SP.withEntropy(replay) { SPHandshake.joinerStart(secrets.bundle, inviter.publicKey, joiner, binding, inner, now) }
            assertEquals(0, replay.left)
            assertEquals(c.getString("helloEnvelope"), h.hello.hx(), "HELLO $version")
            assertEquals(c.getString("frame"), SPInvite.helloFrame(frameSecret, c.b("channelId"), h.hello).hx())
            val a = SPHandshake.inviterAccept(secrets, inviter, h.hello, binding, now)
            assertContentEquals(inner, a.inner)
            assertContentEquals(joiner.serialized, a.session.peerIdentity)
            assertContentEquals(joiner.serialized, SPHandshake.helloIdentity(h.hello))
            assertFailsWith<SwellProtocolError> { SPHandshake.inviterAccept(secrets, inviter, h.hello, Vectors.rep(0xEE, 32), now) }
            // J refuses a bundle that names another identity than the invite.
            assertFailsWith<SwellProtocolError.Crypto> { SPHandshake.joinerStart(secrets.bundle, joiner.publicKey, joiner, binding, inner, now) }
        }
        // MSG frames (spec 5.6).
        for (c in v.getJSONArray("msg").objects()) {
            assertTrue(c.getInt("type") == SPWire.CT_DATA || c.getInt("type") == SPWire.CT_LINK)
            assertEquals(c.getString("frame"), SPInvite.msgFrame(c.b("channelId"), c.getInt("type"), c.b("ciphertext")).hx())
        }
    }

    @Test fun groupStateJson() {
        // The protocol part of spec 18: SwellSig over the state bytes. The state layout itself is checked in core (EngineVectorTest).
        val v = Vectors.load("group-state.json")
        val members = v.getJSONArray("members").objects()
        val ids = members.map { SPIdentity.derive(it.b("entropy")) }
        for ((m, id) in members.zip(ids)) assertEquals(m.getString("serialized"), id.serialized.hx())
        val ctx = v.getString("context")
        assertEquals(SPSignature.GROUP_STATE_CONTEXT, ctx)
        val creator = ids[0]
        for (k in listOf("v1", "v2")) {
            val s = v.getJSONObject(k)
            val state = s.b("state")
            assertEquals(s.getString("stateHash"), SP.sha256(state).hx())
            assertEquals(s.getString("signer"), creator.serialized.hx())
            assertEquals(s.getString("signature"), SPSignature.sign(creator.secret, ctx, state).hx(), "$k signature")
            assertTrue(SPSignature.verifySerialized(creator.serialized, ctx, state, s.b("signature")))
            assertEquals(s.getString("signed"), SPOut().bytes(state).bytes(creator.serialized).bytes(s.b("signature")).done().hx())
        }
        // v2 names v1's hash as previousHash (after u8 1, raw16 id, i64 version).
        assertEquals(v.getJSONObject("v1").getString("stateHash"), v.getJSONObject("v2").b("state").copyOfRange(25, 57).hx())
        for (c in v.getJSONArray("invalid").objects()) {
            assertFalse(SPSignature.verifySerialized(c.b("signer"), ctx, c.b("state"), c.b("signature")), c.getString("why"))
        }
    }

    @Test fun reportJson() {
        val v = Vectors.load("report.json")
        val inboxPublic = SP.x25519Public(v.b("inboxSecret"))
        assertEquals(v.getString("inboxPublic"), inboxPublic.hx())
        val parts = v.getString("inbox").split(":")
        assertEquals(56, parts[0].length); assertEquals(64, parts[1].length); assertEquals(v.getString("inboxPublic"), parts[2])
        assertEquals(v.getString("ephPublic"), SP.x25519Public(v.b("ephSecret")).hx())
        val shared = SP.dh(v.b("ephSecret"), inboxPublic)
        assertEquals(v.getString("shared"), shared.hx())
        assertEquals(v.getString("key"), SPReport.key(shared, v.b("ephPublic"), inboxPublic).hx())
        val env = SPReport.seal(inboxPublic, v.b("body"), v.b("ephSecret"), v.b("nonce"))
        assertEquals(v.getString("envelope"), env.hx())
        assertContentEquals(v.b("body"), SPReport.open(v.b("inboxSecret"), v.b("envelope")))
        assertFailsWith<SwellProtocolError> { SPReport.open(v.b("inboxSecret"), v.b("tamperedEnvelope")) }
        // The body names the reported identity key (33 bytes) after u8 1, i64 now, str reason.
        val r = SPIn(v.b("body")); assertEquals(1, r.u8()); r.i64(); r.str(2000)
        assertEquals(v.getString("reportedIdentity"), r.bytes(64).hx())
        assertTrue(v.getString("body").startsWith(v.getString("bodyWithoutQueue")))
        // What a phone sends: the body padded to a bucket, sealed with the same key and nonce (spec 19).
        assertEquals(v.getString("padded"), SPWire.padRaw(v.b("body")).hx())
        assertEquals(v.getString("envelopePadded"), SPReport.seal(inboxPublic, v.b("padded"), v.b("ephSecret"), v.b("nonce")).hx())
        assertContentEquals(v.b("body"), SPWire.unpadRaw(SPReport.open(v.b("inboxSecret"), v.b("envelopePadded"))))
    }

    @Test fun backupJson() {
        val v = Vectors.load("backup.json")
        val entropy = v.b("entropy"); val salt = v.b("salt")
        assertEquals(v.getString("identityKey"), SPIdentity.derive(entropy).serialized.hx())
        val key = SPBackupFormat.key(entropy, salt)
        assertEquals(v.getString("key"), key.hx())
        assertEquals(v.getString("nonce0"), SPBackupFormat.nonce(0).hx()); assertEquals(v.getString("nonce1"), SPBackupFormat.nonce(1).hx())
        val header = SPBackupFormat.header(salt)
        assertEquals(v.getString("adChunk0Last"), SPBackupFormat.authenticated(header, 0, true).hx())
        assertEquals(v.getString("adChunk1NotLast"), SPBackupFormat.authenticated(header, 1, false).hx())
        val plain = v.b("plaintext")
        val file = header + SPBackupFormat.sealChunk(key, header, 0, true, plain)
        assertEquals(v.getString("file"), file.hx())
        val sealed = file.copyOfRange(SPBackupFormat.HEADER_LEN + 5, file.size)
        assertContentEquals(plain, SPBackupFormat.openChunk(key, header, 0, true, sealed))
        assertFailsWith<SwellProtocolError> { SPBackupFormat.openChunk(key, header, 0, false, sealed) } // the last flag is bound
        assertFailsWith<SwellProtocolError> { SPBackupFormat.openChunk(SPBackupFormat.key(Vectors.rep(0x54, 16), salt), header, 0, true, sealed) }
        // The stream starts with the account item: u8 1 | bytes identityKey; it holds no session.
        val r = SPIn(plain); assertEquals(1, r.u8()); assertEquals(v.getString("identityKey"), r.bytes(64).hx())
    }
}
