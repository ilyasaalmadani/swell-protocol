// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

import java.util.Base64

// Swell Protocol draft 3, spec sections 5.3 (bundle), 6 (handshake), 7.1 (initial state), 11 (safety numbers).
// X3DH without a one-time prekey plus an ML-KEM-768 secret as in PQXDH (both public-domain documents). Draft 3: `ID_I` and `ID_J`
// are the two people's identity keys (SPIdentity), checked by the caller against the invite or the contact record; the prekey
// signature is replaced by the secrecy of the invite or by the link key (SPLink). Without its identity private key nobody can
// finish the handshake (spec 6.3).

/**
 * I's secrets for one open bundle (an invite or a link offer). Deleted at accept or at expiry (spec 12). The identity secret is not
 * here: it is the account's, passed in at accept time (spec 5.3). Record: `raw32 epk_sk | raw64 kem seed | raw1257 bundle`.
 */
class SPInviterSecrets(val epkSK: ByteArray, val kemSeed: ByteArray, val bundle: SPWire.Bundle) {
    fun encode(): ByteArray = SPOut().raw(epkSK).raw(kemSeed).raw(bundle.encode()).done()

    companion object {
        fun decode(b: ByteArray): SPInviterSecrets {
            val r = SPIn(b)
            val s = SPInviterSecrets(r.raw(32), r.raw(SP.KEM_SEED_LEN), SPWire.Bundle.decode(r.raw(SPWire.BUNDLE_LEN)))
            r.end()
            return s
        }
    }
}

object SPHandshake {
    /** I accepts a HELLO up to this long after `expiresAtMs` (spec 6.2 step 1). */
    const val ACCEPT_GRACE_MILLIS = 10L * 60 * 1000
    /** J refuses a bundle that expires more than this far ahead (7 days plus one hour of clock skew, review N1). */
    const val MAX_EXPIRY_AHEAD_MILLIS = 7L * 86400 * 1000 + 3600L * 1000
    /** Prefix of the safety-number QR text (spec 11). */
    const val SAFETY_QR_PREFIX = "swell-safety:"

    /** Spec 5.3: fresh `epk_sk, EPK` and `(dk, EK)` and the bundle for the identity key [identityPublic]. Draws 32 then 64 bytes. */
    fun makeBundle(identityPublic: ByteArray, expiresAtMs: Long): SPInviterSecrets {
        if (!SPIdentity.isValidPublic(identityPublic)) throw SwellProtocolError.Format("identity key")
        val epk = SP.x25519(); val kem = SP.kemGenerate()
        return SPInviterSecrets(epk.sk, kem.seed, SPWire.Bundle(identityPublic, epk.pk, kem.ek, expiresAtMs))
    }

    /** `T = SHA256Tagged("transcript", ID_I | ID_J | EPK | EK | E | ct | binding | i64 expiresAtMs)`. */
    fun transcript(b: SPWire.Bundle, idJ: ByteArray, e: ByteArray, ct: ByteArray, binding: ByteArray): ByteArray =
        SP.tagged("transcript", b.idI + idJ + b.epk + b.ek + e + ct + binding + SP.be64(b.expiresAtMs))

    class HandshakeKeys(val rk0: ByteArray, val hka: ByteArray, val nhkb: ByteArray, val pq0: ByteArray)

    /**
     * `hs = HKDF(salt = T, ikm = 0xFF*32 | dh1 | dh2 | dh3 | ss_kem, info = Info("handshake"), 128)`
     * -> `RK0 | shared_hka | shared_nhkb | PQ0`.
     */
    fun keys(t: ByteArray, dh1: ByteArray, dh2: ByteArray, dh3: ByteArray, ss: ByteArray): HandshakeKeys {
        val ikm = ByteArray(32) { 0xFF.toByte() } + dh1 + dh2 + dh3 + ss
        val hs = SP.hkdf(t, ikm, SP.info("handshake"), 128)
        val k = HandshakeKeys(hs.copyOfRange(0, 32), hs.copyOfRange(32, 64), hs.copyOfRange(64, 96), hs.copyOfRange(96, 128))
        SP.wipe(ikm); SP.wipe(hs)
        return k
    }

    class Hello(val hello: ByteArray, val session: SPSession)
    class Accepted(val inner: ByteArray, val session: SPSession)

    /**
     * Spec 6.1 (J redeems), steps 2 to 5: checks the bundle, runs the handshake, sets up the Alice role (7.1) and builds the HELLO
     * as ratchet message 0 carrying [inner]. [expectedInviter] is the 32-byte identity public key the bundle must name (from the
     * invite or the contact record). Randomness is drawn in this order: `E` (32), `ratchet_sk` (32), the KEM encapsulation.
     */
    fun joinerStart(b: SPWire.Bundle, expectedInviter: ByteArray, identity: SPIdentity, binding: ByteArray, inner: ByteArray, now: Long,
                    policy: SPPolicy = SPPolicy.STANDARD): Hello {
        if (binding.size != 32) throw SwellProtocolError.Format("binding")
        if (expectedInviter.size != 32 || !SP.ctEqual(b.idI, expectedInviter) || !SPIdentity.isValidPublic(b.idI))
            throw SwellProtocolError.Crypto("inviter identity")
        if (now > b.expiresAtMs) throw SwellProtocolError.Format("expired")
        if (b.expiresAtMs > SP.sat(now, MAX_EXPIRY_AHEAD_MILLIS)) throw SwellProtocolError.Format("expiry too far ahead")
        val e = SP.x25519(); val ratchet = SP.x25519()
        val kem = SP.kemEncapsulate(b.ek)
        val dh1 = SP.dh(identity.secret, b.epk); val dh2 = SP.dh(e.sk, b.idI); val dh3 = SP.dh(e.sk, b.epk)
        val t = transcript(b, identity.publicKey, e.pk, kem.ct, binding)
        val k = keys(t, dh1, dh2, dh3, kem.ss)
        // Spec 6.1 step 5: e_sk, ss_kem, the DH outputs and hs are never stored.
        SP.wipe(e.sk); SP.wipe(kem.ss); SP.wipe(dh1); SP.wipe(dh2); SP.wipe(dh3)
        // 7.1, J (Alice): RK, CKs, NHKs = KDF_RK(RK0, DH(ratchet_sk, EPK)); HKs = shared_hka; NHKr = shared_nhkb.
        val r = SPSession.kdfRK(k.rk0, SP.dh(ratchet.sk, b.epk))
        val s = SPSession(false, t, identity.publicKey, b.idI, ratchet.sk, ratchet.pk, r.rk, SPPQState(k.pq0, now))
        s.dhr = b.epk; s.cks = r.ck; s.nhks = r.nhk; s.hks = k.hka; s.nhkr = k.nhkb
        val sent = s.encrypt(inner, now, policy, helloKeys = identity.publicKey + e.pk + kem.ct)
        return Hello(sent.envelope, sent.session)
    }

    /**
     * Spec 6.2 (I accepts), steps 1 to 3: the handshake from I's side, the Bob role (7.1), and the normal receive of the HELLO.
     * `session.idPeer` is J's identity public key, proved by the HELLO opening. Throws, changing nothing, on any failure (6.2 step 4).
     */
    fun inviterAccept(secrets: SPInviterSecrets, identity: SPIdentity, hello: ByteArray, binding: ByteArray, now: Long,
                      policy: SPPolicy = SPPolicy.STANDARD): Accepted {
        if (binding.size != 32) throw SwellProtocolError.Format("binding")
        if (!SP.ctEqual(secrets.bundle.idI, identity.publicKey)) throw SwellProtocolError.Crypto("bundle identity")
        if (now > SP.sat(secrets.bundle.expiresAtMs, ACCEPT_GRACE_MILLIS)) throw SwellProtocolError.Format("expired")
        val env = SPWire.Envelope.decode(hello)
        if (env.kind != SPWire.KIND_HELLO || env.helloKeys.size != SPWire.HELLO_KEYS_LEN) throw SwellProtocolError.Format("hello")
        val idJ = env.helloKeys.copyOfRange(0, 32); val e = env.helloKeys.copyOfRange(32, 64); val ct = env.helloKeys.copyOfRange(64, env.helloKeys.size)
        if (!SPIdentity.isValidPublic(idJ)) throw SwellProtocolError.Format("joiner identity")
        val dh1 = SP.dh(secrets.epkSK, idJ); val dh2 = SP.dh(identity.secret, e); val dh3 = SP.dh(secrets.epkSK, e)
        val ss = SP.kemDecapsulate(secrets.kemSeed, ct)
        val t = transcript(secrets.bundle, idJ, e, ct, binding)
        val k = keys(t, dh1, dh2, dh3, ss)
        SP.wipe(ss); SP.wipe(dh1); SP.wipe(dh2); SP.wipe(dh3)
        // 7.1, I (Bob): DHs = (epk_sk, EPK); RK = RK0; NHKs = shared_nhkb; NHKr = shared_hka.
        val s = SPSession(true, t, secrets.bundle.idI, idJ, secrets.epkSK, secrets.bundle.epk, k.rk0, SPPQState(k.pq0, now))
        s.nhks = k.nhkb; s.nhkr = k.hka
        val got = s.decrypt(hello, now, policy, allowHello = true)
        return Accepted(got.inner, got.session)
    }

    /** The identity key a HELLO envelope names in clear (`u8 2 | u8 1 | raw32 ID_J | ...`), serialized, or null for anything else. */
    fun helloIdentity(envelope: ByteArray): ByteArray? {
        if (envelope.size < 2 + SPWire.HELLO_KEYS_LEN || (envelope[0].toInt() and 0xFF) != SPWire.VER || (envelope[1].toInt() and 0xFF) != SPWire.KIND_HELLO) return null
        return byteArrayOf(SPIdentity.TYPE_BYTE) + envelope.copyOfRange(2, 34)
    }

    // ---- 6.1 and 6.4 bindings ---------------------------------------------------------------------------------------------

    /** Binding of a direct-onion invite (version 6): `SHA256Tagged("direct", secret)`. A mailbox invite (version 5) uses its `queueId`. */
    fun directBinding(secret: ByteArray): ByteArray = SP.tagged("direct", secret)

    /** `binding = SHA256Tagged("upgrade", channelId | lo | hi | offerId)`, `lo`, `hi` the two serialized identity keys in unsigned byte order. */
    fun upgradeBinding(channelId: ByteArray, identityA: ByteArray, identityB: ByteArray, offerId: ByteArray): ByteArray {
        val (lo, hi) = if (SP.lexLess(identityA, identityB)) identityA to identityB else identityB to identityA
        return SP.tagged("upgrade", channelId + lo + hi + offerId)
    }

    // ---- 11 safety numbers -------------------------------------------------------------------------------------------------

    /** `okm = HKDF(salt = 32 zero bytes, ikm = lo | hi, info = Info("safety"), 60)`; draft 3 inputs are the 33-byte identity keys. */
    fun safetyBytes(a: ByteArray, b: ByteArray): ByteArray {
        val (lo, hi) = if (SP.lexLess(a, b)) a to b else b to a
        return SP.hkdf(ByteArray(32), lo + hi, SP.info("safety"), 60)
    }

    /** 12 groups of 5 bytes, each a big-endian number mod 100000 printed as 5 digits. */
    fun safetyNumber(a: ByteArray, b: ByteArray): String {
        val okm = safetyBytes(a, b)
        return (0 until 12).joinToString(" ") { g ->
            var v = 0L
            for (i in 0 until 5) v = (v shl 8) or (okm[g * 5 + i].toLong() and 0xFF)
            (v % 100_000).toString().padStart(5, '0')
        }
    }

    /** QR text: `swell-safety:` + base64url without padding of the 60 bytes. Both phones compute the same text. */
    fun safetyQRText(a: ByteArray, b: ByteArray): String =
        SAFETY_QR_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(safetyBytes(a, b))
}
