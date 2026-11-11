// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol

import java.net.URLDecoder

// Swell Protocol draft 3, spec section 5.4 (invite codes 5 and 6) and 5.5 (the frames of first contact).
//
// Text form: "swell:" + base64url without padding of the payload. Readers refuse padding, whitespace inside a code and any
// non-canonical encoding (low bits set).
//   Version 5 (mailbox, no onion service):  u8 5 | str mailboxOnion | raw32 queueId | raw32 sealKey | bytes identityKey(33)
//   Version 6 (direct onion):               u8 6 | str onion | raw32 secret | bytes identityKey(33) | raw32 authKey
// Versions 2 and 3 are codes of build 26 and older (libsignal, removed in build 27): refused with a plain sentence. Version 4 (draft 2) is withdrawn.

sealed class SPInvite {
    /** The inviter's serialized identity key (33 bytes). Checked for validity (spec 5.1) before anything is sent, not by the decoder. */
    abstract val identityKey: ByteArray
    /** The 32 bytes that enter the transcript (spec 6.1). */
    abstract val binding: ByteArray
    abstract fun payload(): ByteArray
    fun encode(): String = PREFIX + b64(payload())

    /** Version 5: the bundle waits sealed in the queue [queueId] on [mailbox]. */
    class Mailbox(val mailbox: String, val queueId: ByteArray, val sealKey: ByteArray, override val identityKey: ByteArray) : SPInvite() {
        override val binding: ByteArray get() = queueId
        override fun payload(): ByteArray = SPOut().u8(V_MAILBOX).str(mailbox).raw(queueId).raw(sealKey).bytes(identityKey).done()

        /** `raw12 nonce | AES-256-GCM(sealKey, nonce, aad = queueId, bundle)`. [nonce] is random except in tests. */
        fun seal(bundle: ByteArray, nonce: ByteArray = SP.random(12)): ByteArray = nonce + SP.seal(sealKey, nonce, queueId, bundle)

        fun open(sealed: ByteArray): ByteArray {
            if (sealed.size < 12 + 16) throw SwellProtocolError.Format("sealed bundle")
            return SP.open(sealKey, sealed.copyOfRange(0, 12), queueId, sealed.copyOfRange(12, sealed.size))
        }
    }

    /** Version 6: the bundle is fetched from [onion] with GET_BUNDLE and [secret]; [authKey] opens the client-authorized service. */
    class Direct(val onion: String, val secret: ByteArray, override val identityKey: ByteArray, val authKey: ByteArray) : SPInvite() {
        override val binding: ByteArray get() = SPHandshake.directBinding(secret)
        override fun payload(): ByteArray = SPOut().u8(V_DIRECT).str(onion).raw(secret).bytes(identityKey).raw(authKey).done()
    }

    /** A refused code. [olderVersion]: it is a code of build 26 or older, and [message] is the sentence to show. */
    class Refused(val olderVersion: Boolean, message: String) : Exception(message)

    companion object {
        const val PREFIX = "swell:"
        const val V_MAILBOX = 5
        const val V_DIRECT = 6
        /** Versions of builds before 27 (libsignal, removed in build 27). */
        val OLDER_VERSIONS = setOf(2, 3)
        const val OLDER_VERSION_MESSAGE = "This code is from an older version of Swell. Ask them to update Swell and send you a new code."
        const val NOT_A_CODE = "This is not a Swell code."
        const val MAX_TEXT_BYTES = 1024
        const val LINK_PREFIX = "https://jijilabsdigital.com/swell/i#"
        private val ONION = Regex("[a-z2-7]{56}")
        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

        fun b64(b: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b)

        /** Strict base64url without padding: any other character, a length of 1 mod 4 or unused low bits set is refused. */
        fun unb64(s: String): ByteArray {
            if (s.length % 4 == 1) throw SwellProtocolError.Format("base64")
            val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
            var acc = 0; var bits = 0
            for (ch in s) {
                val v = ALPHABET.indexOf(ch)
                if (v < 0) throw SwellProtocolError.Format("base64")
                acc = (acc shl 6) or v; bits += 6
                if (bits >= 8) { bits -= 8; out.write((acc shr bits) and 0xFF) }
            }
            if (bits > 0 && (acc and ((1 shl bits) - 1)) != 0) throw SwellProtocolError.Format("base64 low bits")
            return out.toByteArray()
        }

        /** The version byte of a code token (`swell:...`), or -1. */
        fun versionOf(code: String): Int = runCatching {
            val t = code.trim()
            if (!t.startsWith(PREFIX)) -1 else (unb64(t.removePrefix(PREFIX)).firstOrNull()?.toInt()?.and(0xFF) ?: -1)
        }.getOrDefault(-1)

        /** The strict decoder of one code (`swell:` + payload), surrounding whitespace allowed. */
        fun decode(code: String): SPInvite {
            if (code.toByteArray(Charsets.UTF_8).size > MAX_TEXT_BYTES) throw Refused(false, NOT_A_CODE)
            val t = code.trim()
            if (!t.startsWith(PREFIX)) throw Refused(false, NOT_A_CODE)
            val payload = try { unb64(t.removePrefix(PREFIX)) } catch (e: SwellProtocolError) { throw Refused(false, NOT_A_CODE) }
            if (payload.isEmpty()) throw Refused(false, NOT_A_CODE)
            val v = payload[0].toInt() and 0xFF
            if (v in OLDER_VERSIONS) throw Refused(true, OLDER_VERSION_MESSAGE)
            return try {
                val r = SPIn(payload); r.u8()
                when (v) {
                    V_MAILBOX -> {
                        val mb = r.str(64)
                        if (!ONION.matches(mb)) throw SwellProtocolError.Format("mailbox")
                        Mailbox(mb, r.raw(32), r.raw(32), r.bytes(64).also { if (it.size != SPIdentity.SERIALIZED_LEN) throw SwellProtocolError.Format("identity") }).also { r.end() }
                    }
                    V_DIRECT -> {
                        val onion = r.str(64)
                        if (!ONION.matches(onion)) throw SwellProtocolError.Format("onion")
                        val secret = r.raw(32)
                        val ik = r.bytes(64).also { if (it.size != SPIdentity.SERIALIZED_LEN) throw SwellProtocolError.Format("identity") }
                        Direct(onion, secret, ik, r.raw(32)).also { r.end() }
                    }
                    else -> throw SwellProtocolError.Format("version")
                }
            } catch (e: SwellProtocolError) { throw Refused(false, NOT_A_CODE) }
        }

        /**
         * Finds an invite in any text: a link (`https://jijilabsdigital.com/swell/i#...`), a `swell:` code or a bare code, with any text,
         * line breaks and spaces around it. A code of an older version gives [OLDER_VERSION_MESSAGE] when nothing valid is found.
         */
        fun parse(text: String): SPInvite {
            if (text.toByteArray(Charsets.UTF_8).size > 4096) throw Refused(false, NOT_A_CODE)
            val tokens = ArrayList<String>()
            val cur = StringBuilder()
            for (ch in text) {
                if (ALPHABET.indexOf(ch) >= 0 || ch == ':' || ch == '#' || ch == '/' || ch == '.' || ch == '%') cur.append(ch)
                else { if (cur.isNotEmpty()) tokens += cur.toString(); cur.setLength(0) }
            }
            if (cur.isNotEmpty()) tokens += cur.toString()
            val candidates = tokens.map { tok ->
                var t = runCatching { URLDecoder.decode(tok, "UTF-8") }.getOrDefault(tok)
                val hash = t.indexOf('#')
                if (hash >= 0 && t.lowercase().contains("jijilabsdigital.com")) t = t.substring(hash + 1)
                val at = t.indexOf(PREFIX)
                if (at >= 0) t.substring(at) else PREFIX + t
            }
            var sawOlder = false
            for (t in candidates.sortedByDescending { it.length }) {
                when (versionOf(t)) {
                    V_MAILBOX, V_DIRECT -> try { return decode(t) } catch (e: Refused) { }
                    in OLDER_VERSIONS -> sawOlder = true
                    else -> {}
                }
            }
            if (sawOlder) throw Refused(true, OLDER_VERSION_MESSAGE)
            throw Refused(false, NOT_A_CODE)
        }

        /** The envelope that holds the sealed bundle in a version 5 invite queue: `u8 2 | raw16 zero | u8 0 | bytes sealed`. */
        fun bundleEnvelope(sealed: ByteArray): ByteArray = SPOut().u8(2).raw(ByteArray(16)).u8(0).bytes(sealed).done()

        fun sealedBundle(envelope: ByteArray): ByteArray {
            val r = SPIn(envelope)
            if (r.u8() != 2) throw SwellProtocolError.Format("envelope")
            r.raw(16); r.u8()
            return r.bytes(80 * 1024)
        }

        /** Peer HELLO frame (spec 5.5): `u8 2 | u8 2 | raw32 secret | raw16 channelId | bytes helloEnvelope`. */
        fun helloFrame(secret: ByteArray, channelId: ByteArray, helloEnvelope: ByteArray): ByteArray =
            SPOut().u8(2).u8(2).raw(secret).raw(channelId).bytes(helloEnvelope).done()

        /** MSG frame (spec 5.6): `u8 2 | u8 3 | raw16 channelId | u8 ciphertextType | bytes ciphertext`. */
        fun msgFrame(channelId: ByteArray, type: Int, ciphertext: ByteArray): ByteArray =
            SPOut().u8(2).u8(3).raw(channelId).u8(type).bytes(ciphertext).done()
    }
}
