package com.jijilabsdigital.swell.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Sessions end to end: handshake, long two-way conversation with PQ epochs, out of order, replay, limits, tampering, records. */
class SPSessionTest {
    private val now = 1_700_000_000_000L
    private val binding = SP.random(32)
    private val idI = SPIdentity.derive(SP.random(16))
    private val idJ = SPIdentity.derive(SP.random(16))
    private fun bundle(expires: Long = now + 86_400_000) = SPHandshake.makeBundle(idI.publicKey, expires)
    private fun join(secrets: SPInviterSecrets, inner: ByteArray, at: Long = now, b: ByteArray = binding) =
        SPHandshake.joinerStart(secrets.bundle, idI.publicKey, idJ, b, inner, at)

    private class Pair(var i: SPSession, var j: SPSession)

    /** J redeems a fresh bundle, I accepts: the pair after the HELLO. */
    private fun connect(): Pair {
        val secrets = bundle()
        val ready = SPUpgradeFrame.Ready(SP.random(16)).encode()
        val h = join(secrets, ready)
        val a = SPHandshake.inviterAccept(secrets, idI, h.hello, binding, now + 1000)
        assertContentEquals(ready, a.inner)
        return Pair(a.session, h.session)
    }

    private fun Pair.iSends(msg: ByteArray, t: Long = now, allowPQ: Boolean = true): ByteArray {
        val s = i.encrypt(msg, t, allowPQ = allowPQ); i = s.session; return s.envelope
    }
    private fun Pair.jSends(msg: ByteArray, t: Long = now, allowPQ: Boolean = true): ByteArray {
        val s = j.encrypt(msg, t, allowPQ = allowPQ); j = s.session; return s.envelope
    }
    private fun Pair.iReads(env: ByteArray, t: Long = now): ByteArray { val r = i.decrypt(env, t); i = r.session; return r.inner }
    private fun Pair.jReads(env: ByteArray, t: Long = now): ByteArray { val r = j.decrypt(env, t); j = r.session; return r.inner }

    @Test fun handshakeAndSizes() {
        val secrets = bundle()
        assertEquals(SPWire.BUNDLE_LEN, secrets.bundle.encode().size)
        assertEquals(1257, SPWire.BUNDLE_LEN)
        val h = join(secrets, byteArrayOf(26, 3))
        assertEquals(2266, h.hello.size) // spec 7.5: HELLO in the 1 KiB bucket
        val p = connect()
        assertEquals(p.i.safetyNumber, p.j.safetyNumber)
        assertEquals(SPHandshake.safetyNumber(idI.serialized, idJ.serialized), p.i.safetyNumber)
        assertContentEquals(idJ.serialized, p.i.peerIdentity)
        assertContentEquals(idI.serialized, p.j.peerIdentity)
    }

    @Test fun conversationAcrossPqEpochs() {
        val p = connect()
        var t = now
        val policy = SPPolicy.STANDARD
        for (round in 0 until 120) {
            t += 60_000
            val m1 = "from J $round".toByteArray()
            assertContentEquals(m1, p.iReads(p.jSends(m1, t), t))
            val m2 = "from I $round".toByteArray()
            assertContentEquals(m2, p.jReads(p.iSends(m2, t), t))
        }
        // The two sides are in the same epoch and it moved past 0 (epoch 1 starts at once, then pacing).
        assertTrue(p.i.pq.epoch >= 2, "epoch ${p.i.pq.epoch}")
        assertEquals(p.i.pq.epoch, p.j.pq.epoch)
        assertContentEquals(p.i.pq.key(p.i.pq.epoch)!!, p.j.pq.key(p.j.pq.epoch)!!)
        assertTrue(policy.keptOldEpochs >= p.i.pq.keys.size - 1)
    }

    @Test fun outOfOrderAndReplay() {
        val p = connect()
        val a = p.jSends("a".toByteArray()); val b = p.jSends("b".toByteArray()); val c = p.jSends("c".toByteArray())
        assertContentEquals("c".toByteArray(), p.iReads(c))
        assertContentEquals("a".toByteArray(), p.iReads(a))
        assertContentEquals("b".toByteArray(), p.iReads(b))
        assertFailsWith<SwellProtocolError> { p.i.decrypt(a, now) } // replay
        // Skipped keys survive a reply and a new chain.
        val x = p.jSends("x".toByteArray()); val y = p.jSends("y".toByteArray())
        assertContentEquals("y".toByteArray(), p.iReads(y))
        p.jReads(p.iSends("reply".toByteArray()))
        assertContentEquals("x".toByteArray(), p.iReads(x))
    }

    @Test fun tamperingAtEveryRegionIsRefused() {
        val p = connect()
        p.jReads(p.iSends("hi".toByteArray()))
        val env = p.jSends("secret".toByteArray())
        for (pos in listOf(0, 1, 5, 14, 40, 80, 90, 500, env.size - 1)) {
            val bad = env.copyOf().also { it[pos] = (it[pos].toInt() xor 1).toByte() }
            assertFailsWith<SwellProtocolError>("byte $pos") { p.i.decrypt(bad, now) }
        }
        assertContentEquals("secret".toByteArray(), p.iReads(env)) // the failed attempts changed nothing
    }

    @Test fun maxSkipAndChain() {
        val p = connect()
        p.jReads(p.iSends("x".toByteArray()))
        val envs = (0..1002).map { p.jSends(byteArrayOf(1)) }
        assertFailsWith<SwellProtocolError.Limit> { p.i.decrypt(envs.last(), now) }
        assertContentEquals(byteArrayOf(1), p.iReads(envs[1000]))
        val q = connect()
        q.j.ns = SPPolicy.STANDARD.maxChain
        assertFailsWith<SwellProtocolError.Limit> { q.j.encrypt(byteArrayOf(1), now) }
    }

    @Test fun handshakeRefusals() {
        val secrets = bundle()
        // A bundle that names another identity than expected, expired bundle, expiry too far ahead, short binding.
        assertFailsWith<SwellProtocolError.Crypto> { SPHandshake.joinerStart(secrets.bundle, idJ.publicKey, idJ, binding, byteArrayOf(1), now) }
        assertFailsWith<SwellProtocolError.Format> { join(secrets, byteArrayOf(1), at = now + 2 * 86_400_000) }
        val far = SPWire.Bundle(secrets.bundle.idI, secrets.bundle.epk, secrets.bundle.ek, now + 30L * 86_400_000)
        assertFailsWith<SwellProtocolError.Format> { SPHandshake.joinerStart(far, idI.publicKey, idJ, binding, byteArrayOf(1), now) }
        assertFailsWith<SwellProtocolError.Format> { join(secrets, byteArrayOf(1), b = ByteArray(5)) }
        // An invalid identity key in a bundle is refused.
        assertFailsWith<SwellProtocolError.Format> { SPHandshake.makeBundle(ByteArray(32), now + 1000) }
        // Wrong binding on I's side: the header does not open.
        val h = join(secrets, byteArrayOf(1))
        assertFailsWith<SwellProtocolError> { SPHandshake.inviterAccept(secrets, idI, h.hello, SP.random(32), now) }
        // Another identity cannot accept a HELLO made for this bundle.
        assertFailsWith<SwellProtocolError> { SPHandshake.inviterAccept(secrets, idJ, h.hello, binding, now) }
        // Late accept (past expiry + 10 minutes).
        assertFailsWith<SwellProtocolError.Format> { SPHandshake.inviterAccept(secrets, idI, h.hello, binding, now + 86_400_000 + 11 * 60_000) }
        // A HELLO on the data path is dropped.
        val p = connect()
        assertFailsWith<SwellProtocolError.Format> { p.i.decrypt(h.hello, now) }
    }

    @Test fun invalidEncapsulationKeyKeepsTheMessage() {
        // Spec review F9: a PQ field that cannot be used never costs the message.
        val p = connect()
        p.jReads(p.iSends("start".toByteArray())) // I sends EK(1) here
        assertEquals(1, p.j.pq.epoch)
    }

    @Test fun recordRoundTripAndUseAfterRestore() {
        val p = connect()
        p.jReads(p.iSends("one".toByteArray()))
        p.iReads(p.jSends("two".toByteArray()))
        val i2 = SPSession.decode(p.i.encode()); val j2 = SPSession.decode(p.j.encode())
        assertContentEquals(p.i.encode(), i2.encode())
        val r = j2.decrypt(p.iSends("three".toByteArray()), now)
        assertContentEquals("three".toByteArray(), r.inner)
        assertNotNull(i2.copy())
        assertFailsWith<SwellProtocolError> { SPSession.decode(p.i.encode().copyOf(50)) }
        assertFailsWith<SwellProtocolError> { SPSession.decode(p.i.encode().also { it[0] = 9 }) }
    }

    @Test fun bareBucketsAndPQRepeat() {
        val p = connect()
        p.jReads(p.iSends("x".toByteArray()))
        val s = p.j.encrypt("hello".toByteArray(), now, allowPQ = false)
        // Draft 3: no outer layer, so a short DATA envelope is the 1 KiB bucket plus 90 bytes (spec 7.5).
        assertEquals(1114, s.envelope.size)
        assertContentEquals("hello".toByteArray(), p.i.decrypt(s.envelope, now).inner)
        // A PQ field whose frame never left is owed again: the next durable frame repeats it.
        val q = connect()
        val lost = q.iSends("lost".toByteArray()) // carries EK(1)
        assertTrue(lost.size > 4000)
        q.i = q.i.withPQRepeatOwed()
        val again = q.iSends("again".toByteArray())
        assertTrue(again.size > 4000, "EK(1) repeated")
        q.jReads(again)
        assertEquals(1, q.j.pq.epoch)
    }

    @Test fun linkFramesRefuseStrangers() {
        val channel = SP.random(16)
        val stranger = SPIdentity.derive(SP.random(16))
        val f = SPLink.seal(SPUpgradeFrame.Reset, now, idI, idJ.serialized, channel)
        assertEquals(SPUpgradeFrame.Reset.encode().toList(), SPLink.open(f, idJ, idI.serialized, channel, now).frame.encode().toList())
        assertFailsWith<SwellProtocolError> { SPLink.open(f, stranger, idI.serialized, channel, now) }
        assertFailsWith<SwellProtocolError> { SPLink.open(f, idJ, stranger.serialized, channel, now) }
        val tampered = f.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        assertFailsWith<SwellProtocolError> { SPLink.open(tampered, idJ, idI.serialized, channel, now) }
    }

    @Test fun inviteTextNotYetWiredButUpgradeFramesRoundTrip() {
        val id = SP.random(16)
        val frames = listOf(SPUpgradeFrame.Offer(id, ByteArray(SPWire.BUNDLE_LEN)), SPUpgradeFrame.Hello(id, ByteArray(2266)),
            SPUpgradeFrame.Ready(id), SPUpgradeFrame.Reset, SPUpgradeFrame.Sync(ByteArray(32)))
        for (f in frames) {
            val r = SPIn(f.encode())
            assertEquals(26, r.u8())
            assertContentEquals(f.encode(), SPUpgradeFrame.decode(r).encode())
            r.end()
        }
        assertFailsWith<SwellProtocolError> { SPUpgradeFrame.decode(SPIn(byteArrayOf(9))) }
    }
}
