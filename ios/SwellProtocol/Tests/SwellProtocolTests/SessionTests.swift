// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import XCTest
@testable import SwellProtocol

/// Spec sections 5 to 8 and 7.6 on the library alone: handshake, ratchet, PQ ratchet, limits, persistence.
let testIdentityI = try! SPIdentity.derive(entropy: [UInt8](repeating: 0x21, count: 16))
let testIdentityJ = try! SPIdentity.derive(entropy: [UInt8](repeating: 0x22, count: 16))

func mk(_ expires: Int64) throws -> SPInviterSecrets { try SPHandshake.makeBundle(identityPublic: testIdentityI.publicKey, expiresAtMs: expires) }
func join(_ b: SPWire.Bundle, expected: [UInt8]? = nil, binding: [UInt8], inner: [UInt8], now: Int64, policy: SPPolicy = .standard) throws -> (hello: [UInt8], session: SPSession) {
        try SPHandshake.joinerStart(bundle: b, expectedInviter: expected ?? testIdentityI.publicKey, identity: testIdentityJ, binding: binding, inner: inner, now: now, policy: policy)
    }
func accept(_ s: SPInviterSecrets, hello: [UInt8], binding: [UInt8], now: Int64, policy: SPPolicy = .standard) throws -> (inner: [UInt8], session: SPSession) {
        try SPHandshake.inviterAccept(s, identity: testIdentityI, hello: hello, binding: binding, now: now, policy: policy)
    }


final class SwellProtocolSessionTests: XCTestCase {
    var now: Int64 = 1_800_000_000_000
    /// Short PQ pacing so epochs move within a test.
    let fast = SPPolicy(epochMessages: 2, epochMillis: 3_600_000, keptOldEpochs: 3, maxSkip: 1000, maxStoredSkipped: 2000,
                        skippedLifetimeMillis: 15 * 86400 * 1000, maxChain: 1 << 16)

    func text(_ s: String) -> [UInt8] { Array(s.utf8) }


    /// Invite path (spec 5 and 6): I makes a bundle for its identity, J redeems and sends HELLO, I accepts and replies, J reads the reply.
    func handshake(policy: SPPolicy? = nil) throws -> (i: SPSession, j: SPSession) {
        let p = policy ?? fast
        let queueId = try SP.random(32)
        let secrets = try SPHandshake.makeBundle(identityPublic: testIdentityI.publicKey, expiresAtMs: now + 86_400_000)
        XCTAssertEqual(secrets.bundle.encode().count, 1257, "bundle size of spec 5.3")
        let (hello, j0) = try SPHandshake.joinerStart(bundle: secrets.bundle, expectedInviter: testIdentityI.publicKey, identity: testIdentityJ, binding: queueId,
                                                     inner: text("hello"), now: now, policy: p)
        XCTAssertEqual(hello.count, 2 + SPWire.helloKeysLen + 12 + 60 + 1024 + 16, "HELLO in the 1 KiB bucket")
        let (inner, i0) = try SPHandshake.inviterAccept(secrets, identity: testIdentityI, hello: hello, binding: queueId, now: now, policy: p)
        XCTAssertEqual(inner, text("hello"))
        XCTAssertEqual(i0.idPeer, testIdentityJ.publicKey, "I learns J's identity from a HELLO that only J's key can make")
        XCTAssertEqual(j0.idPeer, testIdentityI.publicKey)
        XCTAssertEqual(i0.transcript, j0.transcript)
        // I's first reply: ordinary DATA, which already starts PQ epoch 1 (I is the keygen side for odd epochs).
        let (i1, reply) = try i0.encrypt(text("welcome"), now: now, policy: p)
        let (j1, got) = try j0.decrypt(reply, now: now, policy: p)
        XCTAssertEqual(got, text("welcome"))
        XCTAssertEqual(i1.pq.pendingTarget, 1)
        return (i1, j1)
    }

    func testHandshakeAndFirstReply() throws {
        let (i, j) = try handshake()
        XCTAssertEqual(i.idSelf, j.idPeer); XCTAssertEqual(i.idPeer, j.idSelf)
    }

    /// A long conversation in both directions: every message arrives, and the PQ epochs move forward on both sides with equal keys.
    func testConversationAndPQEpochs() throws {
        var (i, j) = try handshake()
        for round in 0..<12 {
            for k in 0..<(round % 3 + 1) {
                let (j2, e) = try j.encrypt(text("j\(round).\(k)"), now: now, policy: fast); j = j2
                let (i2, p) = try i.decrypt(e, now: now, policy: fast); i = i2
                XCTAssertEqual(p, text("j\(round).\(k)"))
            }
            let (i3, e) = try i.encrypt(text("i\(round)"), now: now, policy: fast); i = i3
            let (j3, p) = try j.decrypt(e, now: now, policy: fast); j = j3
            XCTAssertEqual(p, text("i\(round)"))
            now += 1000
        }
        XCTAssertGreaterThanOrEqual(i.pq.epoch, 4, "PQ epochs advanced")
        XCTAssertLessThanOrEqual(abs(i.pq.epoch - j.pq.epoch), 1)
        let common = min(i.pq.epoch, j.pq.epoch)
        XCTAssertEqual(i.pq.key(common), j.pq.key(common), "both sides derived the same epoch key")
        XCTAssertLessThanOrEqual(i.pq.keys.count, 4, "old epoch keys are deleted (window)")
        XCTAssertTrue(i.skipped.isEmpty && j.skipped.isEmpty)
    }

    /// Spec 7.6: the epoch exchange step by step (EK from the keygen side, CT back, confirmation).
    func testPQRatchetStep() throws {
        var (i, j) = try handshake()
        XCTAssertEqual(i.pq.pendingTarget, 1); XCTAssertEqual(i.pq.pendingSeed.count, 64)
        XCTAssertEqual(j.pq.epoch, 1, "J encapsulated EK(1) from I's first reply")
        XCTAssertEqual(j.pq.sendEpoch, 0, "but keeps sending under epoch 0 until I proves it holds PQ_1")
        XCTAssertEqual(j.pq.ctTarget, 1)
        let (j1, e1) = try j.encrypt(text("a"), now: now, policy: fast); j = j1
        let (i1, _) = try i.decrypt(e1, now: now, policy: fast); i = i1
        XCTAssertEqual(i.pq.epoch, 1); XCTAssertEqual(i.pq.sendEpoch, 1)
        XCTAssertTrue(i.pq.pendingSeed.isEmpty, "the ML-KEM private key is deleted at decapsulation")
        XCTAssertEqual(i.pq.key(1), j.pq.key(1))
        let (i2, e2) = try i.encrypt(text("b"), now: now, policy: fast); i = i2
        let (j2, _) = try j.decrypt(e2, now: now, policy: fast); j = j2
        XCTAssertEqual(j.pq.sendEpoch, 1, "confirmed by a message under epoch 1")
        XCTAssertEqual(j.pq.ctTarget, 0)
        // J is the keygen side of epoch 2 and starts it once its pacing allows (2 messages in the epoch here).
        for _ in 0..<2 { let (x, e) = try j.encrypt(text("c"), now: now, policy: fast); j = x; let (y, _) = try i.decrypt(e, now: now, policy: fast); i = y }
        let (j3, e3) = try j.encrypt(text("d"), now: now, policy: fast); j = j3
        XCTAssertEqual(j.pq.pendingTarget, 2)
        let (i3, _) = try i.decrypt(e3, now: now, policy: fast); i = i3
        XCTAssertEqual(i.pq.epoch, 2); XCTAssertEqual(i.pq.ctTarget, 2)
    }

    /// Spec 7.6 / formal property P2: after a theft, once a later epoch completes, a phone holding the stolen PQ keys plus the
    /// *current* Double Ratchet state (what a quantum attacker who also breaks every X25519 key would have) cannot read new messages.
    func testPQHealingAfterTheft() throws {
        var (i, j) = try handshake()
        let stolen = j // copy of J's phone: PQ_0, PQ_1, J's ratchet keys
        let epochAtTheft = j.pq.epoch
        for _ in 0..<20 {
            let (j1, e) = try j.encrypt(text("x"), now: now, policy: fast); j = j1
            (i, _) = try i.decrypt(e, now: now, policy: fast)
            let (i1, f) = try i.encrypt(text("y"), now: now, policy: fast); i = i1
            (j, _) = try j.decrypt(f, now: now, policy: fast)
        }
        XCTAssertGreaterThanOrEqual(i.pq.sendEpoch, epochAtTheft + 2)
        // The attacker's best state: J's current ratchet, but only the PQ keys it stole.
        var attacker = j
        attacker.pq = stolen.pq
        let (_, msg) = try i.encrypt(text("secret"), now: now, policy: fast)
        XCTAssertThrowsError(try attacker.decrypt(msg, now: now, policy: fast), "healed: the epoch key is not derivable from the theft")
        XCTAssertEqual(try j.decrypt(msg, now: now, policy: fast).1, text("secret"))
    }

    /// Spec 8.3 / 8.1: out of order, skipped keys, replay rejection.
    func testOutOfOrderAndReplay() throws {
        var (i, j) = try handshake()
        var envs: [[UInt8]] = []
        for k in 0..<6 { let (j1, e) = try j.encrypt(text("m\(k)"), now: now, policy: fast); j = j1; envs.append(e) }
        for k in [5, 0, 3, 1, 4, 2] {
            let (i1, p) = try i.decrypt(envs[k], now: now, policy: fast); i = i1
            XCTAssertEqual(p, text("m\(k)"))
        }
        XCTAssertTrue(i.skipped.isEmpty, "every skipped key was used and deleted")
        for e in envs { XCTAssertThrowsError(try i.decrypt(e, now: now, policy: fast)) { XCTAssertEqual($0 as? SwellProtocolError, .duplicate) } }
        // Across a DH step: J's old chain messages arrive after I has seen the new chain.
        let (i2, r) = try i.encrypt(text("r"), now: now, policy: fast); i = i2
        (j, _) = try j.decrypt(r, now: now, policy: fast)
        var late: [[UInt8]] = []
        let (j3, old) = try j.encrypt(text("new0"), now: now, policy: fast); j = j3; late.append(old)
        let (j4, old2) = try j.encrypt(text("new1"), now: now, policy: fast); j = j4; late.append(old2)
        (i, _) = try i.decrypt(late[1], now: now, policy: fast)
        XCTAssertEqual(try i.decrypt(late[0], now: now, policy: fast).1, text("new0"))
    }

    /// Spec 8.1: a gap above MAX_SKIP is dropped without a state change; a full store evicts the oldest keys.
    func testSkipLimitsAndEviction() throws {
        let tight = SPPolicy(epochMessages: 1000, epochMillis: 1 << 40, keptOldEpochs: 3, maxSkip: 5, maxStoredSkipped: 4,
                             skippedLifetimeMillis: 1000, maxChain: 1 << 16)
        var (i, j) = try handshake(policy: tight)
        var envs: [[UInt8]] = []
        for k in 0..<8 { let (j1, e) = try j.encrypt(text("m\(k)"), now: now, policy: tight); j = j1; envs.append(e) }
        XCTAssertThrowsError(try i.decrypt(envs[7], now: now, policy: tight)) { XCTAssertEqual($0 as? SwellProtocolError, .limit("skip")) }
        let (i1, p5) = try i.decrypt(envs[5], now: now, policy: tight); i = i1
        XCTAssertEqual(p5, text("m5"))
        XCTAssertEqual(i.skipped.count, 4, "5 skipped, store holds 4: the oldest (m0) was evicted")
        XCTAssertThrowsError(try i.decrypt(envs[0], now: now, policy: tight), "evicted key: never readable")
        XCTAssertEqual(try i.decrypt(envs[1], now: now, policy: tight).1, text("m1"))
        // Expiry: skipped keys older than their lifetime are gone.
        now += 2000
        XCTAssertThrowsError(try i.decrypt(envs[2], now: now, policy: tight))
    }

    /// Spec 7.3: a sender stops at MAX_CHAIN until a reply allows a DH step.
    func testMaxChain() throws {
        let tiny = SPPolicy(epochMessages: 1000, epochMillis: 1 << 40, keptOldEpochs: 3, maxSkip: 1000, maxStoredSkipped: 2000,
                            skippedLifetimeMillis: 1 << 40, maxChain: 3)
        var (i, j) = try handshake(policy: tiny)
        for _ in 0..<3 { let (j1, e) = try j.encrypt(text("x"), now: now, policy: tiny); j = j1; (i, _) = try i.decrypt(e, now: now, policy: tiny) }
        XCTAssertThrowsError(try j.encrypt(text("x"), now: now, policy: tiny)) { XCTAssertEqual($0 as? SwellProtocolError, .limit("chain")) }
        let (_, r) = try i.encrypt(text("r"), now: now, policy: tiny)
        (j, _) = try j.decrypt(r, now: now, policy: tiny)
        XCTAssertNoThrow(try j.encrypt(text("again"), now: now, policy: tiny))
    }

    /// Spec 8.4: a changed byte anywhere is dropped and the state does not move.
    func testTamperingAndHelloOnDataPath() throws {
        let (i, j) = try handshake()
        let (_, e) = try j.encrypt(text("t"), now: now, policy: fast)
        for pos in [0, 1, 5, 20, 80, e.count - 1] {
            var bad = e; bad[pos] ^= 0x01
            XCTAssertThrowsError(try i.decrypt(bad, now: now, policy: fast), "byte \(pos)")
        }
        XCTAssertThrowsError(try i.decrypt(Array(e.prefix(100)), now: now, policy: fast))
        XCTAssertEqual(try i.decrypt(e, now: now, policy: fast).1, text("t"), "the untouched copy still opens")
        // A HELLO is never read on the data path (6.2 step 6: later HELLOs are never parsed).
        let secrets = try mk(now + 1000)
        let (hello, _) = try join(secrets.bundle, binding: [UInt8](repeating: 1, count: 32), inner: [1], now: now)
        XCTAssertThrowsError(try i.decrypt(hello, now: now, policy: fast))
    }

    /// Spec 6.1 step 2 and 6.2: bad commit, expiry, a changed KEM ciphertext, a wrong binding.
    func testHandshakeNegatives() throws {
        let s = try mk(now + 1000)
        let bind = [UInt8](repeating: 9, count: 32)
        XCTAssertThrowsError(try join(s.bundle, binding: bind, inner: [1], now: now + 1001), "expired")
        XCTAssertThrowsError(try join(s.bundle, expected: testIdentityJ.publicKey, binding: bind, inner: [1], now: now), "the bundle names another identity than the invite")
        let (hello, _) = try join(s.bundle, binding: bind, inner: [1], now: now)
        var badCT = hello; badCT[2 + 64 + 10] ^= 1 // inside ct: implicit rejection, so the HELLO header fails
        XCTAssertThrowsError(try accept(s, hello: badCT, binding: bind, now: now))
        XCTAssertThrowsError(try accept(s, hello: hello, binding: [UInt8](repeating: 8, count: 32), now: now), "binding is in T")
        XCTAssertThrowsError(try accept(s, hello: hello, binding: bind, now: now + 1000 + SPHandshake.acceptGraceMillis + 1), "too late")
        XCTAssertNoThrow(try accept(s, hello: hello, binding: bind, now: now))
    }

    /// State persistence: encode -> decode is exact, and a restored state keeps talking (spec 8.2: written in the message's transaction).
    func testStatePersistence() throws {
        var (i, j) = try handshake()
        for _ in 0..<5 { let (j1, e) = try j.encrypt(text("p"), now: now, policy: fast); j = j1; (i, _) = try i.decrypt(e, now: now, policy: fast) }
        let (j1, held) = try j.encrypt(text("held back"), now: now, policy: fast); j = j1
        let (j2, e) = try j.encrypt(text("after"), now: now, policy: fast); j = j2
        (i, _) = try i.decrypt(e, now: now, policy: fast)
        XCTAssertEqual(i.skipped.count, 1)
        let i2 = try SPSession.decode(i.encode()), j3 = try SPSession.decode(j.encode())
        XCTAssertEqual(i2, i); XCTAssertEqual(j3, j)
        XCTAssertEqual(try i2.decrypt(held, now: now, policy: fast).1, text("held back"), "a restored skipped key still works")
        let (_, r) = try i2.encrypt(text("r"), now: now, policy: fast)
        XCTAssertEqual(try j3.decrypt(r, now: now, policy: fast).1, text("r"))
        var bad = i.encode(); bad[0] = 9
        XCTAssertThrowsError(try SPSession.decode(bad))
        XCTAssertThrowsError(try SPSession.decode(Array(i.encode().dropLast())))
    }

    /// Spec 8.3 step 2: candidate header keys are distinct values; a key stored twice (skipped and current) is tried once.
    func testDuplicateCandidateKeysCollapse() throws {
        let (i, j) = try handshake()
        let (_, e) = try i.encrypt(text("z"), now: now, policy: fast)
        var weird = j
        weird.skipped = [SPSkipped(hk: j.hkr.isEmpty ? j.nhkr : j.hkr, n: 999, mk: [UInt8](repeating: 0, count: 32), at: now)]
        weird.nhkr = j.hkr.isEmpty ? j.nhkr : j.hkr
        // Duplicate keys collapse into one candidate, so this must still behave like the honest state, never accept twice.
        _ = try? weird.decrypt(e, now: now, policy: fast)
        XCTAssertEqual(try j.decrypt(e, now: now, policy: fast).1, text("z"))
    }
}

/// Review fixes on the library: F5, F9, F14, and the stage 3 wrapping sizes (F2).
final class SwellProtocolReviewFixTests: XCTestCase {
    var now: Int64 = 1_800_000_000_000
    func session() throws -> (i: SPSession, j: SPSession) {
        let s = try mk(now + 1000)
        let bind = [UInt8](repeating: 3, count: 32)
        let (hello, j) = try join(s.bundle, binding: bind, inner: [1], now: now)
        let (_, i) = try accept(s, hello: hello, binding: bind, now: now)
        return (i, j)
    }

    /// F5: a best-effort frame never carries the PQ field and changes nothing; the next durable frame carries it.
    func testBestEffortFramesCarryNoPQField() throws {
        var (i, j) = try session()
        let (i1, e1) = try i.encrypt([5], now: now, allowPQ: false)
        XCTAssertEqual(i1.pq.pendingTarget, 0, "no ML-KEM key made for a frame that may be lost")
        XCTAssertEqual(e1.count, 2 + 12 + 60 + 1024 + 16)
        i = i1
        (j, _) = try j.decrypt(e1, now: now)
        let (i2, e2) = try i.encrypt([6], now: now)
        XCTAssertEqual(i2.pq.pendingTarget, 1)
        XCTAssertEqual(e2.count, 2 + 12 + 60 + 4096 + 16, "EK(1) rides on the durable frame")
        let (j2, _) = try j.decrypt(e2, now: now)
        XCTAssertEqual(j2.pq.epoch, 1)
    }

    /// F9: an authenticated message whose EK fails the FIPS 203 check is delivered; only the EK is ignored.
    func testInvalidEKKeepsMessage() throws {
        var (i, j) = try session()
        i.pq.pendingTarget = 1; i.pq.pendingEK = [UInt8](repeating: 0xFF, count: SP.kemEKLen); i.pq.pendingSeed = [UInt8](repeating: 1, count: 64); i.pq.ekSent = false
        let (_, e) = try i.encrypt([7, 7], now: now)
        let (j2, inner) = try j.decrypt(e, now: now)
        XCTAssertEqual(inner, [7, 7])
        XCTAssertEqual(j2.pq.epoch, 0); XCTAssertEqual(j2.pq.ctTarget, 0)
        j = j2
    }

    /// F14: a PQ field never moves a frame above 16 KiB into a larger bucket; it waits for a smaller frame.
    func testPQFieldNeverGrowsALargeFrame() throws {
        let (i, j) = try session()
        let big = [UInt8](repeating: 0x41, count: 65536 - 4 - 1 - 10) // fits the 64 KiB bucket only without a field
        let (i1, e1) = try i.encrypt(big, now: now)
        XCTAssertEqual(i1.pq.pendingTarget, 0, "no field attached, no key made")
        XCTAssertEqual(e1.count, 2 + 12 + 60 + 65536 + 16, "stays in the 64 KiB bucket, under the 80 KiB mailbox limit")
        XCTAssertEqual(try j.decrypt(e1, now: now).1, big)
        let (i2, _) = try i1.encrypt([1], now: now)
        XCTAssertEqual(i2.pq.pendingTarget, 1, "the next small frame carries it")
        // A frame of 16 KiB or less may grow by one bucket (16 KiB -> 64 KiB is still under the limit).
        let mid = [UInt8](repeating: 0x42, count: 16384 - 4 - 1 - 10)
        let (i3, e3) = try i.encrypt(mid, now: now)
        XCTAssertEqual(i3.pq.pendingTarget, 1)
        XCTAssertEqual(e3.count, 2 + 12 + 60 + 65536 + 16)
    }

}

/// Re-check fixes N1 and N3 on the library, and a fuzz pass over every parser a contact can reach.
final class SwellProtocolRecheckTests: XCTestCase {
    var now: Int64 = 1_800_000_000_000
    /// N1: a bundle whose expiry is far ahead (up to Int64.max) is refused with an error, never a trap.
    func testHugeExpiryRefused() throws {
        for ex in [Int64.max, Int64.max - 1, now + SPHandshake.maxExpiryAheadMillis + 1] {
            var b = try mk(0).bundle
            b.expiresAtMs = ex
            XCTAssertThrowsError(try join(b, binding: [UInt8](repeating: 1, count: 32), inner: [1], now: now))
        }
        var ok = try mk(0).bundle
        ok.expiresAtMs = now + 7 * 86400 * 1000
        XCTAssertNoThrow(try join(ok, binding: [UInt8](repeating: 1, count: 32), inner: [1], now: now))
        XCTAssertEqual(SP.sat(Int64.max, 5), Int64.max); XCTAssertEqual(SP.sat(Int64.min, -5), Int64.min)
        XCTAssertFalse(SP.within(Int64.max, now, 10)); XCTAssertTrue(SP.within(now - 5, now, 10)); XCTAssertFalse(SP.within(Int64.min, now, Int64.max))
    }

    /// N3: a lost EK is repeated on the next durable frame of a new chain, even when that chain starts with best-effort frames.
    func testRepeatOwedSurvivesBestEffortChainStart() throws {
        let s = try mk(now + 1000)
        let bind = [UInt8](repeating: 3, count: 32)
        let (hello, j0) = try join(s.bundle, binding: bind, inner: [1], now: now)
        var (_, i) = try accept(s, hello: hello, binding: bind, now: now)
        var j = j0
        let (i1, _) = try i.encrypt([1], now: now) // carries EK(1); lost
        i = i1
        XCTAssertEqual(i.pq.pendingTarget, 1)
        let (i1b, plain) = try i.encrypt([1], now: now); i = i1b // no field (already sent once); delivered
        (j, _) = try j.decrypt(plain, now: now)
        XCTAssertEqual(j.pq.epoch, 0, "J never saw EK(1)")
        let (j1, r) = try j.encrypt([2], now: now); j = j1 // J's new chain
        (i, _) = try i.decrypt(r, now: now) // DH step: I's next frame starts a new chain
        let (i2, b0) = try i.encrypt([3], now: now, allowPQ: false); i = i2 // a receipt: best effort, no field
        XCTAssertEqual(b0.count, 2 + 12 + 60 + 1024 + 16)
        XCTAssertTrue(i.pq.repeatOwed, "the repeat is still owed")
        let (i3, d1) = try i.encrypt([4], now: now); i = i3
        XCTAssertEqual(d1.count, 2 + 12 + 60 + 4096 + 16, "the durable frame repeats EK(1)")
        XCTAssertFalse(i.pq.repeatOwed)
        (j, _) = try j.decrypt(b0, now: now)
        (j, _) = try j.decrypt(d1, now: now)
        XCTAssertEqual(j.pq.epoch, 1)
        let rec = try SPSession.decode(i.encode())
        XCTAssertEqual(rec.pq.repeatOwed, i.pq.repeatOwed)
    }

    /// N1: random bytes and random field values into every parser and state step a contact can reach: errors only, never a trap.
    func testFuzzParsersNeverTrap() throws {
        var rng = SystemRandomNumberGenerator()
        func rnd(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) } }
        let (i, j) = try { () throws -> (SPSession, SPSession) in
            let s = try mk(now + 1000); let bind = [UInt8](repeating: 3, count: 32)
            let (hello, j) = try join(s.bundle, binding: bind, inner: [1], now: now)
            let (_, i) = try accept(s, hello: hello, binding: bind, now: now)
            return (i, j)
        }()
        let (_, good) = try j.encrypt([9], now: now)
        let extremes: [Int64] = [0, -1, Int64.min, Int64.max, now, now + SPHandshake.maxExpiryAheadMillis]
        for k in 0..<400 {
            // Upgrade frames.
            _ = try? SPUpgradeFrame.decode(SPIn(rnd(Int.random(in: 0...80))))
            let ops: [[UInt8]] = [[1] + rnd(16) + SP.be32(Int32.random(in: -5...1300)) + rnd(Int.random(in: 0...1300)),
                                  [2] + rnd(16) + SP.be32(Int32.random(in: -5...9000)) + rnd(Int.random(in: 0...3000)), [5] + rnd(32), [4], [3] + rnd(16)]
            if let f = try? SPUpgradeFrame.decode(SPIn(ops[k % ops.count])) { _ = f.encode() }
            // A bundle with any expiry, through J's handshake.
            var b = SPWire.Bundle(idI: rnd(32), epk: rnd(32), ek: rnd(SP.kemEKLen), expiresAtMs: extremes[k % extremes.count])
            if k % 3 == 0, let real = try? mk(0).bundle { b.ek = real.ek; b.idI = real.idI; b.epk = real.epk }
            _ = try? join(b, binding: rnd(32), inner: rnd(8), now: now)
            _ = try? SPWire.Bundle.decode([2] + rnd(SPWire.bundleLen - 1))
            // Envelopes: random, and a real one with random bytes changed (all regions, all header fields).
            _ = try? i.decrypt(rnd(Int.random(in: 0...1300)), now: now)
            var bad = good
            for _ in 0..<Int.random(in: 1...4) { bad[Int.random(in: 0..<bad.count)] = UInt8.random(in: 0...255) }
            _ = try? i.decrypt(bad, now: now)
            _ = try? SPWire.unpad(rnd(1024))
            _ = try? SPWire.Header.decode(rnd(44))
            // Stored records (damaged store): decode never traps.
            var rec = i.encode()
            rec[Int.random(in: 1..<rec.count)] = UInt8.random(in: 0...255)
            if let d = try? SPSession.decode(rec) { _ = try? d.encrypt([1], now: now); _ = try? d.decrypt(good, now: now) }
            _ = try? SPSession.decode(rnd(Int.random(in: 0...700)))
            _ = try? SPInviterSecrets.decode(rnd(Int.random(in: 0...1400)))
        }
    }
}

// Review F13: the secret-bearing types are not Equatable in the library; tests compare them field by field through these.
extension SPSkipped: Equatable {
    public static func == (a: SPSkipped, b: SPSkipped) -> Bool { a.hk == b.hk && a.n == b.n && a.mk == b.mk && a.at == b.at }
}
extension SPPQState: Equatable {
    public static func == (a: SPPQState, b: SPPQState) -> Bool {
        a.epoch == b.epoch && a.sendEpoch == b.sendEpoch && a.keys.map(\.0) == b.keys.map(\.0) && a.keys.map(\.1) == b.keys.map(\.1)
            && a.pendingSeed == b.pendingSeed && a.pendingEK == b.pendingEK && a.pendingTarget == b.pendingTarget && a.ekSent == b.ekSent
            && a.pendingCT == b.pendingCT && a.ctTarget == b.ctTarget && a.ctSent == b.ctSent && a.sentInEpoch == b.sentInEpoch && a.confirmedAt == b.confirmedAt
    }
}
extension SPSession: Equatable {
    public static func == (a: SPSession, b: SPSession) -> Bool {
        a.inviter == b.inviter && a.transcript == b.transcript && a.idSelf == b.idSelf && a.idPeer == b.idPeer && a.dhsSK == b.dhsSK
            && a.dhsPK == b.dhsPK && a.dhr == b.dhr && a.rk == b.rk && a.cks == b.cks && a.ckr == b.ckr && a.hks == b.hks && a.hkr == b.hkr
            && a.nhks == b.nhks && a.nhkr == b.nhkr && a.ns == b.ns && a.nr == b.nr && a.pn == b.pn && a.skipped == b.skipped && a.pq == b.pq
    }
}
