// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation


// Swell Protocol, spec section 7.6 (unchanged from draft 2): the post-quantum ratchet.
//
// Designed from the public descriptions of Signal's Sparse Post-Quantum Ratchet and ML-KEM Braid (signal.org/docs) and
// FIPS 203, without reading any implementation. It is simpler than Braid: Swell frames are large, so an encapsulation key
// (1184 bytes) or a ciphertext (1088 bytes) travels whole inside one message body instead of in erasure-coded chunks.
//
// Epochs: epoch 0's key PQ_0 comes from the handshake. For epoch t > 0 one side (the "keygen" side: I for odd t, J for even t)
// makes a fresh ML-KEM-768 key and sends EK(t); the other side encapsulates and sends CT(t). Both then hold
//     PQ_t = HKDF(salt = PQ_{t-1}, ikm = ss_t, info = Info("pq-epoch", i32 t, SHA256Tagged("pq-kem", ek | ct)), 32).
// Every message key is mixed with the epoch key named in its header (SPRatchet.combine), so after a theft the epoch keys
// heal through ML-KEM even if every X25519 key later falls to a quantum computer.

/// Pacing and window parameters (spec 7.6). Tests may shorten them; the app uses `standard`.
public struct SPPolicy: Sendable, Equatable {
    /// A keygen side starts the next epoch after it has sent this many messages in the current one...
    public var epochMessages: Int32
    /// ...or this long after the current epoch was confirmed, whichever comes first. Epoch 1 starts at once.
    public var epochMillis: Int64
    /// Epoch keys kept for late messages: the current one and this many older ones.
    public var keptOldEpochs: Int32
    /// Spec 8.1 limits.
    public var maxSkip: Int32
    public var maxStoredSkipped: Int
    public var skippedLifetimeMillis: Int64
    public var maxChain: Int32

    public static let standard = SPPolicy(epochMessages: 25, epochMillis: 6 * 3600 * 1000, keptOldEpochs: 3,
                                          maxSkip: 1000, maxStoredSkipped: 2000, skippedLifetimeMillis: 15 * 86400 * 1000, maxChain: 1 << 16)
}

/// The PQ part of one relationship's state.
public struct SPPQState: Sendable {
    /// Highest epoch whose key this side knows.
    public var epoch: Int32 = 0
    /// Epoch used for sending: `epoch`, or `epoch - 1` while this side encapsulated and waits for proof that the peer has the new key.
    public var sendEpoch: Int32 = 0
    /// (epoch, key), oldest first; at most `keptOldEpochs + 1` entries.
    public var keys: [(Int32, [UInt8])] = []
    /// Keygen side: the ML-KEM seed (private), its EK and the target epoch, until CT(target) arrives. Target 0 = none.
    public var pendingSeed: [UInt8] = []
    public var pendingEK: [UInt8] = []
    public var pendingTarget: Int32 = 0
    public var ekSent = false
    /// Encapsulating side: CT(ctTarget) (public), sent until a message under `ctTarget` arrives. Target 0 = none.
    public var pendingCT: [UInt8] = []
    public var ctTarget: Int32 = 0
    public var ctSent = false
    /// Messages this side sent since `sendEpoch` was confirmed, and when that was (local clock, ms).
    public var sentInEpoch: Int32 = 0
    public var confirmedAt: Int64 = 0
    /// A new sending chain began while an EK or CT was pending: the next frame that may carry a field repeats it, even when the
    /// chain starts with best-effort frames (review N3). Cleared by the frame that carries it.
    public var repeatOwed = false

    init(pq0: [UInt8], now: Int64) {
        keys = [(0, pq0)]
        confirmedAt = now
    }

    init() {}

    func key(_ e: Int32) -> [UInt8]? { keys.first { $0.0 == e }?.1 }

    /// Encoded sizes of the two PQ fields (kind, target, key or ciphertext).
    static let ekFieldLen = 1 + 4 + SP.kemEKLen, ctFieldLen = 1 + 4 + SP.kemCTLen

    /// Keygen side for epoch t: I (inviter) for odd t, J for even t.
    static func isKeygen(_ t: Int32, inviter: Bool) -> Bool { (t % 2 == 1) == inviter }

    /// `PQ_t = HKDF(salt = PQ_{t-1}, ikm = ss, info = Info("pq-epoch", i32 t, SHA256Tagged("pq-kem", ek | ct)), 32)`.
    static func nextKey(_ prev: [UInt8], ss: [UInt8], target: Int32, ek: [UInt8], ct: [UInt8]) -> [UInt8] {
        SP.hkdf(salt: prev, ikm: ss, info: SP.info("pq-epoch", SP.be32(target), SP.tagged("pq-kem", ek + ct)), 32)
    }

    private mutating func adopt(_ t: Int32, _ k: [UInt8], policy: SPPolicy) {
        keys.append((t, k))
        epoch = t
        while let first = keys.first, first.0 < epoch - policy.keptOldEpochs { keys.removeFirst() } // removed from the stored state (spec 12)
    }

    /// Spec 7.6 "Send": which PQ field this message carries. May start a new epoch (makes an ML-KEM key).
    /// `firstOfChain` is true when the message is number 0 of its sending chain: a pending EK or CT is repeated there, so a
    /// dropped message delays an epoch by at most one DH step.
    /// `carry(fieldLength)` says whether this frame may take a field of that many bytes: false for best-effort frames (review F5)
    /// and when the field would move a frame above 16 KiB into a larger bucket (F14). Nothing changes when it says no.
    mutating func prepareSend(inviter: Bool, firstOfChain: Bool, now: Int64, policy: SPPolicy, entropy: SPEntropy = SPSystemEntropy(), carry: (Int) -> Bool = { _ in true }) throws -> SPWire.PQField {
        if firstOfChain, ctTarget != 0 || pendingTarget != 0 { repeatOwed = true }
        if ctTarget != 0 {
            if (!ctSent || repeatOwed) && carry(Self.ctFieldLen) { ctSent = true; repeatOwed = false; return .ct(target: ctTarget, ct: pendingCT) }
            return .none
        }
        if pendingTarget != 0 {
            if (!ekSent || repeatOwed) && carry(Self.ekFieldLen) { ekSent = true; repeatOwed = false; return .ek(target: pendingTarget, ek: pendingEK) }
            return .none
        }
        let t = epoch + 1
        guard carry(Self.ekFieldLen), Self.isKeygen(t, inviter: inviter), sendEpoch == epoch,
              epoch == 0 || sentInEpoch >= policy.epochMessages || !SP.within(confirmedAt, now, policy.epochMillis) else { return .none }
        let k = try SP.kemGenerate(entropy)
        pendingSeed = k.seed; pendingEK = k.ek; pendingTarget = t; ekSent = true
        return .ek(target: t, ek: k.ek)
    }

    /// Spec 7.6 "Receive", after the body opened under the key of `headerEpoch`. Fields that do not fit the state are ignored
    /// (the message itself authenticated, so it is still delivered).
    mutating func received(headerEpoch: Int32, field: SPWire.PQField, inviter: Bool, now: Int64, policy: SPPolicy, entropy: SPEntropy = SPSystemEntropy()) throws {
        // Confirmation: the peer sends under the epoch we encapsulated for, so it holds that key.
        if headerEpoch == epoch, sendEpoch < epoch {
            sendEpoch = epoch; confirmedAt = now; sentInEpoch = 0
            pendingCT = []; ctTarget = 0; ctSent = false; repeatOwed = false
        }
        switch field {
        case .none: break
        case .ek(let t, let ek):
            guard t == epoch + 1, !Self.isKeygen(t, inviter: inviter), sendEpoch == epoch, ctTarget == 0, let prev = key(epoch) else { return }
            // An encapsulation key that fails the FIPS 203 check is ignored like any field that does not fit; the message is delivered (F9).
            guard let r = try? entropy.encapsulate(ek) else { return }
            let k = Self.nextKey(prev, ss: r.ss, target: t, ek: ek, ct: r.ct)
            adopt(t, k, policy: policy)
            pendingCT = r.ct; ctTarget = t; ctSent = false
        case .ct(let t, let ct):
            guard t == epoch + 1, t == pendingTarget, Self.isKeygen(t, inviter: inviter), let prev = key(epoch) else { return }
            let ss = try SP.kemDecapsulate(seed: pendingSeed, ct)
            let k = Self.nextKey(prev, ss: ss, target: t, ek: pendingEK, ct: ct)
            adopt(t, k, policy: policy)
            pendingSeed = []; pendingEK = []; pendingTarget = 0; ekSent = false; repeatOwed = false // the seed leaves the stored state (spec 12)
            sendEpoch = t; confirmedAt = now; sentInEpoch = 0
        }
    }

    // MARK: storage

    func encode(_ o: SPOut) {
        o.i32(epoch).i32(sendEpoch).i32(Int32(keys.count))
        for (e, k) in keys { o.i32(e).raw(k) }
        o.bytes(pendingSeed).bytes(pendingEK).i32(pendingTarget).u8(ekSent ? 1 : 0)
        o.bytes(pendingCT).i32(ctTarget).u8(ctSent ? 1 : 0).i32(sentInEpoch).i64(confirmedAt).u8(repeatOwed ? 1 : 0)
    }

    static func decode(_ r: SPIn) throws -> SPPQState {
        var s = SPPQState()
        s.epoch = try r.i32(); s.sendEpoch = try r.i32()
        let n = Int(try r.i32())
        guard n >= 1, n <= 64 else { throw SwellProtocolError.format("pq keys") }
        s.keys = try (0..<n).map { _ in (try r.i32(), try r.raw(32)) }
        s.pendingSeed = try r.bytes(max: SP.kemSeedLen); s.pendingEK = try r.bytes(max: SP.kemEKLen)
        s.pendingTarget = try r.i32(); s.ekSent = try r.u8() == 1
        s.pendingCT = try r.bytes(max: SP.kemCTLen); s.ctTarget = try r.i32(); s.ctSent = try r.u8() == 1
        s.sentInEpoch = try r.i32(); s.confirmedAt = try r.i64(); s.repeatOwed = try r.u8() == 1
        // Bounds first, so the arithmetic in this file can never overflow on a damaged record (review N1).
        guard s.epoch >= 0, s.epoch < 1 << 30, s.sendEpoch >= 0, s.sentInEpoch >= 0, s.pendingTarget >= 0, s.ctTarget >= 0 else {
            throw SwellProtocolError.format("pq state")
        }
        guard s.sendEpoch <= s.epoch, s.sendEpoch >= s.epoch - 1, s.key(s.epoch) != nil, s.key(s.sendEpoch) != nil,
              s.pendingTarget == 0 || (s.pendingSeed.count == SP.kemSeedLen && s.pendingEK.count == SP.kemEKLen),
              s.ctTarget == 0 || s.pendingCT.count == SP.kemCTLen else { throw SwellProtocolError.format("pq state") }
        return s
    }
}
