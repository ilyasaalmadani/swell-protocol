// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation

// Swell Protocol draft 3, spec section 6.4 (link frames).
//
// Two people who know each other's identity keys (they are contacts) need a way to start or repair a Swell session without any session
// to run in: the first one after an update, a phone restored from a backup, a lost state. A link frame is sealed with a key only the two
// identity keys can make (static-static X25519), so the mailbox cannot read it and nobody else can forge it. It carries OFFER, HELLO,
// RESET and SYNC (SPUpgradeFrame). READY travels inside a Swell session.
//
//   LK         = HKDF(salt = channelId, ikm = DH(my identity private key, their identity public key),
//                     info = Info("link", lo, hi), L = 32)      lo, hi: the two serialized identity keys, unsigned byte order
//   ciphertext = u8 3 | raw12 nonce | AEAD(LK, nonce, ad = "SWL3-L" | u8 3 | channelId | sender33 | receiver33, padded)
//   padded     = i32 length | content | zeros to a bucket (SPWire.padRaw),  content = i64 sentAtMs | SPUpgradeFrame bytes

public enum SPLink {
    public static let version: UInt8 = 3
    /// A frame with a `sentAtMs` further than this before now is ignored (mailbox time-to-live is 14 days).
    public static let maxAgeMillis: Int64 = 15 * 86_400_000
    /// ...or further than this after now (clock skew).
    public static let maxAheadMillis: Int64 = 3_600_000

    /// The link key of a contact. `mine` and `theirs` are serialized identity keys (33 bytes).
    public static func key(identity: SPIdentity, theirs: [UInt8], channelId: [UInt8]) throws -> [UInt8] {
        guard channelId.count == 16 else { throw SwellProtocolError.format("channel") }
        let peer = try SPIdentity.publicKey(serialized: theirs)
        var shared = try SP.dh(identity.secret, peer)
        defer { SP.wipe(&shared) }
        let mine = identity.serialized
        let (lo, hi) = mine.lexicographicallyPrecedes(theirs) ? (mine, theirs) : (theirs, mine)
        return SP.hkdf(salt: channelId, ikm: shared, info: SP.info("link", lo, hi), 32)
    }

    static func ad(channelId: [UInt8], sender: [UInt8], receiver: [UInt8]) -> [UInt8] {
        Array("SWL3-L".utf8) + [version] + channelId + sender + receiver
    }

    /// Seals one frame from `identity` to `theirs`. `nonce` is 12 random bytes (fixed only by tests).
    public static func seal(_ frame: SPUpgradeFrame, sentAtMs: Int64, identity: SPIdentity, theirs: [UInt8], channelId: [UInt8],
                            nonce: [UInt8]? = nil) throws -> [UInt8] {
        let lk = try key(identity: identity, theirs: theirs, channelId: channelId)
        let n = try nonce ?? SP.random(12)
        let padded = try SPWire.padRaw(SP.be64(sentAtMs) + frame.encode())
        return [version] + n + (try SP.seal(key: lk, nonce: n, ad: ad(channelId: channelId, sender: identity.serialized, receiver: theirs), padded))
    }

    /// Opens a frame that `theirs` sent to `identity`. Throws when it does not open, is malformed, or is too old or too new.
    public static func open(_ ciphertext: [UInt8], identity: SPIdentity, theirs: [UInt8], channelId: [UInt8], now: Int64) throws -> (sentAtMs: Int64, frame: SPUpgradeFrame) {
        guard ciphertext.count >= 1 + 12 + SPWire.buckets[0] + 16, ciphertext[0] == version else { throw SwellProtocolError.format("link version") }
        let lk = try key(identity: identity, theirs: theirs, channelId: channelId)
        let padded = try SP.open(key: lk, nonce: Array(ciphertext[1..<13]), ad: ad(channelId: channelId, sender: theirs, receiver: identity.serialized), Array(ciphertext[13...]))
        let content = try SPWire.unpadRaw(padded)
        let r = SPIn(content)
        let sentAt = try r.i64()
        guard SP.within(sentAt, now, maxAgeMillis) || (sentAt > now && sentAt <= SP.sat(now, maxAheadMillis)) else { throw SwellProtocolError.format("link time") }
        guard try r.u8() == Int(SPUpgradeFrame.innerType) else { throw SwellProtocolError.format("link frame") }
        let frame = try SPUpgradeFrame.decode(r)
        try r.end()
        return (sentAt, frame)
    }
}
