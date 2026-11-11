// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import Foundation

// Swell Protocol draft 3, spec section 5.1 (identity keys).
//
// One identity per person, derived from the 16 bytes of account entropy (the 12-word recovery phrase). It is an X25519 key; the
// 33-byte form `0x05 | public` is what contacts, group rosters and safety numbers carry. The type byte 0x05 is historical: it
// keeps every identity a phone already stores valid. The same scalar also signs (SPSignature).

public struct SPIdentity: Sendable {
    /// The X25519 private key (32 bytes). It never leaves the device and is never logged.
    public let secret: [UInt8]
    /// The X25519 public key (32 bytes).
    public let publicKey: [UInt8]

    /// The serialized public identity key every contact record, roster and safety number uses: `0x05 | publicKey` (33 bytes).
    public var serialized: [UInt8] { [SPIdentity.typeByte] + publicKey }

    public static let typeByte: UInt8 = 0x05
    public static let serializedLength = 33

    public init(secret: [UInt8]) throws {
        self.secret = secret
        self.publicKey = try SP.x25519Public(secret)
    }

    /// `secret = HKDF-SHA-256(ikm = entropy, salt = 32 zero bytes, info = ASCII "swell identity v1", L = 32)` (PROTOCOL.md section 2).
    public static func derive(entropy: [UInt8]) throws -> SPIdentity {
        guard entropy.count == 16 else { throw SwellProtocolError.format("entropy") }
        return try SPIdentity(secret: SP.hkdf(salt: [UInt8](repeating: 0, count: 32), ikm: entropy, info: Array("swell identity v1".utf8), 32))
    }

    /// The 32-byte public key inside a serialized identity key. Refuses a wrong length or type byte and any key that is not a
    /// valid X25519 public key for an honest person (`isValidPublic`).
    public static func publicKey(serialized s: [UInt8]) throws -> [UInt8] {
        guard s.count == serializedLength, s[0] == typeByte else { throw SwellProtocolError.format("identity key") }
        let u = Array(s[1...])
        guard isValidPublic(u) else { throw SwellProtocolError.format("identity key") }
        return u
    }

    /// An identity public key is valid when its encoding is canonical (top bit clear, value below 2^255 - 19) and it is not a point of
    /// small order (a DH with any scalar would be all zero). Keys made by `SPIdentity.init` always are.
    public static func isValidPublic(_ u: [UInt8]) -> Bool {
        guard u.count == 32, u[31] & 0x80 == 0 else { return false }
        guard SPBig(le: u) < SPBig.p else { return false }
        // A fixed non-zero test scalar: for a small-order point the output is zero, which SP.dh refuses.
        return (try? SP.dh([UInt8](repeating: 0x42, count: 32), u)) != nil
    }
}
