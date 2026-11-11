// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

import XCTest
@testable import SwellProtocol

/// docs/protocol-vectors: handshake-conversation.json, link.json, kdf.json.
final class SessionVectorTests: XCTestCase {
    static let expires: Int64 = 1_800_000_000_000
    static let t0: Int64 = 1_799_990_000_000

    // MARK: first contact and a conversation across two PQ epochs

    struct Step { let from: String; let inner: [UInt8]; let now: Int64 }

    func testHandshakeAndConversation() throws {
        let recorded = Vectors.load("handshake-conversation.json")
        let entI: SPEntropy, entJ: SPEntropy
        let recI: RecordingEntropy?, recJ: RecordingEntropy?
        if let ent = recorded?["entropy"] as? [String: Any], !Vectors.writing || true, let i = ent["I"] as? [String: Any], let j = ent["J"] as? [String: Any], !(Vectors.writing && ProcessInfo.processInfo.environment["SWELL_NEW_ENTROPY"] == "1") {
            entI = QueueEntropy.replay(i); entJ = QueueEntropy.replay(j); recI = nil; recJ = nil
        } else {
            recI = RecordingEntropy(label: "vector/I"); recJ = RecordingEntropy(label: "vector/J")
            entI = recI!; entJ = recJ!
        }
        var doc = try runConversation(entI: entI, entJ: entJ)
        if let recI, let recJ { doc["entropy"] = ["I": recI.record, "J": recJ.record] } else { doc["entropy"] = recorded?["entropy"] }
        if let q = entI as? QueueEntropy { XCTAssertEqual(q.leftover, 0, "every recorded chunk of I was used") }
        if let q = entJ as? QueueEntropy { XCTAssertEqual(q.leftover, 0, "every recorded chunk of J was used") }
        try Vectors.check("handshake-conversation.json", doc)
    }

    func runConversation(entI: SPEntropy, entJ: SPEntropy) throws -> [String: Any] {
        let idI = try SPIdentity.derive(entropy: rep(0x21, 16)), idJ = try SPIdentity.derive(entropy: rep(0x22, 16))
        let binding = rep(0x33, 32)
        let secrets = try SPHandshake.makeBundle(identityPublic: idI.publicKey, expiresAtMs: Self.expires, entropy: entI)
        let helloInner = Array("Hello from J".utf8)
        let (hello, jStart) = try SPHandshake.joinerStart(bundle: secrets.bundle, expectedInviter: idI.publicKey, identity: idJ, binding: binding,
                                                         inner: helloInner, now: Self.t0, entropy: entJ)
        XCTAssertEqual(hello.count, 2266)
        let (gotInner, iStart) = try SPHandshake.inviterAccept(secrets, identity: idI, hello: hello, binding: binding, now: Self.t0 + 500, entropy: entI)
        XCTAssertEqual(gotInner, helloInner)
        XCTAssertEqual(iStart.idPeer, idJ.publicKey)
        XCTAssertEqual(jStart.transcript, iStart.transcript)

        var sess: [String: SPSession] = ["I": iStart, "J": jStart]
        var sent: [(from: String, bytes: [UInt8])] = []
        var steps: [[String: Any]] = []
        func send(_ from: String, _ inner: [UInt8], _ now: Int64, allowPQ: Bool = true) throws {
            let (next, env) = try sess[from]!.encrypt(inner, now: now, allowPQ: allowPQ)
            sess[from] = next; sent.append((from, env))
            let e = try SPWire.Envelope.decode(env)
            _ = e
            steps.append(["op": "send", "from": from, "now": now, "inner": hx(inner), "allowPQ": allowPQ, "envelope": hx(env), "bytes": env.count])
        }
        func recv(_ index: Int, _ now: Int64, expect: String = "ok") throws {
            let to = sent[index].from == "I" ? "J" : "I"
            switch expect {
            case "ok":
                let (next, inner) = try sess[to]!.decrypt(sent[index].bytes, now: now)
                sess[to] = next
                steps.append(["op": "recv", "to": to, "send": index, "now": now, "expect": "ok", "inner": hx(inner)])
            default:
                XCTAssertThrowsError(try sess[to]!.decrypt(sent[index].bytes, now: now))
                steps.append(["op": "recv", "to": to, "send": index, "now": now, "expect": expect])
            }
        }
        // The HELLO itself is already delivered (accept above); it is step 0 so later indexes are stable.
        steps.append(["op": "hello", "from": "J", "now": Self.t0, "inner": hx(helloInner), "envelope": hx(hello), "bytes": hello.count])
        sent.append(("J", hello))

        var t = Self.t0 + 1000
        // I's first reply carries EK(1); J's next message carries CT(1); I opens it and holds epoch 1.
        try send("I", Array("reply 1".utf8), t); t += 1000; try recv(1, t)
        try send("J", Array("reply 2".utf8), t); t += 1000; try recv(2, t)
        try send("I", Array("reply 3".utf8), t); t += 1000; try recv(3, t)
        // Three messages that arrive in the order 3, 1, 2, then the first one again.
        try send("I", Array("late a".utf8), t); t += 10
        try send("I", Array("late b".utf8), t); t += 10
        try send("I", Array("late c".utf8), t); t += 1000
        try recv(6, t); try recv(4, t); try recv(5, t); try recv(4, t, expect: "duplicate")
        // Seven hours later J starts epoch 2 (EK(2) in its next message); I answers with CT(2).
        t += 7 * 3600 * 1000
        try send("J", Array("after seven hours".utf8), t); t += 1000; try recv(7, t)
        try send("I", Array("ct for epoch 2".utf8), t); t += 1000; try recv(8, t)
        try send("J", Array("epoch 2 confirmed".utf8), t); t += 1000; try recv(9, t)
        // A message that needs the 16 KiB bucket, a best-effort one (no PQ field) and a tampered envelope.
        try send("I", rep(0x5A, 5000), t); t += 1000; try recv(10, t)
        try send("J", Array("best effort".utf8), t, allowPQ: false); t += 1000; try recv(11, t)
        var tampered = sent[10].bytes; tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try sess["J"]!.decrypt(tampered, now: t))
        steps.append(["op": "recvTampered", "to": "J", "send": 10, "now": t, "flipLastByte": true, "expect": "fail"])

        XCTAssertEqual(sess["I"]!.sessionHash, sess["J"]!.sessionHash)
        return [
            "description": "Invite-path handshake (spec 6.1, 6.2) between identities derived from entropy 21*16 (I) and 22*16 (J), then a conversation over two PQ epochs. Replay: build the identities, draw randomness only from the recorded entropy streams (chunks in order; KEM encapsulations in order), run the steps, compare every envelope byte for byte and every plaintext.",
            "identityI": ["entropy": hx(rep(0x21, 16)), "serialized": hx(idI.serialized)],
            "identityJ": ["entropy": hx(rep(0x22, 16)), "serialized": hx(idJ.serialized)],
            "binding": hx(binding), "expiresAtMs": Self.expires, "bundleNow": Self.t0,
            "bundle": hx(secrets.bundle.encode()),
            "inviterEpkSecret": hx(secrets.epkSK), "inviterKemSeed": hx(secrets.kemSeed),
            "transcript": hx(iStart.transcript), "sessionHash": hx(iStart.sessionHash),
            "steps": steps,
        ]
    }

    // MARK: link frames

    func testLinkVectors() throws {
        let idI = try SPIdentity.derive(entropy: rep(0x21, 16)), idJ = try SPIdentity.derive(entropy: rep(0x22, 16))
        let channel = rep(0x0c, 16), offerId = rep(0x0f, 16)
        let kI = try SPLink.key(identity: idI, theirs: idJ.serialized, channelId: channel)
        let kJ = try SPLink.key(identity: idJ, theirs: idI.serialized, channelId: channel)
        XCTAssertEqual(kI, kJ, "both sides derive the same link key")
        let secrets = try SPHandshake.makeBundle(identityPublic: idI.publicKey, expiresAtMs: Self.expires, entropy: QueueEntropy(chunks: [rep(0x12, 32), rep(0x14, 64)]))
        let sentAt: Int64 = Self.t0
        let frames: [(String, SPUpgradeFrame, SPIdentity, SPIdentity, [UInt8])] = [
            ("offer", .offer(offerId: offerId, bundle: secrets.bundle.encode()), idI, idJ, rep(0x71, 12)),
            ("hello", .hello(offerId: offerId, envelope: rep(0x66, 2266)), idJ, idI, rep(0x72, 12)),
            ("reset", .reset, idJ, idI, rep(0x73, 12)),
            ("sync", .sync(sessionHash: rep(0x74, 32)), idI, idJ, rep(0x75, 12)),
        ]
        var cases: [[String: Any]] = []
        for (name, frame, from, to, nonce) in frames {
            let ct = try SPLink.seal(frame, sentAtMs: sentAt, identity: from, theirs: to.serialized, channelId: channel, nonce: nonce)
            let opened = try SPLink.open(ct, identity: to, theirs: from.serialized, channelId: channel, now: sentAt + 5000)
            XCTAssertEqual(opened.frame, frame); XCTAssertEqual(opened.sentAtMs, sentAt)
            // Reflection: the sender cannot open its own frame as if the peer had sent it.
            XCTAssertThrowsError(try SPLink.open(ct, identity: from, theirs: to.serialized, channelId: channel, now: sentAt))
            // Another channel id, and a time too old.
            XCTAssertThrowsError(try SPLink.open(ct, identity: to, theirs: from.serialized, channelId: rep(0x0d, 16), now: sentAt))
            XCTAssertThrowsError(try SPLink.open(ct, identity: to, theirs: from.serialized, channelId: channel, now: sentAt + 16 * 86_400_000))
            cases.append(["name": name, "from": from.publicKey == idI.publicKey ? "I" : "J", "frame": hx(frame.encode()), "nonce": hx(nonce), "ciphertext": hx(ct), "bytes": ct.count])
        }
        try Vectors.check("link.json", [
            "description": "Link frames (spec 6.4). linkKey = HKDF(salt = channelId, ikm = DH(own identity secret, peer identity public), info = Info('link', lo33, hi33), 32). ciphertext = 03 | nonce | AEAD(linkKey, nonce, ad = 'SWL3-L' 03 channelId sender33 receiver33, padRaw(i64 sentAtMs | frame)). Each case must be produced exactly and opened by the other side at now = sentAtMs + 5000. A frame must not open with sender and receiver swapped, with another channelId, or at now = sentAtMs + 16 days.",
            "identityI": ["entropy": hx(rep(0x21, 16)), "serialized": hx(idI.serialized)],
            "identityJ": ["entropy": hx(rep(0x22, 16)), "serialized": hx(idJ.serialized)],
            "channelId": hx(channel), "sentAtMs": sentAt, "linkKey": hx(kI),
            "bundleInputs": ["epkSecret": hx(rep(0x12, 32)), "kemSeed": hx(rep(0x14, 64)), "expiresAtMs": Self.expires, "bundle": hx(secrets.bundle.encode())],
            "frames": cases])
    }

    // MARK: key derivation vectors (draft 2 appendix A, restated, and the draft 3 additions)

    func testKDFVectors() throws {
        var items: [[String: Any]] = []
        func add(_ name: String, _ inputs: [String: Any], _ outputs: [String: Any]) { items.append(["name": name, "in": inputs, "out": outputs]) }
        add("Info", ["label": "root", "fields": []], ["info": hx(SP.info("root"))])
        add("Info", ["label": "pq-message", "fields": [hx(SP.be32(5))]], ["info": hx(SP.info("pq-message", SP.be32(5)))])
        add("SHA256Tagged", ["tag": "bundle", "data": hx(rep(0, 4))], ["hash": hx(SP.tagged("bundle", rep(0, 4)))])
        let kr = SPSession.kdfRK(rep(1, 32), rep(2, 32))
        add("KDF_RK", ["rk": hx(rep(1, 32)), "dh": hx(rep(2, 32))], ["rk": hx(kr.rk), "ck": hx(kr.ck), "nhk": hx(kr.nhk)])
        let kc = SPSession.kdfCK(rep(3, 32))
        add("KDF_CK", ["ck": hx(rep(3, 32))], ["ck": hx(kc.ck), "mk": hx(kc.mk)])
        let cb = SPSession.combine(rep(4, 32), pq: rep(5, 32), epoch: 1)
        add("combine", ["mkDR": hx(rep(4, 32)), "pq": hx(rep(5, 32)), "epoch": 1], ["key": hx(cb.key), "nonce": hx(cb.nonce)])
        let header = SPWire.Header(dhPub: rep(7, 32), pn: 1, n: 2, epoch: 3).encode()
        let hk = SPSession.headerKeys(rep(6, 32))
        add("header", ["hk": hx(rep(6, 32)), "dhPub": hx(rep(7, 32)), "pn": 1, "n": 2, "epoch": 3],
            ["header": hx(header), "enc": hx(hk.enc), "iv": hx(hk.iv), "hnonce": hx(SPSession.headerNonce(iv: hk.iv, header: header))])
        // Handshake key schedule from given DH outputs (appendix A.8): ID_I etc. are fixed bytes, not real keys.
        let b = SPWire.Bundle(idI: rep(0x11, 32), epk: rep(0x12, 32), ek: rep(0x15, 1184), expiresAtMs: 1_800_000_000_000)
        let t = SPHandshake.transcript(b, idJ: rep(0x13, 32), e: rep(0x14, 32), ct: rep(0x16, 1088), binding: rep(0x17, 32))
        let k = SPHandshake.keys(t: t, dh1: rep(0x01, 32), dh2: rep(0x02, 32), dh3: rep(0x03, 32), ss: rep(0x18, 32))
        add("handshake", ["idI": hx(b.idI), "epk": hx(b.epk), "ek": "15*1184", "idJ": hx(rep(0x13, 32)), "e": hx(rep(0x14, 32)), "ct": "16*1088",
                          "binding": hx(rep(0x17, 32)), "expiresAtMs": b.expiresAtMs, "dh1": hx(rep(1, 32)), "dh2": hx(rep(2, 32)), "dh3": hx(rep(3, 32)), "ssKem": hx(rep(0x18, 32))],
            ["bundleCommit": hx(b.commit), "T": hx(t), "RK0": hx(k.rk0), "sharedHka": hx(k.hka), "sharedNhkb": hx(k.nhkb), "PQ0": hx(k.pq0)])
        let pq1 = SPPQState.nextKey(rep(8, 32), ss: rep(9, 32), target: 1, ek: rep(0x0a, 1184), ct: rep(0x0b, 1088))
        add("pq-epoch", ["prev": hx(rep(8, 32)), "ss": hx(rep(9, 32)), "target": 1, "ek": "0a*1184", "ct": "0b*1088"], ["PQ1": hx(pq1)])
        let ub = SPHandshake.upgradeBinding(channelId: rep(0x0c, 16), identityA: [5] + rep(0x0d, 32), identityB: [5] + rep(0x0e, 32), offerId: rep(0x0f, 16))
        add("upgrade-binding", ["channelId": hx(rep(0x0c, 16)), "identityA": hx([5] + rep(0x0d, 32)), "identityB": hx([5] + rep(0x0e, 32)), "offerId": hx(rep(0x0f, 16))], ["binding": hx(ub)])
        add("direct-binding", ["secret": hx(rep(0x19, 32))], ["binding": hx(SPHandshake.directBinding(secret: rep(0x19, 32)))])
        // Safety numbers: the draft 2 vector (32-byte inputs) and draft 3 (the 33-byte serialized identity keys).
        let a32 = rep(0x0c, 32), b32 = rep(0x0d, 32)
        add("safety-32", ["a": hx(a32), "b": hx(b32)], ["okm": hx(SPHandshake.safetyBytes(a32, b32)), "digits": SPHandshake.safetyNumber(a32, b32)])
        let ia = try SPIdentity.derive(entropy: rep(0x21, 16)).serialized, ib = try SPIdentity.derive(entropy: rep(0x22, 16)).serialized
        add("safety-33", ["a": hx(ia), "b": hx(ib)],
            ["okm": hx(SPHandshake.safetyBytes(ia, ib)), "digits": SPHandshake.safetyNumber(ia, ib), "qr": SPHandshake.safetyQRText(ia, ib)])
        XCTAssertEqual(SPHandshake.safetyNumber(ia, ib), SPHandshake.safetyNumber(ib, ia))
        try Vectors.check("kdf.json", ["description": "Key derivation, tagged hashes, handshake key schedule, bindings and safety numbers (spec 4, 6, 7.2, 7.6, 11). Fixed fill bytes are written 'xx*n'. Inputs not listed as hex are described in the name.", "items": items])
    }
}
