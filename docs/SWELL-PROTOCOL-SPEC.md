# Swell Protocol: specification draft 3

Status: DRAFT 3, written 2026-11-11 for build 27. Draft 2 plus the removal of libsignal: nothing in Swell's end-to-end encryption runs on libsignal any more. Implemented in Swift (`ios/SwellProtocol`, Apache-2.0, a package with no app code; the app-level formats of sections 5.4, 18, 19 and 20 in the app's engine) and, in parallel, in Kotlin (`android/swellprotocol`). The Swift code passes every file in `docs/protocol-vectors/`; the Kotlin code passes Appendix A (A.1 to A.11) and is being brought to draft 3 against the same files. It is internally reviewed, not independently audited: an independent audit is planned and no text may call it audited. The gate and the owner rule in `docs/DESIGN-SWELL-PROTOCOL.md` are superseded by the owner's decision of 2026-11-11 (libsignal out in build 27, audit after both platforms match); section 14 compares the design with that rule.

Draft 2 is in `docs/SWELL-PROTOCOL-SPEC.md` of the commit before build 27, draft 1 at `46aaab6`, draft 0.1 at `abeaef6`. Reviews: `docs/audit/SWELL-PROTOCOL-REVIEW-1.md`, `-REVIEW-2-IMPLEMENTER.md`, `-REVIEW-3.md`, `-REVIEW-4-B26.md`. The formal results are in `docs/FORMAL-RESULTS.md`.

Words: **I** is the inviter, or in a link handshake the phone with the lower identity key. **J** is the joiner, or the other phone. **Mailbox** is the Swell onion mailbox of `docs/PROTOCOL.md`. **Relationship** is one contact link. **Epoch** is one period of the post-quantum ratchet. A line marked **CHANGED in draft 3** differs from draft 2 and may need a code change; everything not marked is byte for byte the draft 2 format, and a draft 2 session (build 26, stage 3) continues unchanged.

Sections that an implementer can use now, and their state: 4 to 8 and Appendix A (ready, unchanged), **5 identity, signatures, invites and bundles (ready for Android)**, **6 handshake and link frames (ready for Android)**, 11 safety numbers (ready), 18 groups (ready), 19 report seal (ready), 20 backup (ready), 21 what libsignal did and what replaced it (ready). The vectors that belong to each are listed in section 13.

## 1. What changed from draft 2

- **libsignal is gone (CHANGED in draft 3).** Every message, group frame, status update and call signal travels in a Swell Protocol session, bare: the MSG frame has ciphertext type **34** and its ciphertext is the DATA envelope of 7.5 (section 5.6). The stage 3 outer libsignal layer (types 32 and 33) and its bucket shrink (`wrapShrink`) no longer exist; envelope buckets are the full 1, 4, 16, 64, 256 KiB of 7.4. A phone never sends types 2, 3, 32 or 33 and treats them from a contact as "that app is older" (6.5).
- **One identity key per person (CHANGED in draft 3, D14).** The 16-byte account entropy still makes the identity key exactly as before (PROTOCOL.md section 2); its 33-byte form `0x05 | X25519 public` is what contacts, rosters and safety numbers carry. It replaces the random per-relationship `ID_I`, `ID_J` of draft 2. The bundle, HELLO and transcript layouts do not change; only the key put into `ID_I` and `ID_J` does (5.1, 6).
- **SwellSig (new, 5.2).** Signatures by the identity key, for signed group states. An RFC 8032 Ed25519 verification under the Edwards form of the X25519 identity key. Replaces libsignal's identity-key signature.
- **Invite codes 5 and 6 (CHANGED in draft 3, 5.4).** Version 5 (mailbox) and 6 (direct onion) have the layouts of the old versions 3 and 2 and carry a Swell bundle. Versions 2 and 3 are libsignal codes and are refused with a plain message. Draft 2's invite version 4 (per-relationship identity, `bundleCommit`) is withdrawn; it was never produced by a build.
- **First-contact binding (6.1).** `binding` is the invite's `queueId` (version 5) or `SHA256Tagged("direct", secret)` (version 6). The joiner checks that the bundle names the identity key the invite carries, so `bundleCommit` is not needed.
- **Link frames replace the libsignal-borne upgrade (CHANGED in draft 3, 6.4).** OFFER, HELLO, RESET and SYNC (inner type 26) travel in a sealed link frame, MSG ciphertext type **35**, keyed by the static-static DH of the two identity keys. They start or repair a session between two people who are already contacts: after an update, after a restore, after a lost state. Nothing else needs them.
- **Capability bit 8, `CAP_SWELL_V3 = 256` (6.5).** "I am a draft 3 build: bare type 34 and link type 35, invite versions 5 and 6." Bit 7 stays `CAP_SWELL_PROTOCOL = 128` and is announced by every draft 3 build as well.
- **Safety number (11, CHANGED in draft 3).** The input is the two 33-byte serialized identity keys; the QR text is defined.
- **Sessions are not in backups** (as in draft 2) and a restored phone repairs them with link frames (20, 6.4). The libsignal-era session state, pre-keys and the "skip sending chains" step after a restore are gone.
- **Minimum platform (4.1, owner decision 2026-11-11).** iOS 26 and macOS 26 for the Swift library (CryptoKit ML-KEM-768); Android uses a permissive ML-KEM (Bouncy Castle).
- **Repair after a restore (CHANGED in draft 3, 6.4).** A J that still holds an `ACTIVE` session and receives a fresh OFFER answers with SYNC (once per offer and day): I made the offer because it holds no session, for example after a restore, and answers the SYNC with RESET and a new offer. Without this rule a restored I could not reach a J that never writes first.
- **Bit 8 decides, not the session (6.5).** A contact that has not announced bit 8 gets only STATE and READY, even over a session kept from stage 3, and its chat shows the update line; learning bit 8 from its STATE is answered with one STATE.
- **Waiting is not failing (6.5).** A message that cannot be sealed because there is no `ACTIVE` session yet waits in the outbox as it is: no failed try, no backoff, no give-up. When a session becomes `ACTIVE` the outbox (one-to-one and group rows) is sent at once.
- **Groups made before build 27 (18.1).** Their current state carries a libsignal signature; the sequencer signs the same state again, once, as the next version.
- **Vectors.** Ten files in `docs/protocol-vectors/` (section 13): the six of the library and `invite.json`, `group-state.json`, `report.json`, `backup.json` of the app formats.
- **Held-back RESET (6.4, answer to Q10).** RESET and SYNC sent before the other phone's OFFER or HELLO of the current session are ignored.
- **Strict SwellSig verification (5.2, answer to the Android port's Q8).** R canonical and of order exactly L, A of order exactly L, S below L; then the RFC 8032 equation. `signature.json` gained a `strict` list of hostile signatures that must be refused; `report.json` gained `padded` and `envelopePadded` (Q2). No value already in those files changed.
- **Bytes that Appendix A fixed do not change.** A.1 to A.11 hold for draft 3 (the Kotlin code that passes them needs no change for them). What changes for an implementation is listed above: what goes into `ID_I`/`ID_J`, the invite versions, the MSG types, the link frames, SwellSig and the rules of 6.4 and 6.5.
- **Domain version stays 2.** Every `Info` and tagged hash keeps the `2` of draft 2, and the AD strings `SWL2-H`, `SWL2-M` do not change, so a session made by build 26 keeps working in build 27. New draft 3 items have their own labels: `SWL3-L` (link frames), `swell-sig-v3`, `swell-sig-nonce` (5.2), tags `direct` (6.1), HKDF label `link` (6.4).

### 1.1 What changed from draft 1 (draft 2, kept for the record)

- **Post-quantum ratchet (7.6).** Every message key is mixed with an epoch key that is renewed by ML-KEM-768 exchanges inside the conversation. After a phone theft, the conversation heals against an attacker who also breaks every X25519 key, at the second epoch change at the latest. Draft 1 healed only through X25519 (formal attack A3).
- **Handshake output** grows to 128 bytes: `RK0 | shared_hka | shared_nhkb | PQ0`. `PQ0` is the epoch 0 key.
- **Header** grows to 44 bytes with an `i32 epoch`. `hct` is 60 bytes.
- **Body** content starts with a PQ field (none, an encapsulation key, or a ciphertext). Buckets are those of `PROTOCOL.md` section 1, including 256 KiB.
- **Domain version 2** in `Info` and `SHA256Tagged`; AD strings `SWL2-H`, `SWL2-M`; envelope version byte 2. No draft 1 value can be reused.
- Forward-secrecy wording (section 3) and the deletion table (section 12) are corrected. Section 6.3 cites the formal results.

### 1.2 Answers for the Android port

Each answer points to the normative text and the vector file that fixes the bytes. "Exact" means a Kotlin implementation reproduces the file byte for byte, not only reads it.

1. **Identity signatures for groups.** SwellSig (5.2): an Ed25519 signature, 64 bytes, verified with RFC 8032 under the Edwards form `A` of the X25519 identity key; signing uses the X25519 identity scalar and a deterministic nonce. Message = `"swell-sig-v3" | 0x00 | u8 len(context) | context | state bytes`, context `swell-group-state-v1`. The identity key and its 33-byte form do not change. Exact: `signature.json` (map, signatures, negatives), `group-state.json` (state, hash, signature, signed state, commit frame, eight invalid cases, an unsorted roster).
2. **Exact invite bytes.** 5.4: `u8 5 | str mailboxOnion | raw32 queueId | raw32 sealKey | bytes identityKey(33)` and `u8 6 | str onion | raw32 secret | bytes identityKey(33) | raw32 authKey`, always 162 bytes, text `swell:` + 216 base64url characters, no padding. Versions 2 and 3 show the sentence of 5.4. The bundle in a version 5 queue is sealed with AES-256-GCM under `sealKey`, AAD `queueId`. Binding: version 5 `queueId`, version 6 `SHA256Tagged("direct", secret)`. Exact: `invite.json` (codes, refused codes, bundle, sealed envelope, GET_BUNDLE, the inner HELLO, both HELLO envelopes and frames, MSG frames).
3. **Safety number and QR.** 11: input the two 33-byte serialized identity keys; 60 digits in 12 groups of 5; QR text `swell-safety:` + base64url without padding of the 60 bytes. Exact: `kdf.json` (`safety-33` and the QR text). Draft 2's 32-byte variant is A.11 (same function, other input). Android's old `Fingerprint` (libsignal, 5200 iterations) and its QR are gone; a number made by an old app does not match and the screen just shows the new one.
4. **Report seal and backup format.** 19 and 20: unchanged from build 26, written out in full; neither ever used libsignal. Sessions are not in a backup; a restored phone repairs them with link frames (6.4). Exact: `report.json` (seal from a fixed ephemeral key and nonce, open, tampered), `backup.json` (key, nonces, AD, a complete one-chunk file made by the real writer).
5. **Group sender-key replacement.** None: Swell groups never had sender keys. Every group frame goes to each member through that pair's own session, as ordinary DATA (18). The Android `SenderKeyRecord` store tables can be dropped.
6. **Bare MSG type.** 5.6: `u8 2 | u8 3 | raw16 channelId | u8 ciphertextType | bytes ciphertext` with type **34** = the DATA envelope of 7.5, unwrapped, and **35** = a link frame (6.4). Types 2, 3, 32, 33 are never sent; received, they are acknowledged, never opened, and mark the contact as an older app (6.5). Capability bit 8 (`256`) is announced by every draft 3 build. Exact: `invite.json` (`msg`), `link.json`, `handshake-conversation.json`.
7. **ML-KEM-768 vectors from a fixed seed.** `mlkem768.json`: three 64-byte seeds `d | z` to `ek` (1184 bytes); for each a recorded `ct` and the `ss` that decapsulation must give; a tampered `ct` and the implicit-rejection secret it must give; an `ek` that encapsulation must refuse (FIPS 203 modulus check). Made with CryptoKit; NIST ACVP vectors are still to be added (O10).

### 1.3 Answers to the Android port's questions (2026-11-11)

From `docs/audit/ANDROID-SPEC-QUESTIONS.md` of the Android worktree (Q1 to Q10). Each answer is also in the section it belongs to.

- **Q1 (old-code sentence).** The sentence is the one in `invite.json` and the apps: "This code is from an older version of Swell. Ask them to update Swell and send you a new code." Section 5.4 says so.
- **Q2 (report padding).** Yes: the phone pads the report body to a bucket (PROTOCOL.md section 1: `i32 length | body | zeros`, 1 to 256 KiB) and seals the padded bytes; the inbox tooling unpads after opening. Section 19; `report.json` `padded`, `envelopePadded`.
- **Q3 (already connected).** Refused when a person redeems a code (the add-contact path) of someone they already hold as a contact; both apps throw it now (the iPhone did not before). Connections the group engine makes (18) are exempt: the pair gets a new channel beside the old contact record, and the newest usable record is the one used for that person. Section 6.1 step 2 and 18.
- **Q4 (reusable codes).** Allowed for the demo contact only, with the rules now in 5.3. In short: bundles of at most 7 days, up to three kept, a HELLO for any bundle still held opens until its expiry plus the grace; for version 5 the oldest envelope in the queue must always be a valid bundle (PEEK answers with the oldest envelope only), so the maker acknowledges each HELLO once handled and, after putting a new bundle, acknowledges the older bundle envelopes.
- **Q5 (bit 8 and kept sessions).** Accepted. Only build 26 iPhones of internal testers hold draft 2 sessions, so a phone that never held one (every Android build) knows that an `ACTIVE` session means a draft 3 peer, and may skip holding frames back by bit 8. Everything else of 6.5 applies. Section 6.5.
- **Q6 (waiting without a durable outbox).** Accepted for build 27: what must hold everywhere is that a missing session is not a failed try. Android keeps waiting texts in memory (after a restart they show as not sent and can be retried); a durable outbox is the target (O18). Section 6.5.
- **Q7 (EK(1) in I's first reply).** No: I's first reply is STATE, a best-effort frame, and carries no PQ field (7.6). `EK(1)` rides on I's first message that may carry one, a durable message. Both apps do this; 6.2 is corrected.
- **Q8 (cofactored or not).** Neither choice is left to the library: the strict rules of 5.2 put R and A in the prime-order subgroup and fix the encodings, and under them the two equations agree, so CryptoKit, Bouncy Castle and any RFC 8032 verifier give the same answer after the checks. `signature.json` `strict` has the edge cases (R plus a point of order 8, R the identity, R not canonical, A with a point of order 8).
- **Q10 (a RESET that waited in the mailbox).** Yes, the same rule on both sides: RESET and SYNC older than the other phone's own OFFER or HELLO of the session held are ignored (6.4 acceptance, record `swp.peerstart`). iPhone test `SwellEngineTests.testAResetThatWaitedInTheMailboxDoesNotEndTheNewSession` reproduces the loss without the rule.
- **Q9.** Agreed with every item as written (no approval state on Android, the crash guard, unknown types, the backup namespaces, `swell-verify:` scanned as "does not match").

## 2. Sources and the clean-room rule

Written only from these public documents and Swell's own documents. The author did not read libsignal source, Signal-iOS or Signal-Android source, the ML-KEM Braid or SPQR reference code (AGPL), or any AGPL or GPL implementation. Implementers must also work from this text and the public documents, and record that in `docs/CLEAN-ROOM.md`, which lists every source used.

- Signal, *The Double Ratchet Algorithm*, revision 4; *The X3DH Key Agreement Protocol*; *The PQXDH Key Agreement Protocol*; the public descriptions of the *Sparse Post-Quantum Ratchet* and *ML-KEM Braid* (signal.org/docs). The first three state "This document is hereby placed in the public domain" (checked 2026-11-04). The Braid status is recorded in `docs/CLEAN-ROOM.md`. Section 7.6 takes only the idea (an ML-KEM ratchet whose epoch secrets are mixed into message keys), not the Braid's chunking, erasure code or state machine.
- NIST FIPS 203 (ML-KEM), RFC 7748 (X25519), **RFC 8032 (Ed25519, used only to verify SwellSig)**, RFC 5869 (HKDF), FIPS 180-4 (SHA-256, SHA-512), NIST SP 800-38D (AES-GCM).
- Academic background on ratchets with post-compromise security, read as papers only.

ML-KEM patent status is not verified and needs a lawyer (O9).

## 3. Threat model

Attackers: a network observer; the mailbox operator, who logs everything and may drop, delay, reorder or replay; a later quantum attacker with recordings; a thief who copies one phone once; a hostile contact.

Aims, each with the formal result that supports it (`docs/FORMAL-RESULTS.md`):

- **Secrecy.** Content is secret from the operator and the network if X25519 or ML-KEM-768 holds for the handshake (properties 1, 4, 5, 17; draft 2: 2-1 to 2-5).
- **Forward secrecy, stated exactly.** A message stays secret after a later theft once its message key is deleted, **with two limits**. (a) The sender's current ratchet private key lives until its next DH step, so a second theft inside the healing window of an earlier, unhealed theft can expose a message that was already sent (attack A1; the published Double Ratchet behaves the same). (b) Skipped message keys (up to 2000, for up to 15 days, section 8.1) are kept on purpose and a theft exposes the messages they belong to (G6).
- **Recovery after theft, classical.** Against an attacker who is passive while healing, messages become secret again one DH round trip after a one-time theft (property 13).
- **Recovery after theft, post-quantum.** Against an attacker who is passive while healing and who also breaks every X25519 key, messages become secret again from the first epoch whose ML-KEM key is made after the theft, that is, at the second epoch change at the latest (property 2-P2, section 7.6). Epoch changes are paced (7.6), so this takes at least two round trips and up to the pacing limits.
- **Authentication of both people.** A session between two identity keys can only be made by whoever holds both private keys (6.3).
- **Linking (CHANGED in draft 3).** Identity keys are one per person, as they were with libsignal: two contacts can tell that they know the same person by comparing identity keys, and the mailbox operator sees an identity key in clear in an invite-path HELLO (D7, D14). Draft 2's per-relationship keys are not used because groups, "already connected" detection and the contact record all rest on one identity per person. Link frames and everything after the HELLO hide identity keys from the mailbox.
- **Mailbox privacy.** The operator cannot link queues by envelope bytes and no key, id or counter repeats in clear: a DATA envelope has a random-looking header nonce and sealed header, a link frame is sealed. The MSG frame's `channelId` and ciphertext type are in clear, as they are today.

The link between two people who are already contacts is opportunistic in one respect: the operator can keep a pair without a session by dropping link frames, and the people see the plain line "Ask <name> to update Swell" or messages that wait (6.5). Contact info shows the protocol a chat uses.

Not protected: mailbox timing, sizes and volume (a PQ field moves a message to a larger bucket, so epoch changes are visible as size); a compromised phone; a contact who keeps what they received; a leaked invite, because whoever uses it first becomes the contact; an **active** attacker after a theft, who can inject its own ratchet or KEM keys and stay in the middle until the safety numbers are compared again or a new invite is made (attack A2, and 2-P2's active variant; every ratchet has this limit); a theft of the identity key (the 12 words), after which the thief can start sessions as that person; header metadata (`dh_pub`, counters, epoch) after a theft plus a quantum break, because header keys are not mixed with epoch keys; link frames and identity authentication are classical (X25519, Ed25519 verification): a quantum attacker who records an invite or a link exchange can later impersonate the identity but cannot read earlier messages (this is also the limit of PQXDH); dropped messages; push tokens and Tor guard exposure; implementation bugs. These must be stated plainly in any public claim.

## 4. Encoding

Integers are big-endian. `i32` and `i64` are signed two's complement. `bytes` is `i32 length | data`. `str` is `bytes` holding valid UTF-8. `raw(n)` is exactly n bytes. These match `PROTOCOL.md` section 1.

Primitive boundaries:
- `DH(sk, pk)` is X25519 with scalar `sk` and u-coordinate `pk`. Reject an all-zero output on both sides, for every DH.
- X25519 keys are 32 bytes in RFC 7748 encoding. The high bit of a received key is masked as RFC 7748 requires. No further canonical check is made for ephemeral keys; **identity public keys must also be canonical and of large order (5.1)**.
- `AEAD(key, nonce, ad, pt)` is AES-256-GCM with a 12-byte nonce. Output is `ciphertext | 16-byte tag`.
- `HKDF(salt, ikm, info, L)` is HKDF-SHA-256 Extract then Expand. `Expand(prk, info, L)` is Expand alone, with a 32-byte `prk`.
- `KEM` is ML-KEM-768. `KEM.Enc(ek)` validates `ek` as FIPS 203 requires. Lengths: ek 1184, ct 1088, ss 32. The private key is stored as its 64-byte seed `d | z` and never leaves the device. `KEM.Dec` of a wrong ciphertext returns a pseudo-random secret (implicit rejection), so the following AEAD fails. Vector file `mlkem768.json`.
- `SHA-512` (FIPS 180-4) is used only by SwellSig (5.2).

Every HKDF `info` is built by one encoder:

```
Info(label, f1..fn) = "Swell" | 0x00 | u8 2 | u8 len(label) | label | (u16 len(f) | f) for each field
SHA256Tagged(tag, data) = SHA-256("Swell" | 0x00 | u8 2 | u8 len(tag) | tag | data)
```

The `2` is the domain version of the session layer; draft 3 keeps it (draft 1 used 1). Labels are ASCII and each has exactly one use (section 9).

Random values come from the platform cryptographic source. If it fails, stop. Do not continue with a fallback. (Tests may replace the source; see Appendix A, "entropy".)

Comparisons of secret or secret-derived values (commitments, header keys, nonces) are constant time. Implementations wipe the buffers they own where the language allows and must not log any key, nonce, plaintext or state record.

### 4.1 Availability (CHANGED in draft 3)

The Swell Protocol needs ML-KEM-768. **The minimum platform is iOS 26 and macOS 26** (CryptoKit `MLKEM768`; owner decision of 2026-11-11, App Store text "Requires iOS 26 or later"). There is no classical-only Swell session. Android uses a permissive-licence ML-KEM (Bouncy Castle `bcprov-jdk18on`, MIT) and needs no OS version. There is no path for a phone that cannot do ML-KEM, and no capability bit that says so.

## 5. Identity, signatures, invites and bundles

### 5.1 Identity key (ready for Android)

One identity per person, made from the 16 bytes of account entropy (the 12-word recovery phrase). It is the key PROTOCOL.md section 2 has always described, so every identity a phone already stores stays valid:

```
secret     = HKDF-SHA-256(ikm = entropy16, salt = 32 zero bytes, info = ASCII "swell identity v1" (no Info() encoder), L = 32)
public     = X25519(secret, 9)                 32 bytes
serialized = 0x05 | public                     33 bytes
```

`secret` is an X25519 private key (clamped as RFC 7748 clamps whenever it is used). The type byte `0x05` is historical (it tagged Curve25519 keys in the library used before); it is kept so that contact records, group rosters and safety numbers do not change, and it is part of the identity wherever the serialized form is compared, hashed or signed. A reader accepts only `0x05`.

An identity public key `u` is **valid** when (a) its 32 bytes are canonical: the top bit is clear and the little-endian value is below 2^255 - 19, and (b) it is not a point of small order, which an implementation tests by checking that `DH(any non-zero scalar, u)` is not all zero. A key that is not valid is refused wherever it appears: in an invite, a bundle, a HELLO, a roster, a link frame. Vector `identity.json` (`derive`, `invalidPublic`).

The 33-byte form is what the contact record, the group roster (18) and the safety number (11) carry. `registrationId` (libsignal) does not exist.

### 5.2 SwellSig: signatures by the identity key (ready for Android)

Used for signed group states (18). Anything else that needs a signature must use a new `context` string.

The signature is an RFC 8032 Ed25519 signature that verifies under the Edwards form `A` of the X25519 identity key, made without ever holding an Ed25519 seed. Notation: `p = 2^255 - 19`, `L = 2^252 + 27742317777372353535851937790883648493` (the Ed25519 group order), `B` the Ed25519 base point, `||` concatenation, integers little endian unless said.

```
u    = identity public key (32 bytes, valid per 5.1; its top bit is ignored as in RFC 7748)
A    = y as 32 bytes, with  y = (u - 1) * (u + 1)^-1 mod p   and the top bit (the sign of x) set to 0     [RFC 7748 section 4.1 map]
a    = identity secret clamped (byte0 &= 248, byte31 &= 127, byte31 |= 64) read as an integer
msg  = "swell-sig-v3" | 0x00 | u8 len(context) | context | message           context: short ASCII, e.g. "swell-group-state-v1"

Sign(secret, context, message):
  rseed  = first 32 bytes of SHA-512("swell-sig-nonce" | 0x00 | secret | msg)
  (R, r) = the RFC 8032 section 5.1.5 key pair of the 32-byte seed rseed:  h = SHA-512(rseed), r = clamp(h[0..32]) (integer), R = encode(r*B) = the Ed25519 public key of rseed
  k      = SHA-512(R | A | msg) as integer, mod L
  S      = (r + k*a0) mod L,  where a0 = a mod L if the point a*B has an even x, otherwise L - (a mod L)
  signature = R | S   (S as 32 bytes), 64 bytes
Verify(u, context, message, signature), strict (CHANGED in draft 3, answer to Q8):
  1. signature is 64 bytes, R = its first 32, S = its last 32 as an integer; S < L
  2. u valid (5.1); compute A; A decodes to a point of order exactly L (A != identity and [L]A = identity)
  3. R decodes strictly (RFC 8032 5.1.3: its y below p, and x = 0 with the sign bit set refused) to a point of order exactly L
  4. k = SHA-512(R | A | msg) mod L; accept if and only if [S]B = R + [k]A
```

Steps 2 and 3 put R and A in the subgroup of order L. There the plain equation of step 4 and RFC 8032's cofactored one (`[8][S]B = [8]R + [8][k]A`) give the same answer, and an implementation may hand step 4 to any RFC 8032 verifier (the Swift code uses CryptoKit, the Kotlin code Bouncy Castle) once its own code has made steps 1 to 3. Without them, hostile signatures exist that one library accepts and another refuses; `signature.json` `strict` lists four (R plus a point of order 8: only the cofactored equation holds; R the identity with S = k a; R a non-canonical encoding of the identity; an identity key whose Edwards form has a point of order 8 in it, with k = 0 mod 8, where both equations hold), and every one must be refused. An honest SwellSig signature always passes steps 1 to 3. A key with a point of small order in it passes 5.1 but fails step 2, so it can never sign a group state.

The sign of x of `a*B` is not visible from `u`. An implementation that cannot read it computes `S` for both `a mod L` and `L - (a mod L)` and returns the signature that the RFC 8032 verification accepts under `A`; exactly one does, and the check doubles as a self-test. The nonce is deterministic, so a signature is reproducible: a conforming implementation produces exactly the bytes of `signature.json`. The map `u -> A` has vectors too (`edwardsMap`). Cost: the Swift implementation uses a small unsigned-integer type and its own point arithmetic for steps 2 and 3 (not constant time: signing is rare and on the owner's own phone, and verification handles public values only); the order check of A is remembered per key.

Security note: the same scalar is used for X25519 and for signing; the `swell-sig-v3` prefix and the context separate the two uses. The scheme follows the shape of Signal's published XEdDSA, but it was written from RFC 8032 and RFC 7748 alone (docs/CLEAN-ROOM.md) and is not interoperable with libsignal signatures (D15).

### 5.3 Bundle (unchanged layout)

I creates fresh random values `epk_sk, EPK` (X25519) and `(dk, EK)` (ML-KEM-768) for each invite or offer. Bundle, 1257 bytes:

```
u8 2 | raw32 ID_I | raw32 EPK | raw1184 EK | i64 expiresAtMs
```

`ID_I` is I's **identity public key** (5.1, 32 bytes, not the 33-byte form). `expiresAtMs` is UTC milliseconds from I's clock: 24 hours ahead for an invite, 7 days for a link offer. There is no signature on the bundle (D1): its authenticity is the invite (which names `ID_I` and travels out of band, or, for a link offer, the link key of 6.4), and a bundle that was swapped on the way gives the swapper nothing, because without the identity secrets `dh2` of 6.1 cannot be computed. `bundleCommit = SHA256Tagged("bundle", bundle)` stays defined (vector `kdf.json`) but no draft 3 rule uses it.

I's secrets for the bundle are `epk_sk` and the 64-byte ML-KEM seed. The identity secret is the account's and is never copied into a bundle record.

**Reusable codes (answer to Q4).** Every code a person makes is one use. The one exception is a service that must stay reachable by one published code: today only the Jiji Labs demo contact for app reviewers. Its maker keeps the code's secret, makes bundles that expire 7 days ahead (J's limit of 7 days and 1 hour holds), keeps up to three of them, makes a new one when the newest has less than 3 days left, and opens a HELLO for any bundle it still holds until that bundle's expiry plus the 10-minute grace. For version 5 the oldest envelope in the invite queue must always be a valid bundle, because PEEK answers with the oldest envelope only: the maker acknowledges each HELLO once it has handled it, and right after a new bundle is in the queue it acknowledges the older bundle envelopes. For version 6 GET_BUNDLE answers with the newest bundle. Every redeemer gets its own session; nothing else about the contact differs.

### 5.4 Invite codes (CHANGED in draft 3, ready for Android)

Text form: `swell:` + base64url without padding of the payload (PROTOCOL.md section 3). Readers reject padding, whitespace inside the code and any non-canonical encoding (low bits set). Two payloads:

```
Version 5 (mailbox, made by a phone that has no onion service; the layout of the old version 3):
  u8 5 | str mailboxOnion | raw32 queueId | raw32 sealKey | bytes identityKey(33)
  mailboxOnion: 56 lowercase characters of the v3 onion address without ".onion"
Version 6 (direct onion, made by a phone that hosts an onion service; the layout of the old version 2):
  u8 6 | str onion | raw32 secret | bytes identityKey(33) | raw32 authKey
```

`identityKey` is the inviter's serialized identity key (5.1) and must be valid: a code whose key is not valid may parse, and redeeming it is refused before anything is sent. A code with trailing bytes, a wrong version or a wrong field size is refused. Both payloads are always 162 bytes, so the code is `swell:` and exactly 216 base64url characters, with no padding and no unused bits. An app that finds a code inside longer text (a link, a pasted message) takes the run of base64url characters after `swell:` (or after the link's `#`) and decodes that; a trailing `=` is then outside the code, while the code token itself with padding is refused (`invite.json`, `refused`). Versions 2, 3 and 16 keep their old meaning for old apps: **a draft 3 app that reads version 2 or 3 says "This code is from an older version of Swell. Ask them to update Swell and send you a new code." and does nothing else**; an old app reads versions 5 and 6 as "not a Swell code". Version 16 (group link, PROTOCOL.md 5i) is unchanged, except that the one-use code inside its request is a version 5 code. Version 4 (draft 2) is withdrawn.

**Version 5 queue contents.** The bundle waits in the invite queue as the first envelope:

```
envelope = u8 2 | raw16 zero | u8 0 | bytes sealed
sealed   = raw12 nonce | AES-256-GCM(sealKey, nonce, aad = queueId, bundle)        ciphertext then 16-byte tag
```

(the layout of the old version 3 with a 1257-byte Swell bundle in place of the libsignal bundle). The redeemer PEEKs the queue (op 0x16), opens the first envelope and checks 6.1 step 2. Durable order for I: commit the invite record, PUT the bundle, then show the invite.

**Version 6.** GET_BUNDLE (PROTOCOL.md section 4, `raw32 secret`) answers `u8 0x81, bytes bundle` with the same 1257-byte bundle, not sealed (the onion service is client-authorized with `authKey`).

**Binding** (the 32 bytes that enter the transcript, 6.1): version 5: `queueId`. Version 6: `SHA256Tagged("direct", secret)`.

Vectors: `invite.json` (codes, sealed envelope with a fixed nonce, peer frames).

### 5.5 Peer frames of first contact (ready for Android)

The frames of PROTOCOL.md section 4 keep their layout; what they carry changes:

```
HELLO   u8 2 | u8 2 | raw32 secret | raw16 channelId | bytes helloEnvelope        (secret = sealKey of version 5, secret of version 6)
GET_BUNDLE answer (version 6)   u8 0x81, bytes bundle
HELLO answer (version 6, direct)   u8 0x80, bytes dataEnvelope        (I's first message, a DATA envelope of 7.5)
```

`helloEnvelope` is the HELLO envelope of 7.5, made by 6.1 (2266 bytes in the 1 KiB bucket). `channelId` is 16 random bytes chosen by J; I refuses a channelId it already holds. The HELLO frame is PUT into the invite queue (version 5) or sent to the onion (version 6). After a version 5 HELLO I sends STATE through J's mailbox, as in build 26; that STATE is I's first DATA message.

The **inner HELLO message** (type 1) and STATE (type 5) are unchanged (PROTOCOL.md section 5), carried as the inner message of the HELLO envelope and of DATA envelopes.

### 5.6 MSG frame and ciphertext types (CHANGED in draft 3, ready for Android)

```
MSG  u8 2 | u8 3 | raw16 channelId | u8 ciphertextType | bytes ciphertext
  ciphertextType 34   DATA envelope (7.5), bare
  ciphertextType 35   link frame (6.4)
  ciphertextTypes 2, 3, 32, 33   libsignal or build 26 (stage 3) ciphertexts: never sent by a draft 3 build; see 6.5
```

The ciphertext is the envelope itself, not wrapped in anything. A mailbox PUT limit of 80 KiB still decides which frames may go through the mailbox (the 64 KiB bucket plus 90 bytes of envelope and 23 of frame fits; the 256 KiB bucket is direct only). Any other type is acknowledged and ignored like any undecryptable frame.

## 6. Handshake

The pattern is X3DH without a one-time prekey, plus an ML-KEM secret as in PQXDH. The people's identity keys take the place of X3DH's identity keys; the prekey signature is replaced by the secrecy of the invite (first contact) or by the link key (6.4). A 32-byte **binding** enters the transcript (5.4, 6.4).

### 6.1 J redeems

1. Obtain the bundle: PEEK `queueId` and open the bundle envelope (version 5), GET_BUNDLE (version 6), or read it from a link OFFER (6.4).
2. Check its exact length (1257) and version byte (2), that `ID_I` equals the expected inviter identity public key (the 32 bytes after the type byte of the invite's `identityKey`, or of the contact record for a link offer) and is valid (5.1), that the current time is not past `expiresAtMs` and `expiresAtMs` is not more than 7 days and 1 hour ahead (a contact cannot make HELLO_SENT last for ever or overflow an expiry, review N1). Otherwise stop. The invite's identity must also differ from J's own, and a person who redeems a code must not already hold a contact with that identity ("You are already connected to this person. To connect again, delete the old chat first.", G4; checked before anything is fetched). A connection the group engine makes for one member pair (18) is exempt: the other member may have deleted its contact, and refusing would leave the pair without a channel. Such a connection makes a new channel beside the old contact record, and the newest usable record is the one used for that person.
3. Take J's identity secret `id_sk_J` and public key `ID_J` (the account identity, 5.1). Create random `e_sk, E` (X25519) and `ratchet_sk, ratchet_pub`. Compute `(ct, ss_kem) = KEM.Enc(EK)`. For a version 5 invite, create J's receiving queue.
4. Compute:

```
dh1 = DH(id_sk_J, EPK)
dh2 = DH(e_sk, ID_I)
dh3 = DH(e_sk, EPK)
T   = SHA256Tagged("transcript", ID_I | ID_J | EPK | EK | E | ct | binding | i64 expiresAtMs)
hs  = HKDF(salt = T, ikm = 0xFF*32 | dh1 | dh2 | dh3 | ss_kem, info = Info("handshake"), 128)
RK0 = hs[0..32]  shared_hka = hs[32..64]  shared_nhkb = hs[64..96]  PQ0 = hs[96..128]
```

All transcript fields have fixed length. `ID_I`, `ID_J`, `EPK`, `E` are the 32-byte forms. `T` is kept with the relationship.

5. Set up the ratchet in the Alice role (7.1), build the HELLO as message `n = 0` of epoch 0, and in one transaction commit the state and the exact HELLO bytes. Delete `e_sk`, `ss_kem`, the DH outputs and `hs`. Keep `ID_I` and `ID_J`.
6. Send the exact bytes (HELLO frame of 5.5, or a link HELLO of 6.4). Retry the same bytes. Never re-encrypt.

J then waits in `HELLO_SENT` and sends no Swell message until I's first reply authenticates.

**Entropy draw order (for the vectors).** `E` (32 bytes), `ratchet_sk` (32 bytes), then the KEM encapsulation. I's bundle: `epk_sk` (32 bytes), then the ML-KEM seed (64 bytes). A later DH step draws 32 bytes; a new ML-KEM key for an epoch draws 64 bytes; an encapsulation of a received `EK` is a KEM encapsulation.

### 6.2 I accepts

1. Check `ver=2, kind=1` and the exact prefix layout, that the time is not past `expiresAtMs` + 10 minutes, and that `ID_J` in the prefix is valid.
2. Compute `dh1 = DH(epk_sk, ID_J)`, `dh2 = DH(id_sk_I, E)`, `dh3 = DH(epk_sk, E)`, `ss_kem = KEM.Dec(dk, ct)`, then `T` and `hs`. `id_sk_I` is the account identity.
3. Set up the ratchet in the Bob role (7.1) and run the normal receive (8.3), with the HELLO allowed this once.
4. On failure, drop it. A bad `ct` gives a random secret by implicit rejection, so the header AEAD fails. There is no refusal byte and no answer. A HELLO from someone who does not hold the private key of the `ID_J` it names fails the same way, because `dh1` cannot be computed without it.
5. On success `ID_J` is authenticated as the other person's identity (serialized `0x05 | ID_J`). In one transaction: commit the ratchet state, the contact (identity key `0x05 | ID_J`) and J's message. Delete `dk`, `epk_sk`, the DH outputs and `hs`. `epk_sk` stays only as the current ratchet private key until I's first DH step replaces it (8.3), which happens in the same receive.
6. Invite path: refuse an `ID_J` equal to `ID_I`; for a connection made for one group member, refuse any `ID_J` other than the member it was made for (18); ACK every envelope in the invite queue, stop fetching it, and never parse a later HELLO. Approval (`WAIT_APPROVAL`) works as in draft 1.

I's first reply is ordinary DATA: STATE (5.5), a best-effort frame, so it carries no PQ field (7.6). I makes the key of every odd epoch, and `EK(1)` rides on I's first message that may carry a PQ field, a durable one (answer to Q7).

### 6.3 Authentication

J is sure it talks to whoever holds the private key of the identity the invite named (without it `dh2` cannot be computed, and no reply opens). I is sure it talks to whoever holds the private key of `ID_J` (without it `dh1` cannot be computed, and the HELLO does not open). Both get key confirmation when the first reply of I opens at J. First contact is trust on first use: the first time, the identity key comes from the invite, and only the safety number (11) tells a person it was the right one. The formal models prove, for one session and under perfect cryptography, mutual authentication with key confirmation (properties 2, 3, 2-2, 2-3) for the draft 2 handshake with random identity keys, and, for draft 3, `docs/FORMAL-RESULTS.md` section "Results for draft 3" (`docs/formal/swell3-link.pv`): secrecy and injective mutual authentication of unbounded link handshakes under persistent identity keys, RESET authenticity without reflection, forward secrecy against a later theft of both identity secrets, and secrecy against a recording quantum attacker (3-1 to 3-5); as expected, an active quantum attacker breaks link sessions (3-6, D16). These are model results with the limits listed there, not proofs about the code.

A person who knows the invite (a leaked code) and also controls the mailbox can swap the bundle; J then gets a session nobody can finish (no `dh2`), so the effect is denial of service, not impersonation. Whoever uses a leaked code first becomes the contact; the safety number is the check.

### 6.4 Link frames: starting or repairing a session between contacts (CHANGED in draft 3, ready for Android)

Two people who are contacts hold each other's identity keys. That is enough to start a session without any other channel, which is needed after an update from libsignal, after a restore (sessions are not in backups), and after a lost state. **The link key** is the static-static DH of the two identity keys:

```
LK  = HKDF(salt = channelId, ikm = DH(my identity secret, their identity public), info = Info("link", lo, hi), L = 32)
      lo, hi = the two serialized identity keys (33 bytes each) in unsigned byte order
link frame (MSG ciphertext type 35) =
      u8 3 | raw12 nonce | AEAD(LK, nonce, ad = "SWL3-L" | u8 3 | channelId | sender33 | receiver33, padded)
padded  = i32 length | content | zero bytes up to a bucket (7.4 padding rules, buckets 1, 4, 16 KiB ...)
content = i64 sentAtMs | frame
frame   = inner type 26 frame, below
```

`nonce` is 12 random bytes (never reused with one key). The AD names the sender and receiver, so a frame cannot be reflected to its sender or moved to another channel. The receiver derives the same `LK` and opens; a frame that does not open is dropped without any other effect (the mailbox and anyone who lacks an identity secret cannot make one). Vector `link.json`.

**Frames**, inner message type 26 (`SWELL_SESSION`; the layouts of draft 2):

```
u8 26 | u8 1 | raw16 offerId | bytes bundle      OFFER, I -> J       (link frame)
u8 26 | u8 2 | raw16 offerId | bytes hello       HELLO, J -> I       (link frame; hello = the HELLO envelope of 7.5)
u8 26 | u8 3 | raw16 offerId                     READY               (inside the first DATA message each way)
u8 26 | u8 4                                     RESET: "I hold no session for you"     (link frame)
u8 26 | u8 5 | raw32 sessionHash                 SYNC: sessionHash = SHA256Tagged("session", T) of the session held, or 32 zero bytes  (link frame)
```

**Acceptance.** A link frame is taken only when all hold; otherwise it is ignored:
- it arrived as MSG type 35 for the `channelId` of a contact whose handshake is finished and who is not blocked, waiting or ended;
- it opens under the link key of that contact's identity key;
- `sentAtMs` is not more than 15 days before and not more than 1 hour after the receiver's clock;
- OFFER comes from the phone that should be I (the lower serialized identity key in unsigned byte order), HELLO from the phone that should be J. Only I makes offers, so two offers cannot cross;
- RESET and SYNC are ignored when `sentAtMs` is more than 5 minutes older than the start of the session the receiver holds (a held-back RESET cannot kill a healthy newer session, review O14);
- **and (CHANGED in draft 3, answer to Q10)** they are ignored when `sentAtMs` is earlier than the `sentAtMs` of the link frame from the same phone that started the session the receiver holds: J notes I's OFFER time when it answers it, I notes J's HELLO time when it accepts it (record `swp.peerstart` per contact, never in a backup, deleted with the session and the contact). Both times come from the sender's clock, so no allowance for skew is needed. Without it, a RESET that waited in the mailbox while a new session was made seconds later ends that session and the messages sent into it. A session made by an invite has no such record, and only the 5-minute rule applies.

**Binding.**

```
binding = SHA256Tagged("upgrade", channelId | lo | hi | offerId)        lo, hi: the two serialized identity keys, unsigned byte order
```

**Steps.**
1. I has a contact and no session (just updated, restored, or after a RESET): it makes a bundle for its identity key (expiry 7 days), commits it as `OFFERED` with a fresh `offerId`, and sends OFFER. If no HELLO arrives within a day, I sends the same OFFER bytes again; after expiry it makes a new offer.
2. J runs 6.1 with the binding and the contact's identity as the expected inviter, the HELLO inner message being `READY(offerId)`; commits `HELLO_SENT` with the exact HELLO bytes, and sends HELLO as a link frame. The same OFFER again gets the same HELLO bytes again, never a new HELLO. A newer offer replaces a pending one. An `ACTIVE` session is never replaced by an offer.
3. I runs 6.2 with the binding. The HELLO must carry `READY` for the same offer, and `ID_J` must equal the contact's identity. In one transaction I commits `ACTIVE` and deletes the offer's secrets. I then sends `READY(offerId)` as its first DATA message.
4. J becomes `ACTIVE` when the first DATA message from I authenticates, whatever it carries.

**Sending and receiving.** A phone sends DATA only when its side is `ACTIVE` (or `HELLO_SENT` for J's HELLO). With no session, messages wait in the outbox. Frames already sealed under a session that is gone can never be read: they are sealed again under whatever session comes next (a new key, never a reused one).

**Lost state.** A phone that receives a DATA frame (type 34) for which it holds no session, or only an offer, sends RESET (at most once a day per contact). A J that has messages to send and no session sends RESET the same way, so an I that never knew J lost its state makes a new offer. An I that held only an offer drops it before the RESET and follows with a new offer with a new `offerId`, so a HELLO for the old offer still on its way is refused (review F1). The receiver of RESET deletes its Swell state for that contact, re-seals queued frames, and I then makes a new offer. Messages sent into the lost session are not readable and are not shown.

**A restored I (CHANGED in draft 3).** I makes offers only when it holds no session, so a J that holds an `ACTIVE` session and receives an OFFER (fresh by the rule for RESET and SYNC above) knows that I lost it, for example by a restore. J does not replace its session with the offer; it sends SYNC with its session hash, at most once a day for the same `offerId` (a new offer gets its own SYNC, so a second restore on one day is not held up). I holds no session, so the hashes differ: I drops its offer, sends RESET and a new offer, and J answers that one. Without this rule a restored I could not reach a J that never writes first.

**A restored J that had not finished.** A phone restored from a backup made between redeeming an invite and the inviter's first answer has the contact `WAITING` and no session, and it knows no queue of the inviter to send RESET to. That chat cannot finish: the person deletes it and asks for a new code.

**Sessions that differ.** SYNC carries `SHA256Tagged("session", T)` of the session the sender holds (or 32 zero bytes). A phone sends it, at most once a day per contact, after 3 DATA messages from that contact that were well-formed but did not open (duplicates do not count), and as the answer to an offer described under "A restored I". Record of the limit: `i64 sentAt`, or `i64 sentAt | raw16 offerId` when it answered an offer. The receiver compares it with its own value in constant time: equal means nothing; different means it deletes its Swell state, re-seals queued frames and sends RESET at once, so both start over with a fresh offer.

**Ends.** `OFFERED` and `HELLO_SENT` end at the offer's expiry plus the 10-minute accept grace; the sweep at app start deletes them, and also deletes a record that no longer decodes (it counts as no session from the moment it fails to decode, review F11). Removing a contact removes its Swell record and its RESET and SYNC stamps.

**Offer timing (review F8).** I offers at app start, after an update, whenever a contact has no session, and again when the contact's STATE announces bit 8.

**Safety number.** The number (11) depends only on the two identity keys, so a session made by a link handshake shows the same number as one made by an invite, and a verified number stays verified.

**Switch off.** There is no switch.

### 6.5 Capabilities and the "update" rule (CHANGED in draft 3, ready for Android)

`CAP_SWELL_PROTOCOL = 128` (bit 7) is announced in HELLO and STATE by every build that has the Swell Protocol, build 26 included. **`CAP_SWELL_V3 = 256` (bit 8) is announced by every draft 3 build**, on both platforms, always (no switch, no OS condition): it says "I send and read MSG type 34 and 35, invite versions 5 and 6, SwellSig". A contact record that lacks bit 8, or a contact from whom a frame of ciphertext type 2, 3, 32 or 33 arrives, runs an older app: the chat shows the plain line **"Ask <name> to update Swell"** (never an error text), nothing is sent to that contact except link frames (a new app tries the link handshake of 6.4 once a day, which an old app ignores), and messages typed meanwhile wait in the outbox. The line goes away when a session is `ACTIVE` and the contact has announced bit 8. A phone that reads types 2, 3, 32 or 33 from a contact acknowledges them and drops them; it never tries to open them.

**A session kept from stage 3 (CHANGED in draft 3).** Two internal testers of build 26 may hold an `ACTIVE` draft 2 session (it is kept, 1). While one of them still runs build 26 it cannot read type 34, and the other cannot tell from the session alone. So the rule is by bit 8, not by the session: to a contact that has not announced bit 8, a draft 3 phone sends only STATE (inner type 5, how bit 8 is learned) and READY (inner type 26); everything else waits, and the chat shows the update line even though a session exists. A phone that receives a STATE announcing bit 8 from a contact it did not know as draft 3 answers once with its own STATE (its earlier STATE may have reached an older app and been dropped) and then sends what waited. A phone that has never held a draft 2 session (every Android build) knows that each of its `ACTIVE` sessions was made by a draft 3 peer, and may skip holding frames back by bit 8 (answer to Q5).

**Waiting is not failing.** A message, a group frame or a status update that cannot be sealed because the contact has no `ACTIVE` session stays in the outbox unchanged: it does not count as a failed try, gets no backoff and is never given up for it (the "Not sent" state is only for real delivery failures). Trying to seal it asks for a session (I offers, J sends RESET, both at most as often as 6.4 allows). When a session becomes `ACTIVE` (I after a link HELLO, J at the first readable message), the phone sends what waited: the one-to-one outbox, then the group rows. What must hold everywhere is that a missing session is not a failed try. A phone without a durable one-to-one outbox (Android build 27) may keep waiting texts in memory; after a restart they show as not sent and can be retried (answer to Q6, O18).

## 7. Ratchet

Double Ratchet with header encryption as in sections 3 and 4 of revision 4 of the published specification, plus the post-quantum ratchet of 7.6. Only the differences are listed.

### 7.1 Initial state

| Field | J (Alice) | I (Bob) |
|---|---|---|
| DHs | `(ratchet_sk, ratchet_pub)` | `(epk_sk, EPK)` |
| DHr | `EPK` | None |
| RK, CKs, NHKs | `KDF_RK(RK0, DH(ratchet_sk, EPK))` | RK = `RK0`, CKs = None, NHKs = `shared_nhkb` |
| CKr | None | None |
| HKs | `shared_hka` | None |
| HKr | None | None |
| NHKr | `shared_nhkb` | `shared_hka` |
| Ns, Nr, PN | 0 | 0 |
| PQ | epoch 0, send epoch 0, keys `{0: PQ0}` | same |

### 7.2 Key derivation

```
KDF_RK(RK, dh) : HKDF(salt = RK, ikm = dh, info = Info("root"), 96) -> RK' | CK | NHK
KDF_CK(CK)     : CK'   = Expand(CK, Info("chain"), 32)
                 mk_dr = Expand(CK, Info("message"), 32)
combine        : mk | body_nonce = HKDF(salt = PQ_e, ikm = mk_dr, info = Info("pq-message", i32 e), 44)
Header key use : hk_enc = Expand(hk, Info("header-enc"), 32)
                 hk_iv  = Expand(hk, Info("header-iv"), 32)
```

`e` is the epoch in the message's header and `PQ_e` that epoch's key (7.6). Message number `n` uses the chain key reached after `n` steps from the chain's start; `n` starts at 0.

### 7.3 Header

Plaintext header, exactly 44 bytes:

```
raw32 dh_pub | i32 pn | i32 n | i32 epoch
```

`pn`, `n` and `epoch` must be 0 or more. A chain carries at most 2^16 messages (`MAX_CHAIN`); a sender at the limit stops sending on that chain until a reply allows a DH step.

```
hnonce = Expand(hk_iv, Info("header-nonce", header), 12)
hct    = AEAD(hk_enc, hnonce, ad = "SWL2-H" | prefix | T, header)        60 bytes
```

`prefix` is `u8 ver | u8 kind` and, for HELLO, also `raw32 ID_J | raw32 E | raw1088 ct`. A receiver that opens a header recomputes `hnonce` from it and drops the message if it differs.

### 7.4 Body

```
body    = AEAD(mk, body_nonce, ad = "SWL2-M" | T | prefix | hnonce | hct, padded)
padded  = i32 length | content | zero bytes up to the bucket size
content = pq field | inner message
pq field: u8 0                                  none
          u8 1 | i32 t | raw1184 ek             EK(t)
          u8 2 | i32 t | raw1088 ct             CT(t), t > 0
```

Buckets are exactly 1024, 4096, 16384, 65536 and 262144 bytes, as `PROTOCOL.md` section 1. Pick the smallest with `4 + length(content) <= bucket`. The receiver rejects any `padded` whose size is not a bucket, a `length` below 1 or above size minus 4, any non-zero padding byte (checked in constant time), an unknown pq kind and a `t` of 0 or less. Inner messages keep their `PROTOCOL.md` layouts; the mailbox PUT limit (80 KiB) still decides which frames may go through the mailbox, as today.

### 7.5 Envelopes

```
DATA  : u8 ver=2 | u8 kind=2 | raw12 hnonce | raw60 hct | body
HELLO : u8 ver=2 | u8 kind=1 | raw32 ID_J | raw32 E | raw1088 ct | raw12 hnonce | raw60 hct | body
```

The body runs to the end of the envelope. DATA costs 90 bytes on top of the bucket (1114 bytes for a short text); a message with a PQ field moves to the 4 KiB bucket. HELLO in the 1 KiB bucket is 2266 bytes. These sizes are checked by the tests.

A DATA envelope is the `ciphertext` of an ordinary MSG frame with ciphertext type 34, bare (5.6); the HELLO envelope travels in the HELLO frame of 5.5 or in a link frame (6.4). It is the same on the direct onion path and through the mailbox (CHANGED in draft 3: no libsignal layer, no bucket shrink). Sizes: a DATA envelope in the 1 KiB bucket is 1114 bytes, plus 23 bytes of MSG frame.

### 7.6 Post-quantum ratchet

Designed from the public descriptions of SPQR and ML-KEM Braid (section 2), without reading any implementation. It is simpler than Braid (deviation D10).

**State per side:** `epoch` (highest epoch whose key is known), `sendEpoch` (`epoch` or `epoch - 1`), the keys `PQ_e` of `epoch` and up to 3 older epochs, a pending keygen (`seed`, `ek`, target `t`), a pending ciphertext (`ct`, target `t`), the number of messages sent in the current epoch and the time it was confirmed.

**Roles:** the keygen side of epoch `t` is I for odd `t` and J for even `t`. The other side encapsulates.

**Key schedule:**

```
PQ_t = HKDF(salt = PQ_{t-1}, ikm = ss_t, info = Info("pq-epoch", i32 t, SHA256Tagged("pq-kem", ek_t | ct_t)), 32)
```

**Send.** A frame may carry a pq field only if it is durable (an outbox, group outbox or status row whose exact bytes are retried until delivered); best-effort frames (receipts, typing, call signals, STATE, upgrade frames) never carry one and change no PQ state (review F5). A field is also not attached when it would move a frame whose bucket is above 16 KiB into a larger bucket; it waits for a smaller frame (review F14). Within those limits, choose the pq field:
1. A pending CT: attach `CT(t)` to the first frame that may carry a field after encapsulating. Each new sending chain that begins while it is pending sets a "repeat owed" mark, and the next frame that may carry a field repeats `CT(t)` and clears the mark, even when the chain starts with best-effort frames (review N3). Stop at confirmation.
2. Else a pending keygen: attach `EK(t)` the same way.
3. Else, if this side is the keygen side of `t = epoch + 1`, `sendEpoch == epoch`, and either `epoch == 0`, or at least 25 messages were sent in this epoch, or 6 hours passed since it was confirmed: make a fresh ML-KEM-768 key, store its seed, and attach `EK(t)`.
The message uses `sendEpoch` in its header and `PQ_sendEpoch` in `combine`.

**Receive**, after the body opened under the header's epoch key, on the same copy of the state:
- If the header's epoch equals `epoch` and `sendEpoch < epoch`: the peer holds the new key. Set `sendEpoch = epoch`, note the time, and drop the pending CT.
- `EK(t)` with `t == epoch + 1`, this side not keygen for `t`, `sendEpoch == epoch` and no pending CT: `(ct, ss) = KEM.Enc(ek)`, derive `PQ_t`, set `epoch = t` (but `sendEpoch` stays), and keep `CT(t)` pending.
- `CT(t)` with `t == epoch + 1` and a pending keygen for `t`: `ss = KEM.Dec(seed, ct)`, derive `PQ_t`, delete the seed, set `epoch = sendEpoch = t`.
- Any other pq field is ignored, including an `EK` that fails the FIPS 203 check; the message itself is still delivered, because it authenticated (review F9).
- Keys of epochs older than `epoch - 3` are deleted.

A message whose header names an epoch this side does not hold is dropped like any message that fails to open.

**Why the encapsulating side waits.** The CT travels in a message under the old epoch, because the keygen side cannot read a message under an epoch it cannot yet derive. The encapsulating side switches when it sees the keygen side use the new epoch.

**Cost.** One encapsulation key and one ciphertext per epoch, each usually in one message (it moves that message to the 4 KiB bucket), repeated only on message 0 of a new sending chain if lost.

**Healing.** A theft at any moment reveals the epoch keys held (up to four) and a pending seed. The first epoch whose ML-KEM key is generated after the theft is unknown to the thief even with every X25519 key broken, and every later epoch key descends from it. With the pacing above, that is at most two epoch changes after the theft (formal property 2-P2).

## 8. Receive and send

### 8.1 Limits

`MAX_SKIP = 1000` per gap. At most 2000 stored skipped keys per relationship; when the store is full the oldest are deleted, so the ratchet keeps moving and only those old messages become unreadable. Skipped keys and the old header keys they need expire 15 days after storing. A skipped key stores `mk_dr`; it is combined with the epoch key named in the late message's header when used, so that epoch key must still be held (4 epochs).

### 8.2 Send

There is one serialized writer per relationship (the engine actor).

1. In one transaction: choose the pq field, advance `CKs` and `Ns`, encrypt, and store the exact envelope with the message or outbox entry.
2. Send the exact bytes. Retries repeat those bytes and never re-encrypt.

A crash before the transaction changes nothing. **Swell state is never in a backup and never restored**, because a rollback would reuse `mk` and `body_nonce` (`SwellSessions.ns` is left out of `Backup.swift`; 6.4 "Lost state" covers the restored phone).

### 8.3 Receive

Work on a copy of the state.

1. Parse `ver`, `kind` and exact lengths.
2. Build the candidates: the distinct header keys among the stored skipped keys, `HKr` if set, and `NHKr`. Try each. Exactly one must open `hct` with the derived nonce; otherwise drop.
3. Check `pn, n, epoch >= 0`. Then:
   - **Stored skipped key** `(hk, n)` present: use it and delete it.
   - **`HKr`**: `dh_pub` must equal `DHr`. `n < Nr` is a duplicate: drop. `n - Nr > MAX_SKIP`: drop. Store skipped keys up to `n`, take the next key.
   - **`NHKr`**: `dh_pub` must differ from `DHr`. If `HKr` is set, `pn >= Nr` and `pn - Nr <= MAX_SKIP` must hold and skipped keys up to `pn` are stored under `HKr`. Run the DH ratchet of the published section 4.4 (the old `DHs` private key is deleted here). Then `n <= MAX_SKIP` must hold; store skipped keys up to `n`.
   - Any other header key: duplicate, drop.
4. Take `PQ_epoch` from the header's epoch (drop if not held), `combine`, open the body, strictly parse `padded`, then apply the pq field (7.6). On any failure drop the copy.
5. In one transaction: commit the state and store the message. In Private Mode store the state only.
6. ACK on the mailbox.

### 8.4 What happens for each event

| Event | State | ACK | User sees |
|---|---|---|---|
| Valid DATA | commit | yes, after commit | message |
| Duplicate or replay | none | yes | nothing |
| Unknown `ver` or `kind`, bad length | none | yes | nothing |
| Header or body fails, unknown epoch | none | yes | nothing |
| Skipped-key store full | commit, oldest keys evicted | yes | message; evicted messages never appear |
| Gap above `MAX_SKIP` | none | yes | nothing; later messages on that chain also fail until the sender's next DH step |
| PQ field that does not fit the state | commit (message only) | yes | message |
| Type 34 with no session | none; RESET due | yes | nothing |
| Link frame (type 35) that does not open or fails 6.4 acceptance | none | yes | nothing |
| Types 2, 3, 32, 33 | none; the contact is marked as running an older app (6.5) | yes | the line "Ask <name> to update Swell" |
| Crash before commit | none | no, it returns | nothing |
| Crash inside the handling, 3 times for the same bytes | none | yes, unprocessed on the 3rd try | nothing (a durable in-progress note per envelope, for frames of types 34 and 35 only; review N1) |
| Crash after commit, before ACK | committed | next fetch, as a duplicate | message, once |


## 9. Labels

HKDF `info` (all through `Info`): `handshake`, `root`, `chain`, `message`, `pq-message`, `pq-epoch`, `header-enc`, `header-iv`, `header-nonce`, `safety`, **`link`** (draft 3). Tagged hashes: `bundle` (defined, unused in draft 3), `transcript`, `upgrade`, `pq-kem`, `session`, **`direct`** (draft 3). AD strings: `SWL2-H`, `SWL2-M`, **`SWL3-L`** (draft 3). SwellSig strings: **`swell-sig-v3`**, **`swell-sig-nonce`**, context **`swell-group-state-v1`**. Old raw-ASCII HKDF infos that do not use `Info`, unchanged since build 23: `swell identity v1` (5.1), `swell report v1` (19), `swell backup v1` (20). Values are in `docs/protocol-vectors/kdf.json` and Appendix A.

## 10. Relationship states

```
Invite path:
I: INVITE_OPEN -> (valid HELLO) -> WAIT_APPROVAL or ACTIVE ; INVITE_OPEN -> (expiry, cancel) -> DESTROYED
   WAIT_APPROVAL -> (accept) -> ACTIVE ; (decline, 7 days) -> DESTROYED
J: HELLO_PENDING -> (PUT answered) -> HELLO_SENT -> (first reply authenticates) -> ACTIVE
   HELLO_PENDING -> (mailbox refuses) -> FAILED ; HELLO_SENT -> (7 days, or cancel) -> FAILED
Link path (6.4), per contact, no session to begin with:
I: none -> OFFERED -> (HELLO for this offer) -> ACTIVE ;  OFFERED -> (7 days) -> none (a new offer follows)
J: none -> (OFFER) -> HELLO_SENT -> (first DATA message) -> ACTIVE
Both: ACTIVE -> (RESET received) -> none -> (I offers again)
      any -> (contact removed) -> DESTROYED (Swell record deleted with the contact)
```

## 11. Safety numbers (CHANGED in draft 3, ready for Android)

Pairwise, from the two **serialized identity keys** (33 bytes each, `0x05 | public`, 5.1), sorted by unsigned byte order into `lo` and `hi`:

```
okm = HKDF(salt = 32 zero bytes, ikm = lo | hi, info = Info("safety"), 60)
```

Digits: 12 groups of 5 bytes, each a big-endian number mod 100000 printed as 5 digits, separated by a space (60 digits). **QR code** (CHANGED in draft 3): the text `swell-safety:` followed by the base64url (no padding) of the 60 bytes of `okm`. Both phones compute the same text, so scanning is an equality check: the phone shows "verified" when the scanned text equals its own. Anything else that scans (another prefix, another length) is not a safety code. The number does not change while both identity keys stay; a new identity key (a person who restored with other words) is a new contact (6.2 step 6), so a verified mark never moves to another key. Vector `kdf.json` (`safety-33`; `safety-32` is the draft 2 vector with 32-byte inputs, the same function).

The Android `Fingerprint` of build 26 (libsignal's numeric fingerprint, 5200 iterations) is replaced by this; the numbers change once, at build 27, for everybody, and verified marks start again.

## 12. Removal and deletion

Removal deletes all relationship keys and the record (including the `swp` record), and stops fetching the queue without telling the contact.

| Key | Deleted |
|---|---|
| `mk`, `body_nonce` | after the transaction that uses them |
| `CK`, `RK` | replaced at each step |
| **`DHs` private key (current ratchet key)** | **at this side's next DH step, i.e. when the first message of the peer's next chain arrives. Until then a theft exposes it (section 3, A1)** |
| skipped keys (`mk_dr`) and old header keys | when used, when evicted, or 15 days after storing |
| **PQ epoch keys `PQ_e`** | **when 3 newer epochs exist** |
| **pending ML-KEM seed (keygen side)** | **at decapsulation of its CT, or at removal** |
| pending CT | public; dropped at confirmation |
| `e_sk`, `ss_kem`, DH outputs, `hs` | J, at the HELLO commit |
| `dk`, `ss_kem`, DH outputs, `hs` | I, at the accept commit; `epk_sk` is the first `DHs` and goes at I's first DH step, in the same receive |
| `dk`, `epk_sk`, invite or offer record | I, at invite or offer expiry or cancel |
| **identity secret** | **never deleted by the protocol: it is the account's, derived from the 12 words (5.1), and goes with the account** |

"Deleted" means removed from the database by the app. Old values may remain in database pages, the write-ahead log, flash wear levelling or storage snapshots. The database uses SQLCipher with `secure_delete` (`docs/DESIGN-ENCRYPTED-DB.md`); neither promises physical erasure. Swift cannot promise that memory is erased. `SP.wipe` reaches the bytes only when the array is their sole owner (a shared copy-on-write buffer is copied first, review F13), so the code calls it only on buffers it made and holds alone (HKDF outputs, DH outputs, the KEM secret on the accept side); elsewhere "deleted" means "removed from the stored state". The secret-bearing types are not `Equatable` outside the tests. Forward secrecy claims must carry this limit.

## 13. Tests and vectors

Shared vectors (`docs/protocol-vectors/*.json`, generated by the Swift code with fixed keys and recorded randomness, replayed byte for byte by Swift and Kotlin; Appendix A.12 explains the file conventions and how the Swift side regenerates them):

| File | Content | Section |
|---|---|---|
| `mlkem768.json` | seed to ek, ek and ct to ss, implicit rejection, invalid ek | 4 |
| `identity.json` | entropy to secret, public, serialized; invalid public keys | 5.1 |
| `signature.json` | X25519 to Edwards map, SwellSig signatures (exact bytes), negative cases, `strict` edge cases on which RFC 8032 verifiers can differ | 5.2 |
| `kdf.json` | `Info`, tagged hashes, KDF_RK, KDF_CK, combine, header keys, handshake key schedule, PQ epoch key, bindings, safety numbers and QR text | 4, 6, 7, 11 |
| `handshake-conversation.json` | invite-path handshake between two identities, then a conversation over two PQ epochs with out-of-order, duplicate, large, best-effort and tampered messages, every envelope exact; the randomness each side draws is recorded | 6, 7, 8 |
| `link.json` | link key and the four link frames exact; reflection, wrong channel, too old | 6.4 |
| `invite.json` | invite codes 5 and 6 and refused codes, the bundle from fixed randomness, the sealed bundle envelope with a fixed nonce, GET_BUNDLE, the inner HELLO, the HELLO envelope and peer frame for each version (recorded encapsulations), MSG frames of type 34 and 35 | 5.3 to 5.6, 6.1 |
| `group-state.json` | group state encoding, SwellSig signature, signed state, negative cases | 18 |
| `report.json` | report seal and open, report body, the padded body and its seal (what a phone sends) | 19 |
| `backup.json` | backup key, nonces, authenticated data, a small complete backup file | 20 |

Swift tests of the library: `ios/SwellProtocol/Tests/SwellProtocolTests` (the first six files above in `PrimitiveVectorTests` and `SessionVectorTests`, plus session, ratchet, PQ, parser fuzz, record and tamper tests). The four app-format files are made and checked by `ios/SwellSignal/Tests/SwellSignalTests/EngineVectorTests.swift`, with the same conventions (A.12). Swift tests of the engine: `ios/SwellSignal/Tests/SwellSignalTests` (first contact, link frames, update rule, groups, backup, every feature on the new session). Appendix A keeps the draft 2 values, which the vectors repeat.

Still to do before outside review: fuzzing of every parser beyond the unit-level pass, crash tests at every transaction boundary, a size report on devices, NIST ACVP ML-KEM vectors (O10).

## 14. Comparison with the owner rule

| Item | Published Signal design | Draft 3 |
|---|---|---|
| Post-quantum handshake | PQXDH | ML-KEM-768 with X25519, custom composition; secrecy, hybrid and authentication properties proved in a one-session model |
| Forward secrecy | Double Ratchet | same design; proved in the model with the A1 qualification Signal shares |
| Recovery after theft, classical | yes | yes, proved in the model (passive attacker) |
| Recovery after theft, post-quantum | Triple Ratchet with SPQR and ML-KEM Braid | **yes, by the epoch ratchet of 7.6; proved in an abstract model (2-P2)**, simpler than Braid (D10) |
| Offline, out of order | yes | yes, by bounded skipped keys (tested; not in the formal models) |
| Identity authentication | long-term identity keys, signed prekeys | long-term identity keys; no prekey signatures (D1); signatures only on group states (D15) |
| Calls | media keys from DTLS-SRTP | same; **not post-quantum yet** (target build 28) |
| Formal analysis | published, by outside researchers | internal models only, by the author's agent |
| Outside review | yes | **none yet; an independent audit is planned** |

**Verdict: on paper and in the internal models draft 3 matches the published Signal design on the protocol properties in the owner rule, except for outside review and for post-quantum calls. Any public text says that the Swell Protocol has not had an independent security audit yet and that one is planned. It never says "audited".**

## 15. Deviations from published constructions

An auditor should read this first.

| ID | Deviation | Risk |
|---|---|---|
| D1 | No signatures on bundles. The secrecy of the invite (first contact) or the link key (6.4) replaces the prekey signature. | A swapped bundle denies service but gives no key (6.3). |
| D2 | `EPK` is a single-use signed-prekey stand-in, no one-time prekey, no DH4. | Single use is enforced by the client, not a server. |
| D3 | `T` binds all public values, including `EK`, `ct` and the binding, through the salt. | Believed sound as a combiner, unproven computationally. |
| D4 | Chain KDF uses HKDF-Expand labels instead of HMAC with constants. | Low. |
| D5 | `mk` and `body_nonce` are derived directly; rollback reuses both. | 8.2 forbids rollback; backups exclude the state. |
| D6 | Header nonce derived from the header under a separate key. | 96-bit output; at the 2^16 per-key limit collision chance near 2^-65. Pending review. |
| D7 | `ID_J`, `E` and `ct` are in clear in an invite-path HELLO. Draft 3: `ID_J` is now the person's identity key, so the mailbox operator sees it (libsignal's pre-key message did too). | The operator can link the queues of one person's invites by identity key. Link frames and later traffic do not show it. O2. |
| D8 | (draft 2) Identity keys deleted after the handshake. **Replaced by D14.** | |
| D9 | The relationship is chosen by `channelId`. | |
| D10 | **PQ ratchet is not Braid.** Whole `ek` and `ct` in one message instead of erasure-coded chunks; one epoch at a time with alternating keygen sides and a confirmation step; pacing by message count and time. | Larger messages during an epoch change, visible as size. A lost message delays an epoch by one DH step. Healing is bounded by pacing, not by message count alone. |
| D11 | **Epoch keys mix into message keys only** (not into the root chain or header keys). | Header metadata is not post-quantum protected after a theft. Content healing is modelled (2-P2). |
| D12 | (draft 2) Upgrade authentication rested on libsignal. **Replaced by D16.** | |
| D13 | One `PQ_e` per epoch for all messages of both directions, combined with the per-message `mk_dr`. | Per-message forward secrecy comes from `mk_dr`; `PQ_e` adds post-quantum healing. |
| D14 | **One identity key per person, used in the handshake (CHANGED in draft 3).** `ID_I`, `ID_J` are the persistent identity keys instead of random per-relationship keys. | Contacts can recognise one person across relationships; a stolen identity secret (the 12 words) lets the thief start sessions as that person; handshake authentication is classical (X25519), not post-quantum, as in PQXDH. |
| D15 | **SwellSig** (5.2): Ed25519 verification under the Edwards form of the X25519 identity key, signing with the X25519 scalar, deterministic nonce from SHA-512, strict verification (R and A of order exactly L, canonical R). Hand-written scalar and point arithmetic. | The same scalar is used for DH and signing (separated by domain strings). The integer code is not constant time. It was written from RFC 8032 and 7748. Needs review. |
| D16 | **Link frames** (6.4): sealed with a key from the static-static DH of the identity keys, no forward secrecy for the frame. | A stolen identity secret lets the thief read past link frames (OFFER, HELLO, RESET, SYNC: public keys and a ratchet HELLO, no message content) and forge new ones until the owner makes a new identity. Message content has full forward secrecy from the ratchet. |
| D17 | The safety number is one HKDF of the two identity keys, not an iterated hash. | 60 digits of output from a single hash: second-preimage cost is the same, but a slow hash is not used. |
| D18 | A session is made again after an update or restore by link frames, authenticated only by the identity keys the phones already hold. | A contact whose phone was restored with other words is a new identity, hence a new contact. |

## 16. Open items

- O1. Closed: the direct onion path uses the same MSG frame (type 34).
- O2. Sealing `ID_J`, `E` and `ct` in an invite-path HELLO. With draft 3 this matters more (D7). The HELLO frame carries `sealKey` in clear, so sealing under it gains nothing; a fix needs a frame layout that drops `secret` from the HELLO frame or a key from a DH with `ID_I` (which J can compute: `DH(E_seal, ID_I)`).
- O3. Closed: the inner HELLO bytes are those of 5.5.
- O4. Queue rotation (`PROTOCOL.md` 6b) on this ratchet.
- O5. Closed by draft 3 (6.4, 6.5): contacts that never upgraded start a session by link frames or see the "update" line.
- O6. Closed: the 12 words make the identity (5.1) and the backup key (20); sessions are not in a backup and are repaired by link frames (6.4).
- O7. ML-KEM: Apple CryptoKit (iOS 26, macOS 26) and Bouncy Castle (Android). No older iOS (4.1).
- O8. Closed by 7.6, pending outside review.
- O9. ML-KEM patent position.
- O10. Fuzzing, crash tests at every transaction boundary, NIST ACVP vectors, cross-implementation runs through the real mailbox (checklist section 5).
- O11. Contact info shows the protocol a chat uses. Still open: a "Verify again" mark after a lost or restored phone.
- O12 (review F6). The operator can stall the PQ ratchet by dropping the frames that carry EK or CT, which stand out by size. Planned fix: carry the field in pieces inside the padding of ordinary frames, so an epoch change costs no visible size; and report an epoch that has not moved for a long time despite traffic in the debug report.
- O13 (review F7). After healing, a receiver still accepts messages under up to three older epoch keys, so an attacker who stole a state and stayed passive through healing can later forge messages under an old epoch. Planned fix: an order rule on receive, so a message later in send order than one accepted under epoch e must name an epoch of at least e.
- O14. Closed in 6.4: RESET and SYNC older than the session start minus 5 minutes are ignored. (review F10a, F10d; the oracle of F10d is closed because link frames need the identity keys.)
- O15 (review F12). Header-key trial is quadratic in the number of distinct stored header keys (up to 2000). Planned fix: keep skipped keys for at most the last 8 receiving chains and store the header-key list once per chain.
- O16. Calls are not post-quantum: WebRTC media keys come from DTLS-SRTP. Planned: frame encryption with keys from this ratchet (build 28). Not specified in draft 3.
- O17. SwellSig integer arithmetic: constant-time implementation and independent review.
- O18. A durable one-to-one outbox on Android, so a text, file or voice note that waits for a session survives a restart (6.5).
- Integer safety (review N1): every count, length, index and time a contact can choose is bounded before arithmetic (`n`, `pn` below `MAX_CHAIN`; expiries checked against now plus 7 days; times added with saturation, `SP.sat`, `SP.within`), stored records are range-checked on decode, and a fuzz test feeds random values to every parser and link step.

## 17. Answers to the formal gaps G1 to G6

- **G1 (FS wording, ratchet key in the deletion table).** Section 3 states forward secrecy with the A1 qualification and the skipped-key limit; section 12 lists the `DHs` private key, the PQ epoch keys and the pending ML-KEM seed.
- **G2 ("Neither claim is proven").** Section 6.3 cites the model results and their limits.
- **G3 (post-quantum recovery).** Section 7.6. Formal property 2-P2.
- **G4 (a known person sends a new invite).** Identity keys are one per person again (D14), so the engine recognises an existing contact and refuses with "You are already connected to this person. To connect again, delete the old chat first." (`EngineError.alreadyContact`), as in build 26. A person with a new identity key is a new contact.
- **G5 (active healing after a theft).** No protocol can notice an injected key (A2). App behaviour: the safety-number section of every contact says "If your phone or theirs was lost, stolen or restored from a backup, compare the numbers again." Planned (O11): a "Verify again" mark on contacts verified before such an event.
- **G6 (skipped keys and theft).** Yes: section 3 lists stored skipped keys as an exposure limit next to A1. The limits (2000 keys, 15 days) bound it.

## 18. Groups (ready for Android)

A Swell group has no server side, no shared key and **no sender keys**. Each member sends each frame (inner type 18, `docs/PROTOCOL.md` section 5e) to every other member through that pair's own session, as an ordinary DATA message. The frame text of section 5e is normative; what changes in draft 3 is only the signature on a state and the way members connect.

- **Member identity.** The serialized identity key (33 bytes, 5.1). The roster is sorted by it in unsigned byte order.
- **State and signature (CHANGED in draft 3).** The state layout is that of section 5e (`u8 1, raw16 groupId, i64 version, raw32 previousHash, bytes sequencer, str name, raw32 avatarHash, i32 timerSec, i32 count, (bytes identityKey, str name, u8 role, i64 joinedVersion) x count`, `stateHash` = SHA-256 of the state bytes). A signed state is `bytes state, bytes signer, bytes signature`, with `signer` the 33-byte identity key of the signer and `signature` = **SwellSig** (5.2) of the state bytes under context `swell-group-state-v1`, 64 bytes (before: libsignal's identity-key signature over the ASCII string `swell-group-state-v1` followed by the state). A signature is valid only if `signer` is a valid identity key (5.1), the signature is exactly 64 bytes and SwellSig verifies. The creator signs version 1 and is the first sequencer. Each next version has version + 1, `previousHash` of the state before it, and is signed by the sequencer that state names. A state signed by anyone else is ignored. Vector `group-state.json`.
- **Connecting members.** For each pair without a channel, the member with the higher `joinedVersion` makes a one-use **version 5** invite for that one person and sends it as INVITE through an admin, inside the sessions. The maker accepts a HELLO only from the identity it was made for (6.2 step 6): the HELLO opens only for the holder of that identity key, so another redeemer fails to open and is dropped, and the invite stays open. A group link (version 16) carries the admin's serialized identity key and queue as before; the asker's one-use code inside the request is a version 5 code.
- **Groups made before build 27** carry states signed with libsignal's signature, which SwellSig does not verify. Section 18.1.

### 18.1 Groups made before build 27

A group made before build 27 has a current state signed with libsignal's identity-key signature, which SwellSig does not verify.
- A stored state is never checked again, so the members keep the group, its roster and its chats.
- A state received from another phone is checked (a joiner's first state, a sync, a commit), so the old signature cannot be handed on.
- Therefore the sequencer, when it runs a draft 3 build and finds that its current state does not verify with SwellSig, signs the same state again as the next version, once: version + 1, `previousHash` = the hash of the old state, the same roster, name, photo and timer, sent as an ordinary commit (frame op 6). Members accept it as any commit from the sequencer, and nothing shows in the chat. From then on every state of the group is SwellSig-signed.
- Until the sequencer has done this (its app is older, or it has not opened the app), nobody new can join that group and a member that falls behind cannot sync; messages between the existing members go on.

## 19. Report seal (ready for Android)

A problem report goes to a Jiji Labs mailbox queue, sealed so only the report inbox's private key opens it. The format is that of build 26 (`Report.swift`, `Report.kt`); it never used libsignal.

```
inbox string  "<56-char onion>:<queueId hex, 64>:<inbox public key hex, 64>"
seal(inboxPublic, plain):
  eph      = fresh X25519 key pair
  shared   = DH(eph secret, inboxPublic)
  key      = HKDF(salt = ephPublic | inboxPublic, ikm = shared, info = ASCII "swell report v1" (raw, no Info()), L = 32)
  nonce    = 12 random bytes
  envelope = u8 1 | raw32 ephPublic | raw12 nonce | bytes(ciphertext | 16-byte tag)         AES-256-GCM(key, nonce, no associated data, plain)
body (plain) = u8 1 | i64 nowMillis | str reason (at most 2000 chars) | bytes identityKey | i32 n | (i64 sentAt, u8 incoming, str text (at most 4000 chars)) x n | [raw32 queueId]
              n at most 50; queueId present only when the reporter holds the queue it PUTs to for that contact
```

`identityKey` is the reported contact's serialized identity key (33 bytes). **The phone pads the body before sealing** (answer to Q2): `plain = i32 length | body | zero bytes` up to the first bucket of 1, 4, 16, 64 or 256 KiB that holds it (PROTOCOL.md section 1), and the inbox tooling unpads after opening. Opening: the inbox owner derives `shared = DH(inbox secret, ephPublic)` and the same key. Vector `report.json` (fixed ephemeral key and nonce): `envelopePadded` is what a phone sends and must be reproduced byte for byte and open; `envelope` is the seal of the unpadded body alone.

## 20. Backup (ready for Android)

The outer format is identical on iPhone and Android and never used libsignal. The records inside differ per platform (an iPhone backup is refused by Android and the other way round).

```
file    = "SWBK" | u8 1 | raw32 salt | chunk*
chunk   = u8 last | u32 length (big endian) | AES-256-GCM ciphertext | 16-byte tag          length = ciphertext + tag
key     = HKDF(salt = file salt, ikm = account entropy (16 bytes), info = ASCII "swell backup v1" (raw), L = 32)
nonce   = 00 00 00 00 | u64 chunk index (big endian)               the index starts at 0
ad      = "SWBK" | u8 1 | salt | u64 chunk index (big endian) | u8 last          (the 37-byte header, the index and the last flag)
```

A chunk holds at most 1 MiB of plaintext; exactly one chunk, the final one, has `last = 1`. A changed, reordered or cut file does not open. The plaintext is a stream of items: `u8 1 account: bytes identityKey`, `u8 2 setting: str key, str value`, `u8 3 record: str ns, str key, bytes value`, `u8 4 file: str name, i64 size, raw bytes`, and finally `u8 5 end: i64 recordCount, i64 fileCount`.

**CHANGED in draft 3.** A backup contains no libsignal records (`sess`, `idk`, `pk`, `spk`, `kpk`, `keep`) and no Swell sessions (`swp*`, never in a backup, 8.2). A phone restored from a backup has the account (the same identity key, from the 12 words), the contacts and the chats, and **no sessions**: it repairs each one with link frames (6.4), and the step that skipped the sending counters of every session after a restore (build 24 to 26) no longer exists. A restored copy that meets a build 26 backup ignores its libsignal records. One case cannot be repaired: a contact that was still waiting for the inviter's first answer when the backup was made (6.4, "A restored J that had not finished"). Vector `backup.json`.

## 21. What libsignal did, and what replaced it

| libsignal function | Where it was used | Replaced by |
|---|---|---|
| Identity key pair (`IdentityKeyPair`, `PrivateKey`, `PublicKey` serialization `0x05 | key`) | account identity (`Store.kt`, `LibSignalCrypto`) | 5.1, the same key and bytes |
| Prekey bundle: signed prekey, one-time prekey, Kyber-1024 prekey with signatures (`PreKeyBundle`, `processPreKeyBundle`) | invite bundle (`Node.kt` `makeBundle`, `LibSignalCrypto.makeBundle`) | the Swell bundle (5.3): `ID_I`, `EPK`, ML-KEM-768 `EK`, no signatures |
| PQXDH session start (`SessionBuilder`, `PreKeySignalMessage`) | first HELLO | 6.1, 6.2 (HELLO envelope) |
| Double Ratchet with its SPQR layer (`SessionCipher`, `SignalMessage`) | every message | 7, 8 (type 34 DATA) |
| Session, identity, prekey stores (`SignalProtocolStore`, `KvSignalStore`, `SignalStateStore`) | storage | the `swp` record per contact (iOS) / its Kotlin equivalent; sessions never in a backup |
| "A changed identity key on a known channel is never trusted", pre-key message naming another key (`KeyChangeRefusal`) | key change line | A HELLO must open under the identity it names; a link frame opens only under the contact's identity key; a person with another identity key is a new contact (6.2 step 6, G4). The key-change line is left for one case: a HELLO envelope on a known channel that names another identity key is refused with that line and never opened (`KeyChange.swift`). |
| Safety number (`NumericFingerprintGenerator`, 5200 iterations) and its QR (`ScannableFingerprint`) | Contact info | 11 |
| Signature with the identity key (`generateSignature`, `verifySignature`) | group state (`GroupModels.kt`, `GroupModels.swift`) | SwellSig (5.2, 18) |
| Sender keys (`SenderKeyRecord`, group cipher) | Android store tables, never used by iOS groups | none; groups fan out through pairwise sessions (18) |
| Padding to buckets before encryption (`Padding`) | all messages | 7.4 (inside the envelope) |
| `registrationId` | account | none |
| Report seal, backup, push ticket, bell tags, blob transfer, invite sealing | none of these used libsignal | 19, 20, PROTOCOL.md 6c, 6a, 5 and 5.4 |

Calls: signalling messages (inner types 6, 21, 22) are ordinary DATA messages. The media keys come from DTLS-SRTP in WebRTC, which is classical (O16); the security code is derived from the DTLS fingerprints as before (`CallAuth`). Nothing in a call used libsignal.

## Appendix A. Test vectors

The machine-readable vectors are in `docs/protocol-vectors/*.json` (section 13); those files are the normative test. This appendix keeps the draft 2 values of the primitives, which `kdf.json` repeats. Inputs written as `xx*n` mean the byte `xx` repeated `n` times. All values are hex.

```
A.1  Info("root")                                   5377656c6c000204726f6f74
A.2  Info("pq-message", i32 5)                      5377656c6c00020a70712d6d657373616765000400000005
A.3  SHA256Tagged("bundle", 00*4)                   292e76d917b207cc9f3bd135f323609c7b110b321705a8f47012bc47b7fbaca6
A.4  KDF_RK(RK 01*32, dh 02*32)
       RK'  867d297231be8e1dd34dbd9ad0b6a6355b2feb9ab7f24e444c78779626ae69ba
       CK   f1ebe66a8309a8712f86f3b3e11891bb02087bce91b2ae4a0a084d9b76a082cf
       NHK  80e4c12cadf0acdaa48a1765a63f9224a43f8a2ccfca60271c5c13eb3939224e
A.5  KDF_CK(CK 03*32)
       CK'   70fc6d94291a0e4dbc5af3839301772646620faaeb2733d7d9f54b4e8c80c53f
       mk_dr d3d194ab575909331c94c2cf10090ec36b9daf94038bb5077b005a0a3ef2fa0e
A.6  combine(mk_dr 04*32, PQ 05*32, epoch 1)
       mk         c4cd9ed26fbd4c361a29c64fcc01604b1e043fc88939a44b0b610d7654e93cfb
       body_nonce f50bc14935410b17ca9212da
A.7  header(dh_pub 07*32, pn 1, n 2, epoch 3)       07*32 | 00000001 00000002 00000003
     hk 06*32: hk_enc 036f00d2bd4b7cdeafe6e423fa85b7072545c6ead718d123d828a2bc61784197
               hk_iv  4ff5aa6aa18eaddb7fb90b3d4423f29a344c80555ccaac8e6e3e5218c552836d
               hnonce fb5351a08626fcca5d921060
A.8  Handshake. Private keys: id_sk_I 11*32, epk_sk 12*32, id_sk_J 13*32, e_sk 14*32;
     EK 15*1184, ct 16*1088, binding 17*32, expiresAtMs 1800000000000, ss_kem 18*32
     (the public keys ID_I, EPK, ID_J, E are X25519(private, 9); `kdf.json` has a second case with fixed bytes in place of public keys and DH outputs)
       bundleCommit 932c74e147a28b35236af22ee822cbdb726722e70a0c539a6fc3b00ff5c6fcd9
       T            3490cc2321d9e8a39a7d55f84bf7a8e6999f005897d2fc1289baa776666befa0
       RK0          add2d1531c5d153e495c91787d6515ae641fb66ebe5a3e4756ce5ad431d14d9b
       shared_hka   90f60e5471d21011fd3c87e24fb813844066b59bbd88c9eab661fe84b9a15626
       shared_nhkb  14a82ce5c49aa99ed7f2754d83ee99ceb5abf4a364ce0c82ff7c0090af1e0996
       PQ0          5fb047f9baae785bea365c7b296f73480e38c62a7497927f2bfb983bf0a644c6
A.9  PQ_1 from PQ_0 08*32, ss 09*32, t 1, ek 0a*1184, ct 0b*1088
                    58fd84d676c909bec66b6998ace3d9659ccdc03c5d1f1f55d0e0df057929aeff
A.10 upgrade binding, channelId 0c*16, keys 05|0d*32 and 05|0e*32, offerId 0f*16
                    7bf5c11a10049b2be0d07b6acc141c7a41b32635176574b373e1ff51f57f96a0
A.11 safety, ID 0c*32 and ID 0d*32 (32-byte inputs; draft 3 uses the 33-byte identity keys, same function)
       okm    803464028e6feb306761fe119327684c7e93105265959a185d8326964b758a6088f0ac7eea029ac69efc7211cc6ea1d2fb928e35c03890896d7ae822
       digits 83374 87809 49736 81682 00861 99701 74092 18534 66860 61298 45872 90914
```

**A.12 How the JSON vectors work.** Every file is `{"description": ..., ...}` with hex strings (lowercase) and plain JSON numbers for small integers and millisecond times. `handshake-conversation.json` carries an `entropy` object per party: `chunks` is the list of byte strings that party's code draws, in order, from the random source (each draw has the exact size listed), and `kem` is the list of ML-KEM encapsulations that party performs, in order (`ct`, `ss`; CryptoKit has no way to fix the randomness of an encapsulation, so it is recorded; the decapsulating side checks it with its own ML-KEM). An implementation replaces its random source with these lists, builds the identities from the `entropy` fields, and replays `steps`: `hello` and `send` steps must produce exactly the listed `envelope`; `recv` steps refer to a send step by its index among the `hello` and `send` steps (the hello is 0) and must give the listed plaintext or the listed failure. The files are regenerated only on purpose, by the Swift tests with `SWELL_WRITE_VECTORS=1`; a normal run recomputes and compares every byte, and an unchanged file is the proof that nothing drifted.

ML-KEM encapsulation is randomised, so every vector that contains a ciphertext records it. NIST ACVP ML-KEM-768 vectors are still to be added (O10).
