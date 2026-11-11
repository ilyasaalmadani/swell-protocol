# Swell Protocol: clean-room record

Owner's decision (legal): the Swell Protocol is written only from public specifications, academic papers and Swell's own documents. Nobody working on it reads libsignal source, Signal-iOS or Signal-Android source, the SPQR or ML-KEM Braid reference code, or any other AGPL or GPL implementation. This file records, per piece of work, what was used. Add a section for every new piece of work.

## Draft 2 and its Swift implementation (2026-11-11, AI agent "J")

Scope: `docs/SWELL-PROTOCOL-SPEC.md` draft 2, `docs/formal/swell2-*.{pv,spthy}`, `ios/SwellSignal/Sources/SwellSignal/SwellProtocol/*.swift`, the three `SwellProtocol*Tests.swift` files, and the small hooks in `Engine.swift`, `Models.swift`, `Backup.swift`, `ios/Swell/Sources/Services.swift` and `AppModel.swift`.

Public documents the design follows (from the author's knowledge of their published text; no web page or repository was opened during this work):

| Source | Used for |
|---|---|
| Signal, *The Double Ratchet Algorithm*, revision 4 (public domain) | Ratchet with header encryption (spec 7, 8) |
| Signal, *The X3DH Key Agreement Protocol* (public domain) | Handshake pattern (spec 6) |
| Signal, *The PQXDH Key Agreement Protocol* (public domain) | Adding an ML-KEM secret to the handshake (spec 6) |
| Signal's public descriptions of the Sparse Post-Quantum Ratchet and ML-KEM Braid (signal.org) | Only the idea of an ML-KEM epoch ratchet mixed into message keys (spec 7.6). Chunking, erasure coding and Braid's state machine were not used. The licence status of the Braid text was not checked in this session (still open in `DESIGN-SWELL-PROTOCOL.md` rule 2). |
| NIST FIPS 203 (ML-KEM) | KEM boundary, lengths, implicit rejection |
| RFC 7748 (X25519), RFC 5869 (HKDF), FIPS 180-4 (SHA-256), NIST SP 800-38D (AES-GCM) | Primitive boundaries and the standard test vectors in `SwellProtocolVectorTests` |
| Apple CryptoKit public API (the SDK's `CryptoKit.swiftinterface`) | Calls only: `Curve25519.KeyAgreement`, `HKDF<SHA256>`, `SHA256`, `AES.GCM`, `MLKEM768` |

Swell's own material read: `docs/SWELL-PROTOCOL-SPEC.md` draft 1, `docs/DESIGN-SWELL-PROTOCOL.md`, `docs/FORMAL-RESULTS.md`, `docs/PROTOCOL.md`, the draft 1 formal models, and Swell's own source (`Engine.swift`, `LibSignalCrypto.swift`, `Models.swift`, `KeyValueStore.swift`, `Backup.swift`, SwellCore `Wire.swift` and `Codec.swift`, and the existing tests). `LibSignalCrypto.swift` is Swell code that calls the libsignal Swift API; it is not libsignal source.

Not read: libsignal (Rust or Swift wrapper source), Signal-iOS, Signal-Android, Signal-Desktop, the SPQR or Braid reference code, any AGPL or GPL implementation of these protocols, and `ios/vendor/libsignal`.

Honest limit for a lawyer: the author is a language model. It was not shown any of the code above during this work, but its training data may have included public code, and that cannot be ruled out. The design and code differ from Signal's in visible ways (spec section 15, D1 to D13), which a reviewer can check.

## Review fixes for build 26 (2026-11-11, same agent)

Scope: the fixes for `docs/audit/SWELL-PROTOCOL-REVIEW-4-B26.md` (F1 to F5, F8, F9, F10b/c/e, F11, F13 to F15), the SYNC frame, the stage 3 wrapping, the switch in `Config.xcconfig`, `project.yml` and `Services.swift`, and the Contact info line in `ChatView.swift`. Sources: the review itself, Swell's own code and documents, and the CryptoKit API. Nothing from the list of sources not read above was opened. The review's probe package under the scratchpad was not read either.

## Draft 3 and the libsignal removal (2026-11-11, AI agent "A")

Scope: `docs/SWELL-PROTOCOL-SPEC.md` draft 3, `ios/SwellProtocol` (new Apache-2.0 package: `SPIdentity`, `SPSignature` (SwellSig), `SPLink`, the handshake and ratchet files moved from `ios/SwellSignal/Sources/SwellSignal/SwellProtocol/`), the app changes that replace `LibSignalCrypto`, `SignalStateStore` and the signature use in `GroupModels.swift`, and `docs/protocol-vectors/*.json`.

Public documents used: the same list as draft 2 (Double Ratchet rev. 4, X3DH, PQXDH, FIPS 203, RFC 7748, RFC 5869, FIPS 180-4, NIST SP 800-38D, CryptoKit's public API) and, new, **RFC 8032 (Ed25519)** for SwellSig. SwellSig is the Ed25519 verification equation under the Edwards form of the X25519 identity key (RFC 7748 section 4.1 gives the map); it was derived here from those two RFCs and checked against CryptoKit's own Ed25519 verification. Signal's XEdDSA document was **not** read, and the scheme is not interoperable with libsignal signatures. Link frames (static-static DH, HKDF, AES-GCM) were designed from the primitives alone.

Swell's own material read: the draft 2 spec, `docs/CLEAN-ROOM.md`, `docs/PROTOCOL.md`, `docs/FORMAL-RESULTS.md`, `docs/audit/SWELL-PROTOCOL-REVIEW-4-B26.md`, `docs/DESIGN-SWELL-PROTOCOL.md`, and Swell's own Swift code (`Engine.swift`, `GroupEngine.swift`, `LibSignalCrypto.swift`, `SignalStateStore.swift`, `GroupModels.swift`, `Backup.swift`, SwellCore). Those Swell files call the libsignal Swift API; they are not libsignal source. For the Android inventory, only the names of Swell's own Kotlin files and the `org.signal` import lines in them were looked at.

Not read: libsignal (Rust or Swift wrapper source), Signal-iOS, Signal-Android, Signal-Desktop, the SPQR or Braid reference code, XEdDSA or VXEdDSA documents, any AGPL or GPL implementation, and `ios/vendor/libsignal`.

## Kotlin port of draft 2 (2026-11-11, AI agent "B")

Recorded by agent B (copied from `docs/BUILD-27-CHECKLIST.md` section 4): read only `docs/SWELL-PROTOCOL-SPEC.md` draft 2, `docs/CLEAN-ROOM.md`, `docs/PROTOCOL.md`, and Swell's own Swift files under `ios/SwellSignal/Sources/SwellSignal/SwellProtocol/` and Swell's own Android code. BouncyCastle was used through its public class/method signatures (javap) only; its source was not read. No libsignal, Signal-iOS/Android, SPQR/Braid or other AGPL/GPL source was opened.

## Draft 3 completed for iOS (2026-11-11, AI agent "A", second session)

Scope: the rest of draft 3 in `docs/SWELL-PROTOCOL-SPEC.md` (1, 1.2, 5.4, 6.4 "A restored I", 6.5 "Waiting is not failing", 13, 18.1, 20, 21), the engine changes that go with them (`Engine+SwellProtocol.swift`, `Engine.swift`, `GroupEngine.swift`, `GroupStore.swift`, `Status.swift`, `Backup.swift`, SwellCore `Report.swift` and `Invite.swift` test hooks), `EngineVectorTests.swift` and the files `invite.json`, `group-state.json`, `report.json`, `backup.json`, the headless driver `ios/SwellSignal/Tools/SwellPeer` and `tools/live-interop.sh`, the formal model `docs/formal/swell3-link.pv`, the app's About text, update line and safety QR, and `project.yml` (iOS 26, no libsignal).

Sources: Swell's own code and documents only (the files above, the engine's existing tests, `docs/PROTOCOL.md`, the draft 2 formal models `swell2-handshake.pv` and `swell2-upgrade.pv`, the Kotlin peer's usage text in `android/peer/.../Main.kt` for its line protocol), the public documents already listed for draft 3, and ProVerif's documented input language. The Android `swellprotocol` module was not read. Not read: libsignal (any part), Signal-iOS, Signal-Android, Signal-Desktop, the SPQR or Braid reference code, XEdDSA or VXEdDSA documents, any AGPL or GPL implementation. The untracked link `ios/vendor` (to a libsignal checkout) was deleted from this worktree without opening what it pointed to.

## Kotlin port of draft 3, Android build 27 (2026-11-11, AI agent "B")

Recorded by agent B in `docs/ANDROID-STATUS.md` ("Build 27") of the Android worktree, copied here: written from `docs/SWELL-PROTOCOL-SPEC.md` draft 3, `docs/protocol-vectors/`, `docs/CLEAN-ROOM.md`, RFC 8032 and RFC 7748 (as described in the spec), and Swell's own Swift code (`ios/SwellProtocol`, `ios/SwellSignal/.../SwellProtocol/*.swift`, `EngineVectorTests.swift`, `GroupEngine.swift` 18.1, `Invite.swift`, the report call in `Engine.swift`) and Swell's own Android code. Bouncy Castle used through its public API only (method signatures via `javap`); its source was not read. No source of libsignal, Signal-iOS, Signal-Android, SPQR or Braid, XEdDSA documents or any AGPL or GPL implementation was opened.

## Answers to the Android port's questions and strict SwellSig (2026-11-11, AI agent "A")

Scope: spec 1.3 and the sections it changes (5.2 strict verification, 5.3 reusable codes, 6.1 G4 scope, 6.2, 6.5, 19), `SPEdPoint` and the strict checks in `ios/SwellProtocol/Sources/SwellProtocol/SPSignature.swift`, the `strict` cases of `signature.json`, the padded report of `report.json`, the G4 refusal in `Engine.swift`. Sources: the questions file of the Android worktree (read only), RFC 8032 (sections 5.1.3, 5.1.4 and 5.1.7: decoding, the point formulas of the extended coordinates, the two verification equations) and RFC 7748, Swell's own code and documents. Bouncy Castle's source and CryptoKit's implementation were not read; the strict rules make their choice of equation irrelevant instead of relying on it. Nothing from the list of sources not read above was opened.
