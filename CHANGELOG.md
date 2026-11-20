# Changelog

All notable changes to the Swell Protocol library and its specification. Versions follow `GOVERNANCE.md`: `0.<spec draft>.<patch>`. Dates are given only where they are recorded.

## Unreleased

Nothing yet.

## 0.3.0 (spec draft 3)

Date: 2026-11-20 (first tagged release).

### Added (since the draft 3 spec)

- Kotlin fuzz targets in `android/fuzz/` (Jazzer, prepared for OSS-Fuzz): `WireFuzzer`, `CodecFuzzer`, `HandshakeFuzzer`, `RatchetFuzzer`, `SessionRecordFuzzer`, `SignatureFuzzer`, `InviteFuzzer`, `LinkFuzzer`. Gradle tasks `:fuzz:fuzzJars`, `:fuzz:seedCorpus` (seeds from `docs/protocol-vectors/`) and `:fuzz:replay`.
- Project documents: `GOVERNANCE.md`, `MAINTAINERS.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, an expanded `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/SECURITY-ROADMAP.md`, `docs/INCIDENT-RESPONSE.md`, issue and pull request templates, `CODEOWNERS` and a Dependabot configuration.

### Security (since the draft 3 spec)

- The session record decoder refuses a record that holds only half of a chain.

### Changed

- Specification draft 3 (`docs/SWELL-PROTOCOL-SPEC.md`). libsignal is no longer used anywhere in Swell's end-to-end encryption. One identity key per person (D14). Bare MSG ciphertext type 34 and link frames, type 35 (6.4). Invite versions 5 and 6 (5.4). Capability bit 8 (6.5). Safety numbers over the 33-byte identity keys, with a defined QR text (11). Domain version stays 2, so draft 2 sessions keep working.

### Added

- SwellSig (5.2): Ed25519 verification under the Edwards form of the X25519 identity key, with strict checks so that different RFC 8032 verifiers give the same answer.
- Swift package `ios/SwellProtocol` (CryptoKit, iOS 26 and macOS 26) and Kotlin library `android/swellprotocol` (Bouncy Castle 1.79, JVM 17).
- Parity vectors: ten files in `docs/protocol-vectors/` that the Swift and Kotlin code both reproduce byte for byte.
- Formal model `docs/formal/swell3-link.pv` and its results in `docs/FORMAL-RESULTS.md`.

### Security

- Review B27 H1: the version 5 HELLO frame carries `SHA256Tagged("hello", sealKey)` instead of `sealKey`, so the mailbox operator can no longer open the bundle and redeem the invite itself (5.5).
- Review B27 M1: frames sealed by an older build or under another session are sealed again in a Swell session; backups carry no sealed frame (6.4, 20). App engine.
- Review B27 L1: a replayed older OFFER cannot replace a pending handshake (6.4).
- Review B27 L2: a gap above `MAX_SKIP` repairs itself after three refusals (8.1, 8.4, 6.4).
- Review B27 L3: the unauthenticated "older app" mark is cleared (6.5). App engine.
- Review B27 L4, L5: a used invite keeps only its onion client-auth key for the grace period; the store commits with `synchronous = FULL` (12, 8.2). App engine.

## Earlier drafts

Spec draft 2 (post-quantum epoch ratchet), draft 1 and draft 0.1 are in the git history and in spec section 1.1. They were not released as library versions from this repository.
