<p align="center">
  <img src="docs/brand/swell-protocol-icon.png" width="96" height="96" alt="SwellProtocol">
</p>

# SwellProtocol

The end-to-end encryption library of Swell Messenger, by PT JIJI LABS DIGITAL ("Jiji Labs"), Indonesia.
Licence: Apache-2.0 (see `LICENSE`). The library has no app code and depends on no closed service.

Two implementations in this repository pass the same test vectors:
- Swift: `ios/SwellProtocol` (CryptoKit, iOS 26 and macOS 26 and later). Run `swift test` in that folder.
- Kotlin: `android/swellprotocol` (Bouncy Castle 1.79, JVM 17). Run `./gradlew :swellprotocol:test` in `android/`.

What it does: X25519 and ML-KEM-768 handshake, HKDF-SHA-256, AES-256-GCM, a Double Ratchet with header encryption, and a post-quantum epoch ratchet. No new cryptographic primitives.

- Specification: `docs/SWELL-PROTOCOL-SPEC.md`
- Shared test vectors: `docs/protocol-vectors/`
- Formal models (ProVerif) and results: `docs/formal/`, `docs/FORMAL-RESULTS.md`
- Clean-room record: `docs/CLEAN-ROOM.md`
- Kotlin fuzz targets (Jazzer, prepared for OSS-Fuzz): `android/fuzz/`

## Who uses it

Swell Messenger 1.3.0 uses this library on both platforms. It is on the Apple App Store (since 2026-11-20) and on Google Play. Website: https://getswell.org . Paper: https://getswell.org/paper .

## Project status

- Specification: draft 3 (`docs/SWELL-PROTOCOL-SPEC.md`). It may still change.
- No independent security audit yet. See "Security status" below.
- Versioning: library versions follow the spec draft. `0.3.x` implements draft 3. A change to the wire format means a new draft and a new minor version. Details in `GOVERNANCE.md`, history in `CHANGELOG.md`.

## Security status

The Swell Protocol has not had an independent security audit yet. One is planned. Do not describe it as audited.
Report security problems as described in `SECURITY.md`. Some documents name files of the Swell app (engine, audits); the app source is not in this repository.

## Use of generative AI

Most of the code, tests and documentation in this library were written with generative AI coding assistants, directed, checked and tested by the Jiji Labs team. Security reviews also used AI tools. The formal models were checked with ProVerif, which is not generative AI. The shared test vectors, the cross-language tests between Swift and Kotlin and the ProVerif results are how the work is checked, not trust in any tool.

## Governance

The project is stewarded by Jiji Labs and maintained by the Jiji Labs team (GitHub org `@swellchat`). How decisions, releases and security fixes are made: `GOVERNANCE.md`. Roles and contacts: `MAINTAINERS.md`.

## Contributing

Read `CONTRIBUTING.md` first. In short: a wire-format change needs the spec, the vectors and both implementations in one pull request; follow the clean-room rule; say in the pull request if AI tools helped; sign off your commits (`git commit -s`). Code of conduct: `CODE_OF_CONDUCT.md`.

## Security roadmap

What is done and what comes next (external design review, OSS-Fuzz, signed releases, audit when funded): `docs/SECURITY-ROADMAP.md`. Incident response plan: `docs/INCIDENT-RESPONSE.md`.

## Threat model

Assets, attackers, the goals the spec claims, what the formal models prove and what they do not: `docs/THREAT-MODEL.md`.
