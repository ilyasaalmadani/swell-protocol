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

## Security status

The Swell Protocol has not had an independent security audit yet. One is planned. Do not describe it as audited.
Report security problems as described in `SECURITY.md`. Some documents name files of the Swell app (engine, audits); the app source is not in this repository.

## Use of generative AI

Most of the code, tests and documentation in this library were written with generative AI coding assistants, directed, checked and tested by the Jiji Labs team. Security reviews also used AI tools. The formal models were checked with ProVerif, which is not generative AI. The shared test vectors, the cross-language tests between Swift and Kotlin and the ProVerif results are how the work is checked, not trust in any tool.
