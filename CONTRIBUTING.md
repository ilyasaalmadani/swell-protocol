# Contributing

Thank you for helping. Please read this whole file before you open a pull request. By taking part you agree to `CODE_OF_CONDUCT.md`.

**Security problems are never reported in issues or pull requests.** Use the private routes in `SECURITY.md`.

## Build and test

Tests run locally. There is no CI on GitHub. Say in your pull request which commands you ran and what they printed.

Swift (`ios/SwellProtocol`, CryptoKit, needs iOS 26 / macOS 26 SDKs):

```sh
cd ios/SwellProtocol
swift test
```

Kotlin (`android/swellprotocol`, Bouncy Castle 1.79, JVM 17):

```sh
cd android
./gradlew :swellprotocol:test
```

Kotlin fuzz targets (`android/fuzz`): replay every target over its seed corpus and saved regressions, no fuzzing engine needed:

```sh
cd android
./gradlew :fuzz:replay
```

Formal models (needs ProVerif and Tamarin, see `docs/FORMAL-RESULTS.md`):

```sh
cd docs/formal
./run.sh lk3_
```

Both test suites replay the shared vectors in `docs/protocol-vectors/`. The vector files are regenerated only on purpose, by the Swift tests with `SWELL_WRITE_VECTORS=1` (spec Appendix A.12). A normal run recomputes and compares every byte. A pull request that changes a vector file must explain why.

## The wire-format rule

A change that changes bytes on the wire, a key schedule or a label needs, **in the same pull request**:

1. the spec text in `docs/SWELL-PROTOCOL-SPEC.md` (mark what changed);
2. the vector files in `docs/protocol-vectors/`;
3. the Swift implementation and its tests;
4. the Kotlin implementation and its tests;
5. the formal model in `docs/formal/` and `docs/FORMAL-RESULTS.md`, when the handshake or the ratchet changes.

Larger spec changes start as a written proposal in an issue first (see `GOVERNANCE.md`).

## The clean-room rule

The Swell Protocol is written only from public specifications, academic papers and Swell's own documents.

- Do not read or copy code from other messaging protocols' implementations. That includes libsignal, Signal-iOS, Signal-Android, Signal-Desktop, the SPQR or ML-KEM Braid reference code, and any AGPL or GPL implementation.
- Use Bouncy Castle and CryptoKit through their public APIs only.
- Add a section to `docs/CLEAN-ROOM.md` for your work: scope, sources used, sources not read.

See `docs/CLEAN-ROOM.md` and spec section 2.

## Use of AI tools

Much of this project was written with generative AI assistants (see `README.md`). We expect the same honesty from contributors. In the pull request description, say whether AI tools helped write the code, tests or text, and what you checked yourself. Do not name the tool in code comments. You remain responsible for the change.

## Sign-off

Every commit needs a `Signed-off-by` line, in the style of the Developer Certificate of Origin (https://developercertificate.org/). It says you have the right to submit the work under the project licence.

```sh
git commit -s
```

## Licence

Contributions are accepted under Apache-2.0, the licence of this repository (`LICENSE`).

## Writing style

Docs use plain, short English. State facts and limits. Make no claim that the spec, the tests and the formal results do not support, and no marketing words. Label plans as plans.

## Pull request checklist

The pull request template (`.github/PULL_REQUEST_TEMPLATE.md`) lists the checks: spec, vectors, Swift, Kotlin, formal model, AI disclosure, sign-off.
