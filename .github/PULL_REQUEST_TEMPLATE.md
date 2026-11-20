<!--
Security fixes are not made in public pull requests. See SECURITY.md.
Read CONTRIBUTING.md before you open this pull request.
-->

## What and why

<!-- What does this change, and why? Link the issue or proposal. -->

## Tests run locally

<!-- There is no CI. Paste the commands you ran and the result. -->

- [ ] `swift test` in `ios/SwellProtocol`
- [ ] `./gradlew :swellprotocol:test` in `android/`
- [ ] `./gradlew :fuzz:replay` in `android/` (if parsers or the fuzz targets changed)

## Checklist

- [ ] **Spec**: `docs/SWELL-PROTOCOL-SPEC.md` updated, or not needed (no change to bytes, key schedule, labels, claims or limits)
- [ ] **Vectors**: `docs/protocol-vectors/` updated and the reason explained, or not needed
- [ ] **Swift**: `ios/SwellProtocol` updated and tests pass
- [ ] **Kotlin**: `android/swellprotocol` updated and tests pass
- [ ] **Formal model**: `docs/formal/` and `docs/FORMAL-RESULTS.md` updated if the handshake or ratchet changed, or not needed
- [ ] **Threat model**: `docs/THREAT-MODEL.md` updated if a security claim or limit changed, or not needed
- [ ] **Clean room**: no code from other messaging protocols' implementations was read or copied; `docs/CLEAN-ROOM.md` updated for protocol work
- [ ] **AI disclosure**: I state below whether AI tools helped and what I checked myself
- [ ] **Sign-off**: every commit has a `Signed-off-by` line (`git commit -s`)

## AI disclosure

<!-- Did AI tools help write code, tests or text in this pull request? What did you check yourself? -->
