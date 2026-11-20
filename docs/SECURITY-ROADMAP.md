# Security roadmap

What has been done to check the Swell Protocol, and what comes next. The protocol has not had an independent security audit yet. Nothing here is a promised date; where a time is given it is a target.

## Done

| Item | Where |
|---|---|
| Written specification, draft 3, with a deviations table for auditors (section 15) and open items (section 16) | `docs/SWELL-PROTOCOL-SPEC.md` |
| Formal models in ProVerif and Tamarin for drafts 1, 2 and 3, with every result recorded, including "no result" and expected attacks | `docs/formal/`, `docs/FORMAL-RESULTS.md` |
| Shared test vectors: ten JSON files, reproduced byte for byte | `docs/protocol-vectors/` |
| Two implementations (Swift with CryptoKit, Kotlin with Bouncy Castle) tested against the same vectors | `ios/SwellProtocol`, `android/swellprotocol` |
| Kotlin fuzz targets for Jazzer, prepared for OSS-Fuzz: eight targets (wire, codec, handshake, ratchet, session record, signature, invite, link), seed corpora from the vectors, and a replay task | `android/fuzz/` |
| Internal reviews, and fixes for the build 27 security review findings H1, M1, L1 to L5 | spec section 1 |
| Clean-room record of every source used | `docs/CLEAN-ROOM.md` |
| Private vulnerability reporting (GitHub Security Advisories and email) | `SECURITY.md` |
| Public security page with scope, safe harbor and Hall of Fame | https://getswell.org/security |
| Governance, threat model, incident response plan | `GOVERNANCE.md`, `docs/THREAT-MODEL.md`, `docs/INCIDENT-RESPONSE.md` |

## Next steps

In order of priority. Support from a security fund and program would let us do steps a to f sooner and with outside experts, and would bring step g closer.

### a. External protocol design review

- **Why.** All analysis so far is internal, and the formal models were written by the same team as the spec. The deviations from published designs (spec 15: D3 combiner, D6 header nonce, D10 PQ ratchet, D15 SwellSig, D16 link frames) need a qualified cryptographer who did not write them.
- **Deliverable.** A written review of the spec and the formal models, published in `docs/`, with each finding answered in the spec and the threat model.
- **Rough size.** About 3 to 6 weeks of reviewer time, plus team time to answer findings.

### b. OSS-Fuzz onboarding for Kotlin, and a Swift fuzz harness

- **Why.** The spec lists fuzzing of every parser beyond the unit-level pass as still to do (spec 13, O10). The Kotlin targets exist but run only when someone runs them. Swift has unit-level parser fuzz tests, not a coverage-guided harness.
- **Deliverable.** The project accepted into OSS-Fuzz with the eight Kotlin targets. A libFuzzer-based harness for the Swift parsers, with a replay mode like the Kotlin one. Findings fixed and added to the regression corpus.
- **Rough size.** 1 to 2 weeks for OSS-Fuzz onboarding; 2 to 3 weeks for the Swift harness.

### c. Signed release tags and a published SBOM

- **Why.** Users of the library, starting with the Swell app, should be able to check that a release came from the maintainers and see exactly what it depends on.
- **Deliverable.** Signed `vX.Y.Z` tags, a documented verification step, and an SBOM (for example CycloneDX or SPDX) for each release, attached to the GitHub release.
- **Rough size.** A few days.

### d. OpenSSF Scorecard and OpenSSF Best Practices badge self-assessment

- **Why.** A public, standard way to show where the project stands and what is missing.
- **Deliverable.** A Scorecard report run locally with the Scorecard CLI, and the Best Practices questionnaire filled in. Both published with notes. Some Scorecard checks expect CI; we will explain those scores instead of adding CI.
- **Rough size.** About one week.

### e. Dependency pinning and update policy (Bouncy Castle)

- **Why.** The Kotlin library depends on Bouncy Castle (`bcprov-jdk18on` 1.79) for X25519 and ML-KEM-768. A change there changes our cryptography. The Swift library depends only on CryptoKit.
- **Deliverable.** Gradle dependency verification (checksums) and locked versions; a written policy for how fast Bouncy Castle security releases are taken, and that each update reruns every vector file and the fuzz replay. Dependabot (`.github/dependabot.yml`) opens weekly update pull requests.
- **Rough size.** A few days, then ongoing.

### f. Incident response plan

- **Why.** A flaw in the protocol needs a coordinated fix in two implementations and in the Swell app.
- **Deliverable.** The first version is `docs/INCIDENT-RESPONSE.md`. Next: a dry run on a made-up flaw, and a filled-in contact list for downstream users.
- **Rough size.** A few days.

### g. Full independent audit, when funded

- **Why.** The spec, the README and the app say an independent audit is planned. Until it is done and its report published, public text keeps saying that there has been no independent audit.
- **Deliverable.** An audit of the spec and both implementations by an independent firm, with the report published in full and every finding answered.
- **Rough size.** Large. Cost and length depend on the auditor; not specified yet.

## Other open work from the spec

These are tracked in the spec and are part of the same effort:

- NIST ACVP ML-KEM-768 vectors (O10).
- Crash tests at every transaction boundary (spec 13).
- A constant-time SwellSig implementation and its review (O17).
- Planned fixes for O12 (PQ stall by dropping frames), O13 (old-epoch forgery after healing) and O15 (quadratic header-key trial).
- A model of SwellSig and of more of the engine rules; a model with many parallel invite-path sessions; a computational proof of the D3 combiner (FORMAL-RESULTS.md, "What would make this stronger").
