# Governance

This file says who runs the Swell Protocol project and how decisions are made.

## Steward

PT JIJI LABS DIGITAL ("Jiji Labs"), Indonesia, is the steward. Jiji Labs owns the GitHub org `swellchat`, pays for the work and is responsible for the project. Public contact: hello@jijilabsdigital.com.

## Maintainers

The maintainers are the Jiji Labs team, acting through the GitHub org `@swellchat`. Roles and contact routes are in `MAINTAINERS.md`. Maintainers review and merge pull requests, triage issues, cut releases and handle security reports.

Every maintainer account must use two-factor authentication.

## How decisions are made

Day-to-day changes (bug fixes, tests, documentation) are decided in the pull request. One maintainer approval is needed to merge.

Some changes need more:

1. **Spec changes.** Any change to `docs/SWELL-PROTOCOL-SPEC.md` that changes bytes on the wire, a key schedule, a security claim or a limit starts as a written proposal in a GitHub issue. The proposal says what changes, why, which sections and vectors are affected, and what it does to the threat model. It stays open for comment for at least 7 days before work is merged.
2. **Both implementations together.** A wire-format change is merged only when the spec text, the shared vectors in `docs/protocol-vectors/`, the Swift code and the Kotlin code are updated in the same pull request, and both test suites pass on the new vectors.
3. **Formal models.** When the handshake (spec section 6) or the ratchet (spec section 7) changes, the matching model in `docs/formal/` is updated and rerun, and `docs/FORMAL-RESULTS.md` records the new results, including "no result" and expected attacks.
4. **Clean-room record.** Each piece of protocol work adds its sources to `docs/CLEAN-ROOM.md`.

Maintainers try to reach consensus. If they cannot, the lead maintainer role (see `MAINTAINERS.md`) decides and writes the reason in the issue.

The project runs no CI on GitHub. Tests run locally on maintainers' machines. A pull request states which test commands were run and their result.

## Releases and versioning

- Versions use semantic versioning, tied to the spec draft: `0.<draft>.<patch>`. `0.3.x` implements spec draft 3.
- A new spec draft that changes the wire format gives a new minor version. A fix that does not change the wire format gives a new patch version.
- Major version 0 means the spec is still a draft. Plan: `1.0.0` only after a final spec and an external review.
- Each release is a git tag `vX.Y.Z` on a commit where both implementations pass every vector file.
- Each release has an entry in `CHANGELOG.md`. Security fixes say so and link the advisory.
- Plan: signed tags and a published SBOM (`docs/SECURITY-ROADMAP.md`, step c).

## Security decisions

- Vulnerability reports follow `SECURITY.md` and `docs/INCIDENT-RESPONSE.md`. They are handled in private by the security contact role until the advisory is published.
- The security contact role sets the severity and the disclosure date, together with the reporter.
- A fix for a protocol flaw is released for Swift and Kotlin at the same time, and coordinated with the Swell app release.
- A change that weakens a security property or adds a known limit must update spec section 3 and `docs/THREAT-MODEL.md` in the same pull request. It must never be described as stronger than the spec and the formal results show.
- Public text says that the protocol has not had an independent audit, until one has been done and its report published.

## Becoming a maintainer

A contributor can become a maintainer when they:

- have had several substantial pull requests merged over at least three months;
- have followed the clean-room rule and recorded their sources in `docs/CLEAN-ROOM.md`;
- are nominated by a maintainer in an issue, and no maintainer objects within 14 days.

New maintainers are added to `MAINTAINERS.md` and to the `@swellchat` org. A maintainer who is inactive for 12 months, or who asks to step down, is moved to an "emeritus" note in `MAINTAINERS.md` and loses write access.

## If the steward stops

The code is Apache-2.0. Anyone may fork it and continue the work at any time.

If Jiji Labs stops maintaining the project, it will either hand the `swellchat` org to the remaining maintainers, or archive the repository. Either step is announced first in `README.md` and in a pinned issue, with at least 90 days notice where possible.

## Code of conduct enforcement

The project follows `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1). Reports go to hello@jijilabsdigital.com. Maintainers who are not involved in the report review it and act according to the Covenant's enforcement guidelines: correction, warning, temporary ban or permanent ban. The reporter's identity is kept private.

## Changing this document

Changes to this file follow the same rule as spec changes: a proposal in an issue, open for at least 7 days.
