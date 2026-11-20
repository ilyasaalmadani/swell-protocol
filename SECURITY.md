# Security policy

The Swell Protocol has had internal reviews and formal models, and has not been independently audited yet. An independent audit is planned. What the formal models show and what they do not: `docs/THREAT-MODEL.md` and `docs/FORMAL-RESULTS.md`.

## Report a vulnerability

Report a vulnerability privately at https://github.com/swellchat/swell-protocol/security/advisories/new, or by email to hello@jijilabsdigital.com with the subject `Swell Protocol security`. Please do not open a public issue. Scope, safe harbor and Hall of Fame: https://getswell.org/security

## Supported versions

| Version | Supported |
|---|---|
| Latest spec draft (draft 3, `docs/SWELL-PROTOCOL-SPEC.md`) | Yes |
| Latest library release (`0.3.x`, spec draft 3) | Yes |
| Earlier spec drafts (0.1, 1, 2) and earlier releases | No |

## What to include

- The component: spec, Swift (`ios/SwellProtocol`), Kotlin (`android/swellprotocol`), vectors, fuzz targets or formal models.
- The version, tag or commit.
- What is wrong and what an attacker gains. Name the spec section if you can.
- Steps to reproduce: a test, an input file or a vector is best.
- A suggested fix, if you have one.
- How you want to be credited, or that you do not want credit.

## What happens next

- We aim to reply within 7 days.
- We confirm the problem, set a severity and agree a disclosure date with you.
- We work on the fix in private, in a GitHub Security Advisory with a private fork. If the flaw is in the protocol, the fix covers both implementations, the spec and the vectors, and is released together with the Swell app.
- We aim to publish a fix and an advisory within 90 days. If a fix needs longer, we tell you why and agree a new date.
- The plan we follow is `docs/INCIDENT-RESPONSE.md`.

## Coordinated disclosure

Please keep the details private until the advisory is published or 90 days have passed, whichever comes first, unless we agree another date with you. We will not take legal action against good-faith research that follows this policy and the safe harbor at https://getswell.org/security.

## Advisories and CVE

Advisories are published through GitHub Security Advisories in this repository. We request CVE identifiers through GitHub when a problem qualifies. Each security fix is noted in `CHANGELOG.md` with a link to its advisory.

## Credit

Reporters are credited unless they ask not to be: in the advisory, in `CHANGELOG.md` and in the Hall of Fame at https://getswell.org/security. There is no cash bounty.

## Out of scope here

- The Swell app (iOS and Android) and the Swell server and mailbox. They are not in this repository. Report problems with them via https://getswell.org/security.
- Bugs in CryptoKit or Bouncy Castle themselves. Report them to those projects. Tell us too if they affect this library.
- Limits the spec already states (spec section 3, `docs/THREAT-MODEL.md` "Non-goals and known limits"), unless you show the effect is worse than stated.
