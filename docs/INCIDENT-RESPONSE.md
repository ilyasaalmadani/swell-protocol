# Incident response plan

A short plan for a security problem in the Swell Protocol. It covers the spec, the Swift and Kotlin libraries and the vectors. The Swell app and server follow their own process (https://getswell.org/security), but a protocol fix is always coordinated with the app.

Roles are those in `MAINTAINERS.md`. The security contact role leads every incident.

## 1. Intake

- Reports arrive through GitHub private vulnerability reporting or by email to hello@jijilabsdigital.com (`SECURITY.md`).
- A report found in a public issue is hidden or moved to a private advisory at once, and the reporter is told why.
- The security contact replies to the reporter within 7 days and opens a draft GitHub Security Advisory.

## 2. Triage and severity

The security contact confirms the problem, names the affected component (spec, Swift, Kotlin, vectors) and versions, and sets a severity:

| Severity | Examples |
|---|---|
| Critical | Message content or keys readable by the mailbox operator or a network attacker; impersonation without the identity secret |
| High | A break of a security goal in `docs/THREAT-MODEL.md` that needs extra conditions; a remote crash of the library from a frame anyone can send |
| Medium | A weaker property than the spec states; a denial of service that needs a privileged position |
| Low | Hardening, or a limit the spec already admits that is a little worse than stated |

A CVSS score is added in the advisory where it fits. If the report is not a vulnerability, the reporter is told why.

## 3. Private fix

- Work happens in the private fork of the GitHub Security Advisory, not in public branches.
- A protocol flaw is fixed in the spec, the vectors, Swift and Kotlin together (the wire-format rule in `CONTRIBUTING.md`), with a test that fails before the fix.
- If the handshake or ratchet changes, the formal model is updated and rerun where possible before release.
- The reporter is invited to check the fix.

## 4. Advisory draft

The advisory states: affected versions, fixed versions, severity, what an attacker gains, whether the Swell app is affected, workarounds, and credit. A CVE is requested through GitHub when the problem qualifies.

## 5. Coordinated release

- Swift and Kotlin fixes are tagged at the same time.
- The Swell app releases for iOS and Android are prepared with the fix, so that the advisory and the app updates go out as close together as store review allows.
- If a fix changes the wire format, the release notes say how old and new versions interact.
- Target: fix and advisory within 90 days of the report, sooner for critical problems or if the problem is being used in the wild.

## 6. Notification

- Publish the GitHub Security Advisory and the `CHANGELOG.md` entry.
- Update https://getswell.org/security and credit the reporter in the Hall of Fame (unless they ask not to be named).
- Tell known downstream users of the library directly before or at publication.

## 7. Post-mortem

Within 30 days of publication (target), publish a short post-mortem in `docs/`: what happened, how it was found, why tests, vectors, fuzzing or models did not catch it, and what changes. Update the spec, `docs/THREAT-MODEL.md` and `docs/SECURITY-ROADMAP.md` as needed. Add the failing input to the fuzz regressions or the vectors.
