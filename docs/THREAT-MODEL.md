# Threat model

This file restates, in one place, what `docs/SWELL-PROTOCOL-SPEC.md` (draft 3) and `docs/FORMAL-RESULTS.md` say about threats. The spec is normative; if this file and the spec differ, the spec wins and this file is a bug. Section numbers ("spec 6.4") refer to the spec. Formal result numbers ("3-1", "2-P2", "13") refer to `docs/FORMAL-RESULTS.md`. Where the spec says nothing, this file says "not specified".

The Swell Protocol has not had an independent security audit yet. The formal results are internal work, run by AI agents on a maintainer's machine (FORMAL-RESULTS.md, opening paragraph).

## Scope

In this repository: the library. Encoding and primitive boundaries (spec 4), identity keys and SwellSig (5.1, 5.2), the bundle (5.3), the handshake (6.1 to 6.3), link frames (6.4), the ratchet and the post-quantum epoch ratchet (7), receive and send (8), safety numbers (11), and the shared vectors (13).

Not in this repository: the Swell app and its engine, the mailbox and the transport. The spec header says the app-level formats of sections 5.4, 18, 19 and 20 live in the app's engine. Engine rules such as the timing windows of 6.4, the capability rule of 6.5 and the outbox are app behaviour. They appear here only where a library claim depends on them.

## Assets

| Asset | Where in the spec | Why it matters |
|---|---|---|
| Message content (inner messages) | 7.4 | The main thing to keep secret |
| Identity secret, derived from the 16-byte account entropy (the 12 words) | 5.1, 12 | Whoever holds it can start sessions as the person (D14) and read or forge link frames (D16). The protocol never deletes it. |
| Session state: root key, chain keys, current `DHs` private key, header keys | 7.1, 7.2, 12 | Theft exposes current and some recent messages (spec 3, A1) |
| Stored skipped message keys and their header keys (up to 2000, up to 15 days) | 8.1, 12 | Theft exposes the messages they belong to (spec 3, G6) |
| PQ epoch keys `PQ_e` (up to four) and a pending ML-KEM seed | 7.6, 12 | Needed for post-quantum healing |
| Handshake secrets: `epk_sk`, ML-KEM seed, `e_sk`, `ss_kem`, `hs` | 6.1, 6.2, 12 | Forward secrecy of the handshake |
| Invite secrets: `sealKey`, `queueId`, version 6 `secret` and `authKey` | 5.4, 5.5 | A leaked invite lets someone else become the contact (spec 3, 6.3) |
| Link key `LK` | 6.4 | Seals OFFER, HELLO, RESET, SYNC between contacts |
| The binding between a person and an identity key, checked by the safety number | 6.3, 11 | First contact is trust on first use |
| Signed group states | 5.2, 18 | Group membership and sequencer authority |
| Metadata: who talks to whom, timing, sizes | 3, 5.6 | Mostly not protected (see limits) |

## Attackers

The spec lists: a network observer; the mailbox operator, who logs everything and may drop, delay, reorder or replay; a later quantum attacker with recordings; a thief who copies one phone once; a hostile contact (spec 3).

1. **Network attacker.** Reads, records, drops and injects on the network. The draft 3 model uses an active network attacker (3-1).
2. **Malicious server or relay (the mailbox operator).** Sees every envelope. Sees the MSG frame's `channelId` and ciphertext type in clear (spec 3, 5.6). Sees the joiner's identity key, `E` and `ct` in clear in an invite-path HELLO (D7, O2). Can drop link frames and keep a pair without a session (spec 3, last paragraph). Can stall the PQ ratchet by dropping the larger frames that carry `EK` or `CT` (O12). Before the build 27 review fix H1, the operator could open a version 5 bundle and redeem the invite itself; the version 5 HELLO frame now carries `SHA256Tagged("hello", sealKey)` instead of `sealKey` (spec 1, 5.5).
3. **Device compromised later.** A thief copies one phone once, after messages were sent. This is the forward-secrecy question (spec 3).
4. **Device compromised earlier.** A thief copied the phone before later messages. This is the recovery question: classical (property 13) and post-quantum (2-P2). An active attacker after a theft can stay in the middle (A2, 2-P6). A theft of the identity secret lets the thief start sessions as that person (D14) and read past link frames (D16).
5. **Quantum-capable future attacker, harvesting now.** Records traffic today and breaks X25519 later. The spec claims secrecy if ML-KEM-768 holds (spec 3; properties 5, 17, 2-5, 3-5). An active quantum attacker breaks link sessions (3-6, D16).
6. **Hostile contact.** Keeps what it receives. Not protected (spec 3).
7. **Holder of a leaked invite.** Whoever redeems first becomes the contact (spec 3, 6.3, A4).

## Security goals the spec claims

| Goal | Spec | Formal support |
|---|---|---|
| **Secrecy** of content from the operator and the network, if X25519 or ML-KEM-768 holds for the handshake | 3, 6 | 1, 4, 5, 17 (draft 1); 2-1 to 2-5 (draft 2); 3-1, 3-5 (draft 3) |
| **Forward secrecy**, with two limits: (a) the sender's current ratchet key lives until its next DH step, so a second theft inside the healing window of an unhealed first theft can expose a sent message (A1); (b) stored skipped keys are exposed by a theft (G6) | 3, 8.1, 12 | 11, 13, 14 (draft 1); 2-7 (draft 2); 3-4 (draft 3, both identity secrets stolen afterwards) |
| **Recovery after theft, classical**: against an attacker passive while healing, secret again one DH round trip after a one-time theft | 3 | 13 |
| **Recovery after theft, post-quantum**: against an attacker passive while healing who also breaks every X25519 key, secret again from the first epoch whose ML-KEM key is made after the theft, at the second epoch change at the latest | 3, 7.6 | 2-P2, 2-P5; tightness 2-P4 |
| **Mutual authentication** of both identity keys, with key confirmation when I's first reply opens | 6.3 | 2, 3, 8 (draft 1, one session); 2-2, 2-3 (draft 2, one session, random keys); 3-2 (draft 3 link handshakes, unbounded, persistent keys). Invite path with persistent keys: 3-7, **no result** |
| **Safety numbers** rule out a replaced invite when both sides compare them | 6.3, 11 | 10 (draft 1); 2-8, 2-9 (draft 2) |
| **Link frame authenticity**: a RESET or other link frame that opens was made by the contact, for that direction, not reflected | 6.4 | 3-3; control 3-8 shows why the AD names sender and receiver |
| **Mailbox privacy**: no key, id or counter repeats in clear; queues cannot be linked by envelope bytes | 3 | Not modelled. Header encryption is dropped in `swell1-ratchet.spthy` |
| **Consistent SwellSig verification** across verifiers (strict checks) | 5.2 | Not modelled. Vectors only (`signature.json`, `strict`) |
| **No rollback**: session state is never in a backup and never restored | 8.2, 20 | Not modelled. Engine rule |

Linking is **not** a goal in draft 3. Identity keys are one per person: contacts can compare them, and the operator sees an identity key in clear in an invite-path HELLO (spec 3, D7, D14).

## What the formal models prove, and what they do not

"Proved" means the tool found no attack *in the model*. The models use perfect cryptography and are much simpler than the code (FORMAL-RESULTS.md, "How to read a result" and "Limits").

### Proved in the model

| Model file | Results |
|---|---|
| `docs/formal/swell3-link.pv` (draft 3, ProVerif) | 3-1 secrecy of unbounded link sessions plus one invite; 3-2 injective authentication both ways for link handshakes; 3-3 RESET authenticity without reflection; 3-4 forward secrecy after theft of both identity secrets; 3-5 secrecy against a recording quantum attacker |
| `docs/formal/swell2-handshake.pv` (draft 2, ProVerif) | 2-1 to 2-5 secrecy and hybrid properties; 2-7 handshake forward secrecy; 2-8, 2-9 safety-number match |
| `docs/formal/swell2-pq-ratchet.spthy` (draft 2, Tamarin) | 2-P1 executable; 2-P2 post-quantum recovery, passive attacker; 2-P3 epoch secrecy without theft; 2-P4 tightness; 2-P5 the A3 case |
| `docs/formal/swell1-handshake.pv` (draft 1, ProVerif) | 1 to 5, 8, 10, 11 |
| `docs/formal/swell1-ratchet.spthy` (draft 1, Tamarin) | 12 executable; 13 forward secrecy and classical recovery, passive; 14 plain forward secrecy; 17 post-quantum secrecy without theft |

FORMAL-RESULTS.md says the draft 2 results still hold for what draft 3 did not change: the handshake key schedule, the ratchet and the PQ epoch ratchet. `docs/formal/swell2-upgrade.pv` (2-U1 to 2-U4) models the draft 2 upgrade inside libsignal; draft 3 replaced that path with link frames (D12 replaced by D16).

### Attacks found, as expected

- 3-6: an active quantum attacker with the identity secrets forges an OFFER and reads that link session (D16). Invite-path secrets stay secret.
- 3-8: control; without sender and receiver in the AD, a RESET can be reflected.
- 2-6, 6: controls; with both X25519 and ML-KEM broken, secrets fall.
- 2-P6, 16 (A2, A6): an active attacker after a theft can stay in the middle.
- 6a, 7 (A4): whoever knows the invite can be J.
- 15: control for 13 (tightness).
- 18 (A3): draft 1 had no post-quantum recovery; draft 2 fixed it (2-P2).

### No result (nothing is claimed)

- 3-7 `lk3_invauth`: invite-path authentication with persistent identity keys and unbounded link sessions in parallel. Open.
- 2-U4, 7a, 9 (A5, argued, not machine-found).

### Not covered by any model

- SwellSig (5.2) and signed group states (18) (FORMAL-RESULTS.md, "Draft 3 limits").
- Engine rules: the 15-day and 5-minute windows, "only I offers", "an ACTIVE session is never replaced by an offer", the SYNC answer to an offer, the bit 8 rule, the once-a-day limits, outbox re-sealing, and what RESET deletes.
- Skipped keys, several messages per chain, out-of-order delivery, `MAX_SKIP`, the 15-day expiry.
- Header encryption and metadata hiding; the derived header nonce (D6); padding, lengths and byte encodings; nonce reuse; key commitment.
- The combiner of D3, which needs a computational proof (for example CryptoVerif).
- Many parallel sessions of the invite-path handshake (the draft 1 and draft 2 handshake models are one session; the I side uses a cut model).
- In the PQ ratchet model: pacing, the four-epoch key window, the repeat rule, out-of-order delivery and header keys. Epochs are unrolled to four.
- The Swift and Kotlin code. Key deletion, memory wiping, crash and rollback rules and constant time are outside the models; the models assume deleted keys are gone.
- FORMAL-RESULTS.md does not say whether the version 5 HELLO frame change of review B27 H1 is in `swell3-link.pv`. Treat it as not modelled.
- The draft 2 models were not remodelled after the review fixes of 2026-11-11 (FORMAL-RESULTS.md, "Draft 2 limits").

## Non-goals and known limits

From spec 3 ("Not protected"), the deviations table (15), the deletion table (12) and the open items (16):

- **Metadata.** Mailbox timing, sizes and volume. A PQ field moves a message to a larger bucket, so epoch changes are visible as size (spec 3, D10, O12). `channelId` and ciphertext type are in clear (5.6).
- **Linking by identity key.** Contacts can tell they know the same person; the operator sees an identity key in an invite-path HELLO (D7, D14, O2).
- **A compromised phone**, and a contact who keeps what they received.
- **A leaked invite.** Whoever uses it first becomes the contact. The safety number is the check (spec 3, 6.3).
- **Trust on first use.** The first identity key comes from the invite (6.3).
- **An active attacker after a theft** can inject its own ratchet or KEM keys and stay in the middle until safety numbers are compared again or a new invite is made (A2, 2-P6).
- **Theft of the identity secret (the 12 words).** The thief can start sessions as that person (D14), and read past link frames and forge new ones until the person makes a new identity (D16). Message content keeps forward secrecy from the ratchet.
- **Header metadata after a theft plus a quantum break**, because header keys are not mixed with epoch keys (D11).
- **Classical identity authentication and link frames** (X25519, Ed25519 verification). A quantum attacker who records an invite or a link exchange can later impersonate the identity but cannot read earlier messages (spec 3, 3-6).
- **Forgery under an old epoch after healing.** A receiver still accepts up to three older epoch keys (O13, planned fix).
- **Availability.** Not a goal the spec claims. Dropped messages, dropped link frames and a stalled PQ ratchet are not prevented (spec 3, O12). A swapped bundle gives denial of service, not a key (6.3, D1).
- **Deletion is not physical erasure.** Old values may remain in database pages, the write-ahead log or flash. Swift cannot promise memory is erased (spec 12). Memory wiping in the Kotlin code: not specified.
- **Calls.** Not post-quantum; media keys come from DTLS-SRTP (O16). Call encryption is not specified in draft 3 and is not in this library.
- **Push tokens and Tor guard exposure** (spec 3). App and transport matters, not in this library.
- **Implementation bugs** (spec 3).
- **Side channels.** Secret comparisons are constant time (spec 4). The SwellSig integer code is not constant time (5.2, D15, O17). Whether CryptoKit and Bouncy Castle operations are constant time: not specified.

## Open questions for an auditor

The spec asks an auditor to read the deviations table (spec 15) first. Questions we would most like answered:

1. **D3.** Is binding all public values through the HKDF salt (`T`) a sound combiner of X25519 and ML-KEM-768? There is no computational proof.
2. **D6.** Is the header nonce derived from the header under a separate key acceptable at the 2^16-per-key limit?
3. **D15, O17.** SwellSig uses the same scalar for X25519 and Ed25519-style signing, separated by domain strings, with hand-written, non-constant-time arithmetic. Is that acceptable, and are the strict checks of 5.2 complete?
4. **D16, D18.** Link frames have no forward secrecy and rely on the identity keys alone. Are the acceptance rules of 6.4 (15-day and 1-hour window, 5-minute rule, `swp.peerstart`) enough against replay and held-back frames?
5. **3-7.** Does invite-path authentication hold with persistent identity keys and parallel link sessions? The tool gave no result.
6. **D10, D13, O12, O13.** Is the simplified PQ epoch ratchet (whole `ek` and `ct` per message, alternating keygen sides, pacing by count and time, four-epoch window) sound, and how serious are the stall and old-epoch forgery issues?
7. **D2.** Single use of `EPK` is enforced by the client, not a server. What happens if a client fails to enforce it?
8. **D5, 8.2.** Rollback reuses `mk` and `body_nonce`. Swell's own backups exclude session state. Restores by the operating system's own device backup: not specified.
9. **O15.** Header-key trial is quadratic in the number of stored header keys (up to 2000). Is that a practical denial-of-service?
10. **O10.** ML-KEM-768 vectors come from CryptoKit; NIST ACVP vectors are not added yet. Is Bouncy Castle's ML-KEM use correct at the edges (modulus check, implicit rejection)?
11. **Parsers.** Fuzzing beyond the unit-level pass and crash tests at every transaction boundary are still to do (spec 13). Kotlin fuzz targets exist in `android/fuzz/`; a Swift fuzz harness does not.
12. **D7, O2.** Should the invite-path HELLO prefix be sealed to hide `ID_J` from the operator, and with which key?
