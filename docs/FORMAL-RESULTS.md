# Swell Protocol: formal analysis results

Run on 2026-11-10 against **draft 1** and on 2026-11-11 against **draft 2** and **draft 3** of `docs/SWELL-PROTOCOL-SPEC.md`, by AI agents, on the owner's Mac. This is internal work. It is not an independent audit, and a model is only as good as its abstractions. The owner rule of 2026-11-04 ("without outside review, libsignal stays for public users") was replaced by the owner on 2026-11-11 (`docs/BUILD-27-CHECKLIST.md`, owner decisions): libsignal is removed in build 27 and the app says honestly that the Swell Protocol has not had an independent security audit yet and that one is planned; an internal review comes first, an independent audit (NLnet) after. The draft 3 results come first, then draft 2, whose results still hold for what draft 3 did not change (the handshake key schedule, the ratchet and the PQ epoch ratchet), then draft 1 for the classical Double Ratchet.

How to read a result:
- **Proved**: the tool finished and found no attack *in the model*. The model is simpler than the spec (see "Limits"), and much simpler than the code.
- **Attack found**: the tool produced a concrete attack trace. Some of these are expected, for example a control run that must fail, or a limit the spec already admits. Each one is explained in plain words.
- **No result**: the tool ran out of time. Nothing is claimed.

## Tools

| Tool | Version | How it was installed |
|---|---|---|
| ProVerif | 2.05 | Built from the official source tarball (`bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz`) with Homebrew OCaml 5.5.2, `./build -nointeract`. Installed in `~/.local/opt/proverif2.05`, linked as `~/.local/bin/proverif`. No sudo. |
| Tamarin | 1.12.0, Maude 3.5.1 | `brew install tamarin-prover/tap/tamarin-prover`, after `brew trust tamarin-prover/tap` (the official Tamarin tap; Homebrew now asks for that trust step). No sudo. |

## Files

| File | What it models |
|---|---|
| `docs/formal/swell3-link.pv` | Draft 3: one persistent identity key per person (5.1), unbounded link handshakes between two contacts (6.4: OFFER, HELLO with READY, I's first DATA), RESET frames both ways, and one invite-path first contact (6.1, 6.2, version 5 binding) with the same identity keys, all in parallel. ProVerif. |
| `docs/formal/swell2-handshake.pv` | Draft 2 invite path handshake: draft 1's model plus the 128-byte handshake output with `PQ0`, every message key combined with `PQ0`, and a probe for `PQ0`. ProVerif. |
| `docs/formal/swell2-upgrade.pv` | Draft 2 section 6.4: the upgrade of a libsignal chat, OFFER and HELLO inside libsignal (a private authenticated channel), READY on the open network. ProVerif. |
| `docs/formal/swell2-pq-ratchet.spthy` | Draft 2 section 7.6: the post-quantum epoch ratchet, epochs 0 to 3, theft at any moment, the Double Ratchet handed to the attacker. Tamarin. |
| `docs/formal/swell1-handshake.pv` | Draft 1 invite, handshake, HELLO as ratchet message 0, and I's first reply (spec sections 5, 6, 7.1 to 7.5, 8.3). ProVerif. |
| `docs/formal/swell1-ratchet.spthy` | Draft 1 DH ratchet after the handshake, 4 messages in strict ping-pong, with phone theft at any step and a quantum attacker. Tamarin. |
| `docs/formal/run.sh` | Runs every job one after another with a time limit. |
| `docs/formal/legacy-draft0.1/` | The three ProVerif models of draft 0.1. Obsolete, kept for history (see "Old models"). |

## Results for draft 3 (2026-11-11)

Model `swell3-link.pv`, ProVerif 2.05, jobs `./run.sh lk3_`. What is new against draft 2: the identity keys are the same in every session (persistent), sessions are unbounded on both sides, and the link frames are sealed with a static-static key, so cross-session and cross-protocol use of the identity keys is in the model.

| # | Job | Property | Result |
|---|---|---|---|
| 3-1 | `lk3_secrecy` | Unbounded link sessions plus one invite, active network attacker: I's first DATA after a link handshake, the RK0 and PQ0 probes, J's first text and I's reply on the invite path stay secret; the run is executable | **Proved** (105 s) |
| 3-2 | `lk3_auth` | When J accepts I's first DATA, an I session sent exactly that (injective); when I accepts a link HELLO, a J session made exactly that for this offer (injective) | **Proved** (both queries; the job then hit the 900 s limit on a third query, moved to 3-7) |
| 3-3 | `lk3_reset` | A RESET that opens at a phone was made by the contact, for that direction: no third party, no reflection of a phone's own RESET | **Proved** (56 s) |
| 3-4 | `lk3_fs` | Both identity secrets stolen afterwards (phase 1): every earlier session secret stays secret | **Proved** (829 s) |
| 3-5 | `lk3_quantum_passive` | Every X25519 private key known to the attacker, frames recorded but not injected ("record now, decrypt later"): all secrets above stay secret, by ML-KEM-768 | **Proved** (85 s) |
| 3-6 | `lk3_quantum_active` | Same, attacker may also inject | **Attack found, as expected (D16)** for the link session: with the identity secrets the attacker forges an OFFER with its own ML-KEM key and reads that session (110 s). The invite-path secrets **stay secret** (the bundle reached J out of band, so its ML-KEM key is honest). |
| 3-7 | `lk3_invauth` | Invite path with persistent keys: I's accepted HELLO came from the real J | **No result** (900 s limit, twice). The draft 2 model proves it for one session with random keys (2-2, 2-3); with persistent keys and unbounded link sessions in parallel it is open. |
| 3-8 | `lk3_nodir_reset` | Control: link AD without sender and receiver | **Attack found, as expected**: a phone's own RESET, reflected back to it, opens as if the contact had sent it (both directions share one key). This is why the AD names sender and receiver (6.4). |

### Draft 3 limits

- Engine rules are not modelled: the 15-day and 5-minute windows, "only I offers", "an ACTIVE session is never replaced by an offer", the SYNC answer to an offer, the bit 8 rule, the once-a-day limits, outbox re-sealing. What RESET deletes is not modelled, only who can make one.
- SwellSig (spec 5.2) and signed group states are in no model yet; they rest on RFC 8032 verification and the vectors, plus review (D15, O17).
- Link frames are classical by design (D16): a quantum attacker who also injects is expected to break link sessions (3-6). The model gives no post-quantum claim for identity authentication, as in PQXDH.
- Same primitive abstractions as draft 2 (perfect AEAD, ideal KEM, random-oracle KDFs, abstract X25519; the identity validity check of 5.1 is what keeps low-order keys out).

## Results for draft 2 (2026-11-11)

All jobs through `./run.sh 2_` (one at a time, `nice`, 600 s limit). Times are wall-clock.

| # | Property (plain words) | Tool | Job | Result | Time |
|---|---|---|---|---|---|
| 2-1 | **Secrecy** of J's first message, I's first reply, RK0 and the new epoch-0 PQ key PQ0, honest invite | ProVerif | `hs2_secrecy` | **Proved** (and J can reach ACTIVE) | 26 s |
| 2-2 | **J authenticates I** with key confirmation, one-to-one | ProVerif | `hs2_jauth` | **Proved** | 93 s |
| 2-3 | **I authenticates J** ("whoever held the invite"), one-to-one, cut model as draft 1 | ProVerif | `hs2_iauth` | **Proved** | 2 s |
| 2-4 | Hybrid: ML-KEM key leaked, X25519 holds | ProVerif | `hs2_leak_dk` | **Proved** (all four secrets) | 74 s |
| 2-5 | Hybrid: every X25519 key broken (active quantum), ML-KEM holds | ProVerif | `hs2_quantum` | **Proved** | 7 s |
| 2-6 | Control: both broken | ProVerif | `hs2_quantum_leak_dk` | **Attack found (expected)** | 19 s |
| 2-7 | **Forward secrecy of the handshake**: all kept state stolen afterwards, including PQ0 (still the current epoch key) | ProVerif | `hs2_fs` | **Proved** for both messages and RK0 | 66 s |
| 2-8 | Invite replaced, safety numbers match: secrecy | ProVerif | `hs2_snmatch_secrecy` | **Proved** | 136 s |
| 2-9 | Invite replaced, safety numbers match: I authenticates J | ProVerif | `hs2_snmatch_iauth` | **Proved** | 25 s |
| 2-U1 | **Upgrade (6.4): secrecy** of the HELLO message, the READY reply, RK0 and PQ0 | ProVerif | `up2_secrecy` | **Proved** | 1 s |
| 2-U2 | **Upgrade: mutual authentication**, both directions injective (J's ACTIVE matches I's reply; I's accept matches J's start) | ProVerif | `up2_auth` | **Proved** | 6 s |
| 2-U3 | Upgrade with every X25519 key broken | ProVerif | `up2_quantum` | **Proved** | 2 s |
| 2-U4 | Control: libsignal channel open to the attacker | ProVerif | `up2_lsopen_auth` | **No result** (600 s). The attack is obvious (the attacker answers the offer itself), argued, not machine-found | 600 s |
| 2-P1 | Sanity: four epochs can run | Tamarin | `pq2_executable` | **Proved** (trace exists) | 0 s |
| 2-P2 | **Post-quantum recovery after theft** (the property draft 1 failed, A3). With every Double Ratchet key given to the attacker (what a quantum attacker gets after one theft), a message of epoch e leaks only if the stolen state was made no earlier than the step that generated epoch e's ML-KEM key. So a theft heals at the first epoch whose key is made after it. Passive attacker while healing. | Tamarin | `pq2_recovery_passive` | **Proved** | 4 s |
| 2-P3 | No theft: every epoch secret even with the Double Ratchet public | Tamarin | `pq2_secrecy_no_theft` | **Proved** | 18 s |
| 2-P4 | Control: a theft of J while it holds epoch 2's pending ML-KEM key exposes epoch 2 (2-P2 is tight) | Tamarin | `pq2_recovery_tight` | **Proved** (trace exists) | 4 s |
| 2-P5 | The concrete A3 case: one theft before epoch 1's key existed, epoch 3 stays secret | Tamarin | `pq2_epoch3_safe` | **Proved** | 3 s |
| 2-P6 | 2-P2 against an active attacker | Tamarin | `pq2_recovery_active` | **Attack found (expected)**, see A6 | 1 s |
| 2-P0 | Well-formedness | Tamarin | `pq2_wellformed` | Passed | 1 s |

**A first version of 2-P2 was falsified** in 1 s: it said "the stolen state was made strictly after the key generation", and Tamarin stole the Setup state itself, which holds PQ0 and is made at the same step that "generates" epoch 0. The lemma's wording was wrong, not the protocol: a keygen step's own state holds that epoch's key. The lemma now says "not before" and is proved.

**A6. Active attacker on the PQ ratchet (expected).** Tamarin's trace makes I encapsulate to an encapsulation key the attacker made. In the model EK and CT travel on the open network without authentication, and the passivity premise of 2-P2 stands in for the AEAD that protects them in the real protocol (they ride inside messages whose keys mix `mk_dr` and the epoch key). Without a theft the attacker cannot forge such a message. After a theft it can, and then it can stay in the middle, exactly as A2 for the Double Ratchet. Signal's design shares this limit.

### Draft 2 limits

- **Not remodelled after the review fixes (2026-11-11).** The stage 3 wrapping puts the Swell envelope inside the libsignal session; that only adds a layer, so every secrecy and authentication result above still holds for the Swell layer (libsignal is not modelled, and its own published analyses are what protect the outer layer). SYNC, the fresh offer after RESET and the HELLO_SENT expiry are recovery rules that are tested in `SwellProtocolEngineTests` but not modelled.

- `swell2-handshake.pv` and `swell2-upgrade.pv` keep every limit of the draft 1 handshake model below (one session, perfect cryptography, cut model for the I side). The upgrade model treats libsignal as a private authenticated channel: the engine's acceptance rules (whisper type only, key order, kept identity equals session identity) are what make that true, and they are code, tested in `SwellProtocolEngineTests`, not modelled. RESET and offer repetition are not modelled.
- `swell2-pq-ratchet.spthy` hands the whole Double Ratchet to the attacker, which is sound for the quantum-after-theft question (more attacker knowledge) but says nothing about the classical properties; those are the draft 1 ratchet results (13 to 16), which still apply because draft 2 did not change the Double Ratchet and only adds the epoch key into each message key. Epochs are unrolled to four, in strict order; pacing, the 4-epoch key window, the repeat rule, out-of-order delivery and header keys are not modelled. "Healing" is stated per epoch, not per message count; spec 7.6 turns it into "at most two epoch changes".
- No model covers skipped keys, the bucket padding, the derived header nonce, or the Swift code.

## Results for draft 1

Times are wall-clock on the owner's Mac, one job at a time. Tamarin numbers are from the final rerun of the finished model through `run.sh` (2026-11-11). For exists-trace lemmas (12, 15, 18) Tamarin prints "verified", which means a trace was found.

| # | Property (plain words) | Tool | Model / job | Result | Time |
|---|---|---|---|---|---|
| 1 | **Message secrecy.** With an honest invite, nobody but I and J learns J's first message, I's first reply, or the handshake key RK0. | ProVerif | `swell1-handshake.pv` / `hs_secrecy` | **Proved** | 26 s |
| 2 | **J authenticates I, with key confirmation.** J becomes ACTIVE only if I really sent a reply to this J, with the same transcript and the same root key RK2. One-to-one (injective). | ProVerif | `hs_jauth` | **Proved** | 89 s |
| 3 | **I authenticates J, with key confirmation.** I accepts a HELLO only if J really started this handshake with the same identity keys and the same handshake key RK0 (which binds the transcript T). One-to-one. "J" here means "whoever held the invite" (spec 6.3). | ProVerif | `hs_iauth` (cut model, see Limits) | **Proved** | 1 s |
| 4 | **Hybrid post-quantum, ML-KEM broken.** If the ML-KEM key `dk` leaks, X25519 alone still keeps 1's secrets. | ProVerif | `hs_leak_dk` | **Proved** | 51 s |
| 5 | **Hybrid post-quantum, X25519 broken.** The attacker holds every X25519 private key from the start (active quantum attacker, stronger than harvest-now-decrypt-later) and did not see the invite. It still learns none of 1's secrets, because ML-KEM holds. | ProVerif | `hs_quantum` | **Proved** | 6 s |
| 6 | Control for 4 and 5: break both X25519 and ML-KEM. The secrets must fall, otherwise 4 and 5 mean nothing. | ProVerif | `hs_quantum_leak_dk` | **Attack found (expected)**: all three secrets leak | 16 s |
| 6a | Quantum attacker who also saw the bundle (invite seen). | ProVerif | `hs_quantum_bundle` | J's message and RK0 stay secret. **Attack found** on I's reply, see A4 | 7 s |
| 7 | **Leaked invite.** Someone else saw the invite (QR or link) and races J. Does I still only accept the real J? | ProVerif | `hs_leak_invite_iauth` | **Attack found (expected, stated in spec 3 and 6)**, see A4 | 1 s |
| 7a | Same, secrecy queries. | ProVerif | (removed from run.sh) | No result (600 s) | 600 s |
| 8 | **Stolen I identity key before the handshake.** Can the thief pose as I to J? | ProVerif | `hs_leak_idI_jauth` | **Proved**: J's authentication of I still holds (the thief also needs `epk_sk` or `dk`) | 46 s |
| 9 | **Invite replaced (man in the middle), safety numbers not compared.** An attack is expected (spec D1). | ProVerif | `hs_pubinv_iauth` | No result (600 s). The attack is argued in A5, not machine-found | 600 s |
| 10 | **Safety numbers / identity keys.** The attacker may replace the whole invite. If the safety numbers match (each side saw the real other identity key), then: messages and RK0 stay secret; J authenticates I; I authenticates J. All with key confirmation. | ProVerif | `hs_snmatch_secrecy`, `hs_snmatch_jauth`, `hs_snmatch_iauth` | **Proved** (all three) | 141 s, 559 s, 25 s |
| 11 | **Forward secrecy of the handshake.** Everything I and J still hold after the handshake (current ratchet state, plus I's identity key and `dk` as if deletion had failed) is stolen later. Earlier messages and RK0 stay secret. | ProVerif | `hs_fs` | **Proved** | 81 s |
| 12 | Sanity: the full 4-message conversation can run. | Tamarin | `swell1-ratchet.spthy` / `executable` | **Proved** (trace exists) | 24 s |
| 13 | **Forward secrecy and post-compromise security, classical attacker, passive while healing.** A message m_s leaks only if (a) a phone was stolen at step s before m_s was sent, or (b) the receiver was stolen at step s-1 while waiting for it, or (c) the sender was stolen right after sending m_s *and* an earlier theft at step s-2 had not healed yet. So one theft exposes at most two messages, and the conversation heals one round trip later. | Tamarin | `fs_pcs_classical_passive` | **Proved** | 74 s |
| 13a | First version of 13 without case (c). | Tamarin | (same lemma, earlier form) | **Attack found**, see A1 | 24 s |
| 14 | **Plain forward secrecy.** If the only theft happens after m_s was sent, at any later step, m_s stays secret. | Tamarin | `fs_single_theft_after_send` | **Proved** | 280 s |
| 15 | Control for 13: a theft of J right after it sent m_1 does expose I's reply m_2, so 13 is tight. | Tamarin | `pcs_bound_is_tight` | **Attack found (expected)** | 24 s |
| 16 | Same as 13 against an **active** attacker who may inject its own ratchet keys. | Tamarin | `fs_pcs_classical_active` | **Attack found (expected)**, see A2 | 26 s |
| 17 | **Post-quantum secrecy of the whole conversation.** With no phone theft, every message stays secret even if every X25519 key breaks (active quantum attacker), because each root key descends from RK0. | Tamarin | `pq_secrecy_no_theft` | **Proved** | 81 s |
| 18 | **Post-quantum recovery after theft.** One theft plus a quantum break exposes the last message too. | Tamarin | `pq_no_healing_after_theft` | **Attack found (expected)**, see A3 | 49 s |
| 19 | Tamarin well-formedness and derivation checks of the ratchet model. | Tamarin | `ratchet_wellformed` | Passed (needs `--derivcheck-timeout` above the 5 s default) | 29 s |

### Attacks found, in plain words

**A1. A second theft inside the healing window exposes a message that was already sent.** Tamarin found this against the first, stricter wording of property 13. The thief copies I's phone early (step 0) and learns the root key the next step will use. J sends m_1 and I answers with m_2. The thief then copies I's phone again, right after it sent m_2. At that moment I still holds the private ratchet key it used for m_2, because it needs it for J's next reply. Together the two copies give m_2's key. Neither copy alone exposes m_2. This is how the published Double Ratchet works too, so it is not a Swell-specific flaw. It does mean that the sentence in spec section 3, "Messages sent before a theft stay secret once their keys are deleted", is too strong as written. See spec gap G1.

**A2. After a theft, an active attacker can stay in the middle for ever.** The thief copies I's early state, then sends I a message with its own ratchet key in place of J's. I accepts it, because the thief holds the right chain keys, and from then on every key I derives is known to the thief. All ratchets have this limit, Signal's included: healing needs at least one DH step the attacker did not tamper with. Only comparing safety numbers again or starting over with a new invite ends it, and draft 1 has no automatic way to notice.

**A3. No post-quantum recovery after a theft (expected, stated in the spec).** One copy of J's phone after it sent m_1, plus a later quantum break of X25519, exposes m_4. Property 13 shows m_4 is safe against a classical attacker. Draft 1 heals only through X25519 steps, and a quantum attacker can undo those. This is exactly the "no" in spec section 14 (no Sparse Post-Quantum Ratchet / ML-KEM Braid). **Signal's Triple Ratchet does not have this gap, so here draft 1 does not match Signal.**

**A4. Whoever knows the invite can be J (expected).** With the invite, or just the bundle's public keys (ID_I, EPK, EK), anyone can build a valid HELLO with keys of their own. I then accepts that person and sends them its reply. This holds with or without a quantum computer. The quantum attacker learns nothing extra, because the bundle is sealed under `sealKey` with AES-256. J's own message stays secret in every case: the impostor cannot read the real J's HELLO. Spec sections 3 and 5 already say the invite is a bearer token, so this is stated, not new. Comparing safety numbers is the only defence (property 10).

**A5. A replaced invite is a man in the middle (expected, deviation D1; argued, not machine-found).** If the attacker replaces the whole invite, it gives J its own bundle and redeems I's real invite itself. Both sides then talk to the attacker. ProVerif did not finish this variant in 600 s. Property 10 proves the converse: if the safety numbers match, no such attacker exists. The safety-number check is therefore not optional for anyone who needs this protection, and draft 1 does not force it.

## What the owner asked for, compared with Signal

Draft 2 changes one row: **post-quantum recovery after theft is now proved in the abstract model (2-P2)**, where draft 1 had attack A3. The handshake rows hold again for draft 2 (2-1 to 2-9), and the upgrade path is proved for one session (2-U1 to 2-U3). Review by people outside the project is still missing, so the owner rule is still not met.

| Property | Status for draft 1 | Matches Signal? |
|---|---|---|
| Secrecy of messages | Proved in the model (1, 17) | Yes, in the model |
| Mutual authentication with key confirmation | Proved for one session (2, 3, 8, 10). I's view of J is only "whoever held the invite" (A4); real identity needs the safety-number check (A5). | Comparable to PQXDH without a server-signed prekey; TOFU in both |
| Forward secrecy | Proved (13, 14), with the A1 qualification that the published Double Ratchet shares | Yes, in the model |
| Post-compromise security (heals after one round trip) | Proved against a passive attacker while healing (13). Fails against an active injector (16, A2), as for every ratchet | Yes, classical only |
| Post-quantum secrecy, harvest now decrypt later | Proved for the handshake (5, against an even stronger active quantum attacker) and for the whole conversation without theft (17) | Yes, in the model |
| Post-quantum recovery after theft | **Attack found (A3)** | **No** |
| Identity-key change detection | Matching safety numbers rule out a man in the middle (10, proved). Draft 1 never changes keys inside a relationship, so there is no change to detect, and a new invite starts a new unverified contact (G4) | Different design; see G4 |

## Limits: what the models leave out

Common to both tools:
- **Perfect cryptography.** X25519 is an abstract DH group (no small-subgroup or all-zero issues), ML-KEM is an ideal KEM, HKDF and SHA-256 are random oracles with one function per label, and AES-GCM is perfect authenticated encryption. Nonce reuse, the derived header nonce (deviation D6), key commitment, padding, lengths and byte encodings are not checked.
- **No implementation.** Key deletion, crash and rollback rules, secure_delete, memory wiping and constant time are outside the models. The models assume deleted keys are really gone.
- Time, expiry, PEEK/ACK, approval, outbox and the 7-day states are not modelled.

`swell1-handshake.pv` (ProVerif):
- **One inviter session and one joiner session.** Injectivity is checked only inside that single session. Many parallel invites were not modelled, because the replicated draft 0.1 model never finished.
- I's first-reply message and J's processing of it are modelled with `pn = n = 0`.
- **The I-side queries (3, part of 10) use a cut model.** Both processes stop right after I's accept event and J's HELLO. This is sound for those queries only. In one session, nothing I sends after accepting can cause that acceptance, and J sends nothing after the HELLO and the RK0 probe. Without the cut ProVerif did not finish in 600 s. A side effect: I's event sits right after the HELLO *header* opens (authenticated encryption under `shared_hka` with T in its AD). The body check adds a DH on an attacker-chosen ratchet key; that is covered by the secrecy queries, not by 3.
- RK0's secrecy is checked through a probe: J publishes one fixed secret encrypted under RK0.
- Identity public keys are given to the attacker at the start. That is conservative: in the real protocol ID_I sits inside the sealed bundle.
- **Safety numbers (property 10):** the attacker may replace the whole invite (`PUBINV`). "The numbers match" is modelled as a filter: each side continues only if it saw the real other identity key, which is what comparing the pair (ID_I, ID_J) checks (`SNMATCH`). In a one-session model this is the same as asking "if the numbers match, do the properties hold?". The digit encoding and the 60-byte truncation are not modelled. In the real app the HELLO goes out before anyone compares, so a mismatch is found after the fact.
- **Quantum (properties 5, 6, 6a):** every honest X25519 private key goes to the attacker as soon as it is made. A first version with a symbolic discrete-log function did not finish in 600 s. EK is not given to the attacker unless `QBUNDLE` is set, because it travels only inside the sealed bundle.

`swell1-ratchet.spthy` (Tamarin):
- **Bounded to 4 messages in strict ping-pong**, so every message starts a new DH step. Several messages per chain, skipped message keys, out-of-order delivery, MAX_SKIP and the 15-day expiry are **not modelled**. Stored skipped keys would be exposed by a theft. That is a real extra exposure the model does not show.
- RK0 is taken as a fresh shared secret. Its secrecy, including against the quantum attacker, comes from the ProVerif model (1, 5). It is an assumption in Tamarin.
- **Header encryption is dropped**: ratchet public keys travel in clear. That only helps the attacker, so the secrecy results still stand, but metadata hiding is not studied.
- A theft copies one phone's whole live state at one step: root key, current private ratchet key and both chain keys.
- "Quantum" hands over every X25519 private key of the relationship. It does not touch RK0.

## Spec gaps and questions (not guessed)

All six are answered in spec draft 2, section 17 (2026-11-11).

- **G1. Forward-secrecy wording (spec section 3, section 12).** The aim "messages sent before a theft stay secret once their keys are deleted" holds for a single theft. It fails for a second theft inside the healing window of a first one (A1), because the sender's ratchet private key lives until the next DH step. The deletion table in section 12 does not list the ratchet private key (`DHs`) at all. Question for the author: add a row "DHs private key: replaced at the next DH step" and state the A1 qualification in section 3?
- **G2. Section 6.3 says "Neither claim is proven."** Properties 2 and 3 are now proved in a one-session model. The spec should cite this file and its limits instead, still without claiming more than the model shows.
- **G3. Post-quantum recovery (section 14, O8).** A3 confirms the gap. It is the main reason draft 1 does not match Signal.
- **G4. Identity-key change detection.** Draft 1 creates fresh identity keys per relationship and never changes them, so there is no "this contact's key changed" event as in Signal. A new invite from the same person gives a new, unverified contact (section 11). The spec does not say whether the app links the new contact to the old one, warns that the number changed, or keeps both. Question: what should the user see when a known person sends a new invite? The cryptographic part (matching numbers rule out a man in the middle) is property 10.
- **G5. Active healing.** After a theft, draft 1 has no way to notice an injected ratchet key (A2). Signal has the same limit. Question: should the app ask users to compare safety numbers again after a device is lost or stolen?
- **G6. Skipped keys and theft.** The 2000 stored skipped keys and their header keys are exposed by a theft until they expire (15 days). The models do not cover them. Question: should section 3 list this next to the deletion caveat?

## Old models (draft 0.1)

The three models that were in `docs/formal/` describe draft 0.1, not draft 1. They now live in `docs/formal/legacy-draft0.1/`. They were rerun on 2026-11-10 (ProVerif 2.05, 300 s limit) so the old record can be checked:

| Model / variant | Result | Time |
|---|---|---|
| handshake `base` | 3 secrecy and 3 agreement queries proved; honest run reachable | 131 s |
| handshake `leak_invite` | no result (timeout) | 300 s |
| handshake `leak_idJ` | all proved | 38 s |
| handshake `leak_idI` | all proved (did not finish in 100 s in review 1) | 179 s |
| handshake `leak_dk` | 3 secrecy and 3 agreement queries proved; the 2 reachability checks did not finish | 300 s (timeout) |
| handshake `quantum` | all proved | 13 s |
| handshake `forward_secrecy` | 3 secrecy queries in phase 1 proved; the agreement queries did not finish | 300 s (timeout) |
| pq-epoch `pq_with_mix` | secret proved | 1 s |
| pq-epoch `pq_without_mix` (control) | attack found (expected) | 8 s |
| pq-epoch `pq_classical_only` | secret proved | 0 s |
| resume `symmetric` | attack found (reflection, as in review 1) | 0 s |
| resume `directional` | proved | 0 s |
| resume `symmetric_leakB`, `directional_leakB` | attack found (expected with a stolen key) | 0 s |

Where they no longer match draft 1:
1. The old handshake encrypts a separate HELLO body under its own key (`hs_hello`) and then sends a further J message. In draft 1 the HELLO *is* ratchet message 0: header under `shared_hka`, body under the first message key of `KDF_RK(RK0, DH(ratchet_sk, EPK))`. J sends nothing else until I replies.
2. The transcript T has no `expiresAtMs`. Draft 1 includes it.
3. Header AD is `adrel(ID_I, ID_J)`, and body AD is only the header ciphertext. Draft 1 uses `"SWL1-H" | prefix | T` for the header and `"SWL1-M" | T | prefix | hnonce | hct` for the body.
4. The header carries a PQ flag (`pq0`). The draft 1 header is only `dh_pub | pn | n`.
5. KEM epochs (`swell-pq-epoch.pv`) and RESUME (`swell-resume.pv`) were removed in draft 1. Those two models describe features that no longer exist.
6. The bundle had no version or expiry. Safety numbers were not modelled.

All six are fixed in `swell1-handshake.pv`, which was written fresh from draft 1.

## How to rerun

```sh
cd docs/formal
./run.sh lk3_            # only the draft 3 jobs (about an hour: lk3_fs alone takes 14 minutes, two jobs run to the limit)
./run.sh 2_              # only the draft 2 jobs (about 25 minutes, most of it up2_lsopen_auth hitting the limit)
./run.sh                 # every draft 3, draft 2 and draft 1 job, ProVerif then Tamarin, one at a time
./run.sh hs_             # only the ProVerif handshake jobs
./run.sh tamarin         # only the Tamarin ratchet jobs
./run.sh legacy          # the obsolete draft 0.1 models
TIMEOUT=1200 ./run.sh hs_quantum
```

Do not edit `run.sh` while it runs: the shell reads it as it goes. Environment variables: `PROVERIF` and `TAMARIN` point at the binaries (default: on PATH), and `TIMEOUT` is seconds per job (default 900). A job that hits the limit prints `TIMEOUT ... no result`. Report that as "no result", never as a pass. Expected outcomes are written next to each job in `run.sh` and in the table above. Where a job is expected to find an attack, ProVerif prints `is false` and Tamarin prints `falsified` (all-traces lemma) or `verified` (exists-trace lemma).

The whole draft 1 set takes about 45 minutes on the owner's Mac. Most of that is `hs_pubinv_iauth`, which runs to the time limit, and `hs_snmatch_jauth` (about 9 minutes). Jobs run one at a time on purpose, to keep the machine cool.

## What would make this stronger

- A ProVerif or Tamarin model with many parallel sessions of the handshake.
- Several messages per chain, skipped keys and out-of-order delivery in the ratchet model.
- A computational proof (for example CryptoVerif) of the combiner in deviation D3, which the symbolic tools cannot judge.
- Review of these models by someone who did not write them or the spec.
