#!/bin/sh
# Formal models of the Swell Protocol. Results and limits: docs/FORMAL-RESULTS.md.
#
# Usage:  ./run.sh [filter]
#   filter  run only jobs whose name contains it, e.g. ./run.sh quantum,
#           ./run.sh tamarin, ./run.sh legacy (draft 0.1 models, obsolete).
#           Without a filter: every draft 3, draft 2 and draft 1 job (ProVerif, then Tamarin).
#           ./run.sh 3_  runs only the draft 3 jobs, ./run.sh 2_ only the draft 2 jobs.
# Env:    PROVERIF=/path/to/proverif   (ProVerif 2.05)
#         TAMARIN=/path/to/tamarin-prover  (Tamarin 1.12, needs maude)
#         TIMEOUT=seconds per job (default 900). A timeout means NO result.
#
# Jobs run one after the other on purpose: keep the machine cool.
# ProVerif variants: lines of the form (*M:NAME ... *) are uncommented per variant.
cd "$(dirname "$0")" || exit 1
PV=${PROVERIF:-proverif}
TM=${TAMARIN:-tamarin-prover}
TO=${TIMEOUT:-900}
ONLY=$1
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

want() { case "$1" in *"$ONLY"*) return 0 ;; *) return 1 ;; esac; }
legacy_ok() { case "$1" in legacy*) [ -n "$ONLY" ] && want "$1" ;; *) want "$1" ;; esac; }

pv() { # file name markers...
  f=$1; name=$2; shift 2
  legacy_ok "$name" || return 0
  cp "$f" "$T/$name.pv"
  for m in "$@"; do sed -i.bak "s/(\*M:$m \(.*\) \*)/\1/" "$T/$name.pv"; done
  echo "=== proverif $name ($*)"
  s=$(date +%s)
  timeout "$TO" "$PV" "$T/$name.pv" > "$T/$name.out" 2>&1; rc=$?
  grep -E "^RESULT|^Error|syntax" "$T/$name.out"
  [ $rc -eq 124 ] && echo "TIMEOUT after ${TO}s: no result for $name"
  echo "time $(( $(date +%s) - s ))s"
}

tm() { # file name lemma
  f=$1; name=$2; lemma=$3
  want "tamarin $name" || return 0
  echo "=== tamarin $name"
  s=$(date +%s)
  if [ "$lemma" = "-" ]; then  # wellformedness + derivation checks only
    timeout "$TO" "$TM" --derivcheck-timeout=300 "$f" > "$T/$name.out" 2>&1; rc=$?
    grep -q "WARNING" "$T/$name.out" && echo "WARNING: checks failed, see tamarin output" || echo "wellformedness and derivation checks passed"
  else
    timeout "$TO" "$TM" --derivcheck-timeout=0 --prove="$lemma" "$f" > "$T/$name.out" 2>&1; rc=$?
  fi
  sed -n '/summary of summaries/,$p' "$T/$name.out" | grep -E "WARNING| $lemma "
  [ $rc -eq 124 ] && echo "TIMEOUT after ${TO}s: no result for $name"
  echo "time $(( $(date +%s) - s ))s"
}

# ---- draft 3 (build 27): persistent identity keys, the invite path with them, link frames (spec 5.1, 6.1, 6.4).
# Run only these with: ./run.sh 3_   Every job needs exactly one of ACTIVE or PASSIVE.
L3=swell3-link.pv
pv $L3 lk3_secrecy ACTIVE QSEC                    # unbounded link sessions + one invite: secrecy
pv $L3 lk3_auth ACTIVE QAUTH                      # ... mutual authentication of the link handshake, injective
pv $L3 lk3_invauth ACTIVE QINVAUTH                # ... the invite path with the same keys: I's HELLO came from J (no result in 900 s on 2026-11-11)
pv $L3 lk3_reset ACTIVE QRESET                    # ... only the contact can make a RESET that opens, no reflection
pv $L3 lk3_fs ACTIVE FS QSEC                      # both identity secrets stolen later: earlier sessions stay secret
pv $L3 lk3_quantum_passive PASSIVE QUANTUM QSEC   # record now, decrypt later: every X25519 key broken, ML-KEM holds
pv $L3 lk3_quantum_active ACTIVE QUANTUM QSEC     # active quantum attacker: link sessions expected to fail (D16), invite path holds
pv $L3 lk3_nodir_reset ACTIVE NODIR QRESET        # control: AD without sender and receiver, reflection expected

# ---- draft 2 (2026-11-11): handshake, upgrade inside libsignal, PQ ratchet.
# Run only these with: ./run.sh 2_
H2=swell2-handshake.pv
pv $H2 hs2_secrecy QSEC                        # honest invite: messages, RK0 and PQ0 secret
pv $H2 hs2_jauth QJAUTH                        # J authenticates I
pv $H2 hs2_iauth QIAUTH IAUTH                  # I authenticates J (cut model)
pv $H2 hs2_leak_dk LEAK_DK QSEC                # ML-KEM broken, X25519 holds
pv $H2 hs2_quantum QUANTUM QSEC                # X25519 broken (active quantum), ML-KEM holds
pv $H2 hs2_quantum_leak_dk QUANTUM LEAK_DK QSEC  # control: both broken, attack expected
pv $H2 hs2_fs FS QFS                           # all kept state (incl. PQ0) stolen after the handshake
pv $H2 hs2_snmatch_secrecy PUBINV SNMATCH QSEC # invite replaced, numbers match: secrecy
pv $H2 hs2_snmatch_iauth PUBINV SNMATCH QIAUTH IAUTH  # ... I authenticates J
U2=swell2-upgrade.pv
pv $U2 up2_secrecy QSEC                        # upgrade inside libsignal: secrecy
pv $U2 up2_auth QAUTH                          # ... mutual authentication, injective
pv $U2 up2_quantum QUANTUM QSEC                # ... every X25519 key broken, ML-KEM holds
pv $U2 up2_lsopen_auth LSOPEN QAUTH            # control: libsignal channel open to the attacker, attack expected
P2=swell2-pq-ratchet.spthy
tm $P2 pq2_wellformed -
tm $P2 pq2_executable executable
tm $P2 pq2_recovery_passive pq_recovery_passive
tm $P2 pq2_secrecy_no_theft pq_secrecy_no_theft
tm $P2 pq2_recovery_tight pq_recovery_tight
tm $P2 pq2_epoch3_safe pq_epoch3_after_epoch0_theft_safe
tm $P2 pq2_recovery_active pq_recovery_active   # attack expected (active injector, as A2)

# ---- draft 1: handshake (ProVerif). Markers: Q* pick query groups, the rest
# change the attacker or the protocol (see the header of the .pv file).
H=swell1-handshake.pv
pv $H hs_secrecy QSEC                          # honest invite
pv $H hs_jauth QJAUTH                          # J authenticates I
pv $H hs_iauth QIAUTH IAUTH                    # I authenticates J (cut model)
pv $H hs_leak_dk LEAK_DK QSEC                  # ML-KEM broken, X25519 holds
pv $H hs_quantum QUANTUM QSEC                  # X25519 broken (active quantum), ML-KEM holds
pv $H hs_quantum_leak_dk QUANTUM LEAK_DK QSEC  # control: both broken, attack expected
pv $H hs_quantum_bundle QUANTUM QBUNDLE QSEC   # quantum + saw the bundle: J impersonable, as classically
pv $H hs_leak_invite_iauth LEAK_INVITE QIAUTH IAUTH  # attack expected: first redeemer wins
pv $H hs_leak_idI_jauth LEAK_IDI QJAUTH        # I's identity key stolen: impersonate I to J?
pv $H hs_pubinv_iauth PUBINV QIAUTH IAUTH      # invite replaced, numbers not compared: attack expected (no result in 600 s, 2026-11-10)
pv $H hs_snmatch_secrecy PUBINV SNMATCH QSEC   # invite replaced, but numbers match: secrecy
pv $H hs_snmatch_jauth PUBINV SNMATCH QJAUTH   # ... J authenticates I
pv $H hs_snmatch_iauth PUBINV SNMATCH QIAUTH IAUTH  # ... I authenticates J
pv $H hs_fs FS QSEC                            # all kept state stolen after the handshake

# ---- draft 1: ratchet (Tamarin)
R=swell1-ratchet.spthy
tm $R ratchet_wellformed -
tm $R ratchet_executable executable
tm $R ratchet_fs_pcs_passive fs_pcs_classical_passive
tm $R ratchet_fs_single_theft fs_single_theft_after_send
tm $R ratchet_pcs_tight pcs_bound_is_tight
tm $R ratchet_fs_pcs_active fs_pcs_classical_active
tm $R ratchet_pq_no_theft pq_secrecy_no_theft
tm $R ratchet_pq_no_healing pq_no_healing_after_theft

# ---- draft 0.1 (obsolete: KEM epochs and RESUME were removed in draft 1)
L=legacy-draft0.1
pv $L/swell-handshake.pv legacy_base
pv $L/swell-handshake.pv legacy_leak_idJ LEAK_IDJ
pv $L/swell-handshake.pv legacy_quantum QUANTUM LEAK_ALLDH
pv $L/swell-pq-epoch.pv legacy_pq_with_mix QUANTUM
pv $L/swell-pq-epoch.pv legacy_pq_without_mix QUANTUM NOMIX
pv $L/swell-pq-epoch.pv legacy_pq_classical_only NOMIX
pv $L/swell-resume.pv legacy_resume_symmetric SYM
pv $L/swell-resume.pv legacy_resume_directional DIRECTIONAL
pv $L/swell-resume.pv legacy_resume_symmetric_leakB SYM LEAK_SKB
pv $L/swell-resume.pv legacy_resume_directional_leakB DIRECTIONAL LEAK_SKB
pv $L/swell-handshake.pv legacy_leak_invite LEAK_INVITE
pv $L/swell-handshake.pv legacy_leak_idI LEAK_IDI
pv $L/swell-handshake.pv legacy_leak_dk LEAK_DK
pv $L/swell-handshake.pv legacy_forward_secrecy FS
