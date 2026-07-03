# Report — Kerberoasting Detection (Case 001)

**Status:** 🚧 drafted — pending range verification.
**Started:** 2026-07-04

## 1. Environment

Windows Server AD domain controller (KDC) with Splunk collecting `WinEventLog:Security`; separate attacker workstation. Deliberately-vulnerable, network-isolated lab. (Lab addresses/credentials intentionally omitted from this public repo.)

## 2. Detonation

- [ ] Snapshot the range (testing mode).
- [ ] From the attacker host, run one Kerberoast: `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request` (or Rubeus `kerberoast`).
- [ ] Record the attack window (start/end timestamps) for labeling.

## 3. What the telemetry showed

- [ ] Confirm Event ID **4769** appears for each targeted SPN.
- [ ] Confirm `Ticket_Encryption_Type` = `0x17` on the roast requests.
- [ ] Record the **actual field names** the TA produced, and fix any drift back into `detection-card.md` and `splunk-search.spl`.

_Paste 2–4 redacted sample events into `sample-events.jsonl`._

## 4. Detection result

- [ ] Ran `splunk-search.spl` over the detonation window → did it fire? (rows, `distinct_spns`)
- [ ] Ran it over a quiet baseline window → any false positives? What tuned them out?
- [ ] Final threshold chosen, and why.

## 5. Honest limits

- Evasion not covered (AES / low-and-slow — see detection card, failure modes).
- Threshold tuned to this lab's baseline; would need re-baselining in production.

## 6. AI's role vs mine

The LLM drafted the detection card and the initial SPL from the attack description. Verification against real 4769 telemetry — confirming fields, fixing drift, setting the threshold, tuning lookalikes — was done against the range. The model drafts; the telemetry decides.
