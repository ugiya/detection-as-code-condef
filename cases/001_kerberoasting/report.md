# Report — Kerberoasting Detection (Case 001)

**Status:** ✅ verified against live telemetry.
**Date:** 2026-07-04

## 1. Environment

Self-hosted Windows Server AD domain controller (KDC) with Splunk collecting Windows Security events as **`XmlWinEventLog`** (`Channel=Security`); a separate Windows attacker workstation. Deliberately-vulnerable, network-isolated lab. (Lab addresses/credentials intentionally omitted from this public repo.)

## 2. Detonation

1. From the attacker workstation, requested service tickets for every SPN-bearing account via LDAP + `KerberosRequestorSecurityToken` (pure PowerShell, no tooling, run as a domain user).
2. **First result was a dead end that became the most useful finding** — see §3.
3. Created a deliberately-weak target: a service account `svc_mssql` with SPN `MSSQLSvc/...` and `msDS-SupportedEncryptionTypes=4` (**RC4-only**), reproducing a legacy service account.
4. Re-roasted `svc_mssql` specifically → produced the detectable event.

## 3. What the telemetry showed

- **Sourcetype was `XmlWinEventLog`, not `WinEventLog:Security`.** The initial search returned 0 events purely because of this; the data was flowing the whole time (97× 4769 from the DC in 24h).
- **The domain is AES-only.** Across 30 days: **0 events** with `TicketEncryptionType=0x17`; every SPN belonged to a machine account or `krbtgt`. The naive first roast returned **AES (`0x12`)** and was invisible to the classic RC4 signature — a real-world evasion condition, observed rather than assumed.
- After forcing the target RC4-only, the roast produced a clean **`4769`**: `ServiceName=svc_mssql`, `TicketEncryptionType=0x17`, `TicketOptions=0x40810000`, from the attacker host.
- Confirmed field extractions (XML, no underscores): `ServiceName`, `TicketEncryptionType`, `TicketOptions`, `IpAddress`, `TargetUserName`.

## 4. Detection result

- `splunk-search.spl` run over the last **30 days**: **1 match — the roast itself. 0 false positives.**
- Over the same window the machine-account/AES traffic that dominates 4769 (e.g. `DC01$` with `0x12`) is correctly excluded, by both the `0x17` filter and the `*$` exclusion.
- Firing threshold set to **1 event**, justified by the measured baseline (RC4 = 0). `distinct_spns` is emitted as a **severity** signal (`>=3` = mass roast) rather than a firing gate.

## 5. Honest limits

- **AES evasion** — the detection keys on RC4; an attacker requesting AES (or an already-AES account) evades it. Documented as failure mode #1; a breadth-of-SPNs detection would complement it.
- **Baseline-dependent** — the threshold-of-1 fidelity holds *because* this environment's RC4 baseline is zero. In a legacy-RC4 shop the query would need `distinct_spns>=3` and velocity logic.
- **We weakened an account to demonstrate the signal** — no real service account existed to roast. The report is explicit that the vulnerable condition was reproduced deliberately.

## 6. AI's role vs mine

The LLM drafted the detection card and initial SPL, and helped diagnose the telemetry (wrong sourcetype, AES-vs-RC4, field-name drift) by querying Splunk directly. Every claim here — the sourcetype, the AES-only baseline, the field names, the 1-TP/0-FP result — was **verified against the live range**, not asserted. The model drafts and reasons; the telemetry decides.
