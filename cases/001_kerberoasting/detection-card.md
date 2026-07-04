# Detection Card — Kerberoasting (T1558.003)

> Attack model first, query second. The query (`splunk-search.spl`) is derived from this card and was **verified against real telemetry** captured from a live detonation (see `report.md`): 1 true positive, 0 false positives over 30 days.

## Attack summary

Kerberoasting abuses a normal feature of Kerberos: any authenticated domain user can request a service ticket (TGS) for any account that has a Service Principal Name (SPN). Part of that ticket is encrypted with the **service account's password-derived key**, so it can be taken offline and cracked. Attackers deliberately request **RC4-HMAC (etype `0x17`)** because RC4 keys the ciphertext directly off the account's NT hash — no salt, no iteration — making it far faster to crack than AES (hashcat mode 13100).

No elevated privileges are required — this is a low-noise credential-access technique against service accounts, which are often over-privileged and have stale passwords. The offline crack leaves no trace; the **only** defender-visible footprint is the ticket *request* below.

## MITRE ATT&CK

- **T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting
- Tactic: Credential Access (TA0006)

## Data source

- **Windows Security Event Log**, **Event ID 4769** — "A Kerberos service ticket was requested."
- Splunk sourcetype: **`XmlWinEventLog`** (XML-format Windows event forwarding; `source="XmlWinEventLog:Security"`, `Channel=Security`). *Note:* not `WinEventLog:Security` — confirm your own environment's sourcetype.
- Logged on the **domain controller (KDC)**. Requires *Audit Kerberos Service Ticket Operations (Success)* — confirmed on in this range.

## Features (the signal)

Field names are the XML extractions (no underscores), confirmed against a real 4769:

| Field | Why it matters |
|---|---|
| `TicketEncryptionType` | `0x17` = RC4-HMAC — the weak cipher Kerberoasting forces. Prime indicator. |
| `ServiceName` | The targeted account. Exclude `krbtgt` and machine accounts (`*$`); roasting hits *user* service accounts. |
| `TargetUserName` | The requesting principal (`user@REALM`). Pivot for "one requestor, many SPNs." |
| `IpAddress` | Source host of the request (strip the `::ffff:` IPv4-mapped prefix). |
| `TicketOptions` | `0x40810000` is a common roast mask (not distinctive alone — normal clients use it too). |
| volume / velocity | Many *distinct* `ServiceName`s from one `TargetUserName` in a short window = mass-roast pattern. |

## Measured baseline (why this detection is high-fidelity here)

Over 30 days in this domain: **0 tickets with `TicketEncryptionType=0x17`** — everything is AES (`0x12`), and every SPN belongs to a machine account or `krbtgt`. So an RC4 request for a *user* service account is genuinely anomalous, and the detection is trustworthy at a threshold of **one event**. This is empirical, not assumed — it's the reason `distinct_spns` is used as a *severity* signal rather than a firing gate.

## Benign lookalikes (what would false-positive)

- Legacy applications/services that still negotiate **RC4** legitimately (weakens the `0x17` signal — see failure modes).
- Accounts that genuinely touch many services (some admin/service accounts) — inflates `distinct_spns`.
- Vulnerability scanners / AD-hygiene tools that enumerate SPNs.
- **Machine-to-machine AES traffic** (`0x12`, `*$` accounts) — the bulk of normal 4769s; excluded by the `0x17` filter *and* the `*$` exclusion.

## Labeling method (ground truth)

Live range, snapshot-capable:
1. Created a deliberately-weak service account `svc_mssql` with SPN `MSSQLSvc/...` and `msDS-SupportedEncryptionTypes=4` (**RC4-only**), reproducing the legacy-service-account condition.
2. Requested its ticket from the attacker host (`KerberosRequestorSecurityToken`) → **true positive** (`0x17`, in the detonation window).
3. Quiet baseline (30 days of normal domain activity) → **negatives** / benign-lookalike source.

## Failure modes (how this detection breaks)

1. **AES evasion** — the *first* roast in this lab returned AES (`0x12`) and was invisible; the account only produced `0x17` after being made RC4-only. A careful attacker requesting AES, or an already-AES account, slips the `0x17` filter. Mitigation: also baseline per-principal SPN-request *breadth* independent of etype.
2. **Low-and-slow** — one SPN at a time under a volume threshold. Mitigation here: firing at threshold 1 (safe because baseline RC4 = 0).
3. **Legacy-RC4 environments** — where RC4 is common, `0x17` alone is noisy; raise the bar to `distinct_spns>=3` and lean on the fan-out/velocity pattern.
4. **Machine-account / krbtgt noise** — wrong exclusions flood results with normal Kerberos traffic.
5. **Audit policy off** — no *Kerberos Service Ticket Operations* auditing → no 4769 at all.
