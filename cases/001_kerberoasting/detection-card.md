# Detection Card — Kerberoasting (T1558.003)

> Attack model first, query second. The query (`splunk-search.spl`) is derived from this card and is **not** considered valid until it fires on telemetry captured from a real detonation (see `report.md`).

## Attack summary

Kerberoasting abuses a normal feature of Kerberos: any authenticated domain user can request a service ticket (TGS) for any account that has a Service Principal Name (SPN). The portion of that ticket encrypted with the service account's password hash can be taken offline and cracked. Attackers deliberately request the ticket with **RC4-HMAC (etype `0x17`)** because it cracks far faster than AES. Common tooling: `GetUserSPNs.py` (Impacket), Rubeus (`kerberoast`), PowerView.

No elevated privileges are required — this is a low-noise credential-access technique against service accounts, which are often over-privileged and have stale passwords.

## MITRE ATT&CK

- **T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting
- Tactic: Credential Access (TA0006)

## Data source

- **Windows Security Event Log**, **Event ID 4769** — "A Kerberos service ticket was requested."
- Splunk sourcetype: `WinEventLog:Security` (via the Splunk Add-on for Microsoft Windows).
- Logged on the **domain controller (KDC)**. Requires *Audit Kerberos Service Ticket Operations (Success)* to be enabled — on in many AD builds; confirm in the lab.

## Features (the signal)

| Field (TA extraction) | Why it matters |
|---|---|
| `Ticket_Encryption_Type` | `0x17` = RC4-HMAC — the weak cipher Kerberoasting forces. Prime indicator. |
| `Ticket_Options` | Rubeus / Impacket commonly emit `0x40810000` or `0x40800000`. |
| `Service_Name` | The targeted SPN account. Exclude `krbtgt` and machine accounts (`*$`). |
| `Account_Name` | The requesting user — pivot for "one account, many SPNs." |
| `Client_Address` | Source host of the requests. |
| volume / velocity | Many *distinct* SPNs requested by one account in a short window = roast pattern. |

## Benign lookalikes (what will false-positive)

- Legacy applications/services that still negotiate **RC4** legitimately (older Windows, misconfigured SPNs).
- Accounts that genuinely touch many services (some admin or service accounts).
- Vulnerability scanners / AD-hygiene tools that enumerate SPNs.
- Single, isolated 4769/RC4 events — normal churn. The *pattern*, not the single event, is the detection.

## Labeling method (ground truth)

Ludus **testing mode**: snapshot → run `GetUserSPNs` / Rubeus from the attacker host → revert.
- Events inside the detonation window = **true positives**.
- A quiet baseline window (normal domain activity) = **negatives** / benign-lookalike source.

This produces labeled data that public datasets can't give.

## Failure modes (how this detection breaks)

1. **AES evasion** — a careful attacker requests AES (etype `0x12`); the `0x17` filter misses it. Mitigation: also baseline per-account SPN-request *breadth* independent of etype.
2. **Low-and-slow** — one SPN at a time, under the volume threshold. Mitigation: longer window / lower threshold with reputation.
3. **Field-name drift** — extraction names vary across Splunk_TA_windows versions and XML vs classic WinEventLog. **Must be confirmed against the lab's actual events** before trusting the query.
4. **Machine-account / krbtgt noise** — wrong exclusions flood the results with normal Kerberos traffic.
5. **Audit policy off** — if *Kerberos Service Ticket Operations* auditing isn't enabled, there are no 4769 events at all.
