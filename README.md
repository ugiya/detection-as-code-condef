# detection-as-code-condef

AI-assisted **detection engineering, verified against a live range** — not just prompted into existence.

Each case takes one real attack technique, runs it in a self-hosted Windows Active Directory + Splunk lab, has an LLM draft the detection logic, and then **verifies that logic against the actual telemetry the attack produced**. A detection ships only after it fires on ground truth and survives its benign lookalikes.

Started 2026-07-04.

## Why this exists

Anyone can ask a model for a Splunk query. The engineering is in the loop *after* that: does the query fire on the real event the attack emits? Does it stay quiet on the legitimate traffic that looks similar? This repo is that loop, done in the open, as versioned detection-as-code.

## Method

For each case:

1. **Detonate** the technique in a lab with snapshot → run → revert, so the attack window is labeled ground truth.
2. **Draft** the detection with an LLM from a written detection card (attack model first, query second).
3. **Verify** the draft against the captured telemetry — confirm true positives fire, tune out benign lookalikes.
4. **Ship** the card + the verified query + a short report of what held and what didn't.

The LLM drafts and explains; the telemetry decides. No detection is committed as "working" until it has fired on real evidence.

## Cases

| # | Technique | MITRE | Status |
|---|-----------|-------|--------|
| [001](cases/001_kerberoasting/) | Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | ✅ verified — 1 true positive, 0 false positives / 30d |

## Lab

A self-hosted Windows Server AD domain (deliberately vulnerable, network-isolated) with Splunk collecting Windows Security event logs, plus an attacker workstation, built on the [Ludus](https://ludus.cloud) range framework. Lab addresses and credentials are **not** published here — detections are written against standard `WinEventLog:Security` fields so they port to any Splunk deployment.

## Layout

```
cases/<nnn>_<technique>/
  detection-card.md    # attack model, data source, features, benign lookalikes, failure modes
  splunk-search.spl    # the detection query
  sample-events.jsonl  # representative (redacted) events the query must match / must not match
  report.md            # what was run, what fired, what was tuned, honest limits
docs/
  safety-boundaries.md
```

Built one verified case at a time.
