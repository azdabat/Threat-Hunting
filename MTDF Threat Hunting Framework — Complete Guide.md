# MTDF Threat Hunting Framework — Complete Guide
### PEAK · TaHiTI · MITRE-Mapped KQL Examples

**Author:** Ala Dabat | 2026
**Framework:** [Minimum Truth Detection Framework](https://github.com/azdabat/Minimum-Truth-Detection-Framework-ADX-Validated-Composite-Rules)
**Primary sources:** [hunt.io — Threat Hunting Framework](https://hunt.io/glossary/threat-hunting-framework) · [hunt.io — PEAK Framework](https://hunt.io/glossary/peak-threat-hunting-framework) · [hunt.io — TaHiTI Framework](https://hunt.io/glossary/tahiti-threat-hunting-framework)

---

## A correction made while building this guide

Going back to the primary TaHiTI source material for this pass surfaced something
worth fixing rather than quietly carrying forward: **TaHiTI has 7 phases, not 6.**
Your existing `HUNT_PROMPT` doctrine (and the `T1-T6` lifecycle naming) was missing
TaHiTI's real **Phase 2 — Scoping and Prioritizing Threats** as its own numbered
phase. Last session's `hq_scope` question patched the *content* of this gap into
the intake form, but never renumbered the lifecycle labels to match. This guide
uses the correct 7-phase numbering throughout, and the companion prompt update
fixes the labels in the live doctrine to match.

```mermaid
flowchart LR
    Old["OLD (incorrect) labelling:<br/>T1 Trigger → T2 Hypothesis → T3 Data →<br/>T4 Analysis → T5 Iterate → T6 Outcome<br/>(6 phases — scoping folded into intake,<br/>never its own numbered phase)"]
    New["CORRECTED — matches real TaHiTI:<br/>P1 Intel Intake → P2 Scoping/Prioritising →<br/>P3 Hypothesis/Hunt Plan → P4 Data Collection →<br/>P5 Execution → P6 Findings/Response →<br/>P7 Feedback/Metrics<br/>(7 phases, properly numbered)"]
    Old -.->|"corrected in this pass"| New
```

---

## Part 1 — What a Threat Hunting Framework Actually Does

A threat hunting framework is a **documented, repeatable process** for planning,
running, and operationalising hunts — not a one-off investigation technique.
Without one, hunting becomes hero-driven (dependent on individual analyst
expertise, lost when they leave) rather than an institutional capability.

```mermaid
flowchart TD
    A["No Framework"] --> A1["Hunts go undocumented —\nknowledge leaves with the analyst"]
    A --> A2["Different hunters repeat\nthe same work unknowingly"]
    A --> A3["Findings never become\nautomated detections"]
    A --> A4["Leadership sees hunting as\n'nice to have', not strategic"]

    B["With a Framework"] --> B1["Consistent documentation,\nactionable metrics"]
    B --> B2["Findings feed directly into\ndetection engineering"]
    B --> B3["Clear hand-offs to SOC/IR"]
    B --> B4["Measurable program maturity\nover months and years"]
```

**The five components every effective framework needs** (per the source material):
intelligence-driven hypotheses, supporting data, adversary model-based
correlation, field-tested scenarios, and automation. MTDF's three-layer
inference spectrum (Primitive/Router/Composite) *is* the "automation" and
"adversary model-based correlation" components — this is exactly why MTDF and
PEAK/TaHiTI integrate cleanly rather than competing.

---

## Part 2 — PEAK: Prepare, Execute, Act with Knowledge

PEAK (Splunk, 2023) is the **execution-cycle framework** — it tells you *how
a single hunt moves through its lifecycle*, regardless of what triggered it.

```mermaid
flowchart LR
    subgraph PEAK["The PEAK Loop"]
        P["PREPARE\nDefine goal · Pick data sources\nScope the hunt"]
        E["EXECUTE\nRun queries · Pivot on findings\nConfirm or refute"]
        A["ACT WITH KNOWLEDGE\nBuild detections · Update playbooks\nHarden controls"]
        P --> E --> A --> P
    end
    K["KNOWLEDGE\n(threat intel, incident history,\nred-team findings, past hunts)"] -.->|"informs every phase,\nnot a separate step"| PEAK
```

### The three PEAK hunt types

```mermaid
flowchart TD
    Start["What's driving this hunt?"] --> Q1{"Specific testable claim<br/>about adversary behaviour?"}
    Q1 -->|Yes| HD["HYPOTHESIS-DRIVEN<br/>'If X compromised an account,<br/>they'll use OAuth grants within 14 days'"]
    Q1 -->|"No — want to know<br/>what's normal first"| Q2{"Have 90+ days of<br/>historical data?"}
    Q2 -->|Yes| BL["BASELINE<br/>Establish normal admin access<br/>to DCs, flag deviations"]
    Q2 -->|"No data yet,<br/>but have UEBA/ML"| MA["MODEL-ASSISTED (M-ATH)<br/>Model pre-surfaces risk scores,<br/>analyst validates"]
```

| Hunt Type | Best For | Key Requirement | MTDF Mapping |
|---|---|---|---|
| Hypothesis-Driven | Investigating specific threat intel | Clear, testable, falsifiable claim | Hunt's **E — Entity** and **A — Anomaly** types |
| Baseline | Understanding normal, surfacing anomalies | 90+ days historical data | Hunt's **B — Baseline** type |
| Model-Assisted | Scaling with automation | ML/UEBA capability | Hunt's **M — Model-Assisted** type |

This is the exact three-type structure already corrected into your live
`HUNT_PROMPT` (B/M split from the old conflated "Pattern" bucket) — confirmed
accurate against the primary source, not just internally consistent.

---

## Part 3 — TaHiTI: The 7 Real Phases

TaHiTI (Dutch Payments Association, 2018) is the **intelligence-integration
framework** — it tells you *where the hunt's hypothesis comes from* and how
intelligence flows through the entire lifecycle, not just at the start.

```mermaid
flowchart TD
    P1["PHASE 1: Preparation &<br/>Threat Intelligence Intake"] --> P2
    P2["PHASE 2: Scoping &<br/>Prioritising Threats"] --> P3
    P3["PHASE 3: Formulating Hypotheses<br/>& Hunt Plans"] --> P4
    P4["PHASE 4: Data Collection,<br/>Normalisation & Enrichment"] --> P5
    P5["PHASE 5: Hunt Execution &<br/>Analytical Techniques"] --> P6
    P6["PHASE 6: Documenting Findings,<br/>Response & Remediation"] --> P7
    P7["PHASE 7: Feedback, Metrics &<br/>Continuous Improvement"] -.->|"feeds back into"| P1
```

### Phase 1 — Sources of intelligence (the open-source question, answered directly)

This is exactly where your "can we use open-source threat intelligence"
question fits. TaHiTI's own Phase 1 names these legitimate intake sources —
all of them open or commercially-available, none requiring proprietary access:

| Source Category | Examples | Open-Source? |
|---|---|---|
| Government advisories | CISA, NCSC, CERT-EU | ✅ Fully open |
| MITRE ATT&CK mappings | attack.mitre.org | ✅ Fully open |
| ISAC/sector communities | FS-ISAC, sector-specific sharing groups | Membership-gated, not paid |
| Commercial CTI feeds | Vendor threat intel platforms | ❌ Paid |
| Internal incident history | Your own past IR cases | Internal, not external |
| Red/purple team findings | Your own exercises | Internal |
| Malware sandbox results | Detonated samples (yours or shared) | Mixed |

**Direct answer:** yes — CISA advisories, MITRE ATT&CK, and CERT-EU bulletins
are all legitimate, free, citable intel sources for Hunt's Trigger/Scoping
questions. What's **not yet built** is live automated ingestion of these feeds
into the app (e.g., a STIX/TAXII puller) — right now, you'd manually paste a
CISA advisory's content into Hunt's intake, the same way Novel Threat already
handles a pasted CVE or article. Automated feed ingestion is a real, separate
feature — flagged as a roadmap item, not something to claim is already live.

### Phase 2 — Scoping and Prioritising (the gap this guide fixes)

Not every piece of intel deserves a hunt. TaHiTI ranks using four factors:

```mermaid
flowchart TD
    Intel["New threat intel arrives"] --> F1{"Sector relevance?<br/>(targets payment processors,<br/>and we're a bank = HIGH)"}
    F1 --> F2{"Active campaign<br/>in our region?"}
    F2 --> F3{"Tech stack overlap?<br/>(Azure AD, AWS IAM, K8s —<br/>only relevant if we run it)"}
    F3 --> F4{"Regulatory impact?<br/>(NIS2, DORA compliance driver)"}
    F4 --> Tier{"Assign tier"}
    Tier -->|"All 4 factors high"| High["HIGH PRIORITY<br/>Active queue, immediate hunt"]
    Tier -->|"2-3 factors present"| Med["MEDIUM PRIORITY<br/>Emerging, could escalate"]
    Tier -->|"Theoretical/unlikely"| Low["LOW PRIORITY<br/>Documented, revisit later"]
```

This is precisely what your `hq_scope` question already implements — confirmed
correct against the primary source.

### Phases 3-7 — Hypothesis through Continuous Improvement

```mermaid
flowchart LR
    subgraph P3["Phase 3 — Hypothesis"]
        H["'If actor targets EU payment\nprocessors via T1078.004, Azure AD\nsign-in logs show anomalous\nlogin patterns from unseen IPs'"]
    end
    subgraph P4["Phase 4 — Data"]
        D["Normalise fields across\nAWS/Azure/GCP · Enrich with\ngeo-IP, threat intel, asset criticality"]
    end
    subgraph P5["Phase 5 — Execution"]
        E["ATT&CK-aligned queries ·\nFrequency analysis · Entity pivoting ·\nTargeted IOC sweeps"]
    end
    subgraph P6["Phase 6 — Findings"]
        F["Confirmed → IR ticket ·\nClean → validates posture ·\nEither way: documented"]
    end
    subgraph P7["Phase 7 — Feedback"]
        FB["New detection rules ·\nRefined scoping criteria ·\nShared with ISAC community"]
    end
    P3 --> P4 --> P5 --> P6 --> P7
```

**Key metrics TaHiTI tracks** (Phase 7): hunts per quarter, intel-derived vs.
incident-derived ratio, time to confirm/refute, hunts yielding new detections,
dwell time reduction. These map directly onto what your Hunt Record/Hunt
Library should be capturing per session — currently captured qualitatively in
your doctrine's Hunt Record format, not yet tracked as aggregate metrics
across sessions (a Rule Library-adjacent feature, not yet built).

---

## Part 4 — How PEAK and TaHiTI Combine (and Map to MTDF)

```mermaid
flowchart TD
    subgraph Strategic["STRATEGIC LAYER — PEAK"]
        direction LR
        Prep["Prepare"] --> Exec["Execute"] --> Act["Act with Knowledge"]
    end
    subgraph Tactical["TACTICAL LAYER — TaHiTI (sits inside Prepare)"]
        direction LR
        T1["P1 Intel Intake"] --> T2["P2 Scoping"] --> T3["P3 Hypothesis"]
    end
    subgraph MTDF["MTDF OUTPUT LAYER"]
        direction LR
        Prim["Primitive"] --> Rout["Router Rule"]
        Prim --> Comp["Composite"]
    end

    Tactical -.->|"operationalises"| Strategic
    Act -->|"True Positive"| MTDF
```

| PEAK Phase | TaHiTI Equivalent | MTDF Output |
|---|---|---|
| Prepare | Phases 1-3 (Intel → Scoping → Hypothesis) | — |
| Execute | Phases 4-5 (Data → Execution) | Architecture 4 Hunt Query |
| Act with Knowledge | Phases 6-7 (Findings → Feedback) | Primitive / Router / Composite, per noise-domain test |

This is the precise relationship your doctrine's "connective tissue" paragraph
already states in prose — this table just makes it literal.

## Part 5 — Worked Hunt Examples Across Major MITRE Tactics

Every example below follows the same structure: PEAK type declared, TaHiTI
hypothesis stated in the mandatory falsifiable format, then the Architecture 4
hunt query — tagged, never scored, exactly per MTDF Hunt doctrine.

---

### Example 1 — Registry-Based Persistence (T1547.001 — Run Keys)

**PEAK Type:** E — Entity (Intel-driven: known persistence technique)
**TaHiTI Phase 3 Hypothesis:** *"I hypothesise that an attacker has established
persistence via a Run key because no legitimate software deployment occurred
in this window, which would be visible as a new RegistryValueData payload in
DeviceRegistryEvents."*

```mermaid
flowchart LR
    A["Attacker has code execution"] --> B["Write to HKCU/HKLM\nRun or RunOnce key"]
    B --> C["Payload path stored in\nRegistryValueData"]
    C --> D["Survives reboot —\nre-executes at logon"]
    D --> E["Why this surface:\nRun keys are processed by\nexplorer.exe automatically —\nno additional attacker action needed"]
```

```kql
// ============================================================================
// HUNT QUERY: Run Key Persistence — Non-Standard Payload Path
// ============================================================================
// PEAK Type: E — Entity | TaHiTI Phase: 5 — Execution
// MITRE: T1547.001
// ⚠ HUNT MODE — NOT FOR PRODUCTION DEPLOYMENT ⚠
// Schema Confidence: DeviceRegistryEvents fields confirmed against MTDF
// Schema Reference. Fields used: Timestamp, DeviceId, DeviceName, ActionType,
// RegistryKey, RegistryValueData, InitiatingProcessFileName,
// InitiatingProcessAccountName. No hallucinated fields.
// ============================================================================

let lookback = 30d;  // user-specified — Run key persistence often dormant for weeks

DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
| extend
    HasWritablePath   = toint(RegistryValueData matches regex
                          @"(?i)(\\temp\\|\\appdata\\|\\programdata\\|\\users\\public\\)"),
    HasEncodedPayload = toint(RegistryValueData has_any ("-enc", "frombase64string", "iex")),
    IsScriptParent    = toint(InitiatingProcessFileName in~
                          ("wscript.exe", "cscript.exe", "powershell.exe", "cmd.exe"))
| extend HuntSignals = strcat(
    iif(HasWritablePath == 1,   "[WRITABLE_PATH] ", ""),
    iif(HasEncodedPayload == 1, "[ENCODED_PAYLOAD] ", ""),
    iif(IsScriptParent == 1,    "[SCRIPT_PARENT] ", "")
)
| project
    Timestamp, DeviceName, RegistryKey, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessAccountName,
    HuntSignals, DeviceId
| sort by Timestamp desc
| take 10000

// HUNT ANALYST NOTES:
// HIGH CONFIDENCE: writable-path payload + encoded content together.
// NOISE: legitimate installers commonly write Run keys pointing to
//   Program Files paths — these will NOT match HasWritablePath.
// PROMOTION TRIGGER: confirmed malicious Run key entry → Composite Sensor,
//   Substrate-First if the path alone is the anchor, Intent-First if an
//   encoded/obfuscated payload is required to distinguish from legitimate use.
```

---

### Example 2 — Scheduled Task "Run Once" Persistence (T1053.005)

**PEAK Type:** B — Baseline (establishing what "normal" task creation looks
like, then flagging deviation)
**TaHiTI Phase 3 Hypothesis:** *"I hypothesise that an attacker created a
one-time scheduled task for immediate execution because the task's start time
and creation time are nearly identical, which would be visible as a `/sc once`
or near-zero-delay task in DeviceProcessEvents schtasks invocations."*

```mermaid
flowchart LR
    A["Attacker wants execution\nwithout a persistent footprint"] --> B["schtasks /create /sc once\n/tn [random] /tr [payload]"]
    B --> C["Task fires almost\nimmediately after creation"]
    C --> D["Task often self-deletes\nor is removed manually after"]
    D --> E["Why this surface:\n'Run once' tasks don't need to\nsurvive reboot — used for a single\nexecution that blends into noise"]
```

```kql
// ============================================================================
// HUNT QUERY: Scheduled Task — Run-Once With Near-Zero Delay
// ============================================================================
// PEAK Type: B — Baseline | TaHiTI Phase: 5 — Execution
// MITRE: T1053.005
// ⚠ HUNT MODE — NOT FOR PRODUCTION DEPLOYMENT ⚠
// Schema Confidence: DeviceProcessEvents fields confirmed.
// Fields used: Timestamp, DeviceId, DeviceName, ProcessCommandLine,
// InitiatingProcessFileName, InitiatingProcessAccountName.
// ============================================================================

let lookback = 14d;

DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| extend
    IsRunOnce       = toint(ProcessCommandLine has_any ("/sc once", "/sc ONCE")),
    HasImmediateRun = toint(ProcessCommandLine matches regex @"(?i)/st\s+\d{2}:\d{2}"),
    HasWritablePath = toint(ProcessCommandLine matches regex
                        @"(?i)(\\temp\\|\\appdata\\|\\programdata\\|\\public\\)"),
    HasSuspiciousTR = toint(ProcessCommandLine has_any
                        ("powershell", "cmd.exe /c", "-enc", "wscript", "mshta"))
| where IsRunOnce == 1
| extend HuntSignals = strcat(
    iif(HasWritablePath == 1,  "[WRITABLE_PATH] ", ""),
    iif(HasSuspiciousTR == 1,  "[SUSPICIOUS_PAYLOAD] ", ""),
    iif(HasImmediateRun == 1,  "[IMMEDIATE_RUN] ", "")
)
| project
    Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, HuntSignals, DeviceId
| sort by Timestamp desc
| take 10000

// HUNT ANALYST NOTES:
// BASELINE FIRST: run this query unfiltered (remove "where IsRunOnce==1")
// over 30 days to establish what legitimate /sc once usage looks like in
// YOUR environment — some backup/deployment tools use this pattern.
// HIGH CONFIDENCE: writable-path payload + suspicious /tr content together.
// PROMOTION TRIGGER: if a clean baseline shows /sc once is genuinely rare
// outside IT automation, this becomes a strong Composite anchor
// (Intent-First — the /sc once + suspicious payload combination is the signal).
```

---

### Example 3 — rundll32.exe Multi-Vector Abuse Hunt (T1218.011 / T1003.001)

**PEAK Type:** E — Entity (intel-driven: known LOLBin abuse family)
**TaHiTI Phase 3 Hypothesis:** *"I hypothesise that rundll32.exe is being used
for credential access or proxy execution because the binary itself carries no
inherent risk, which would be visible as a dangerous export name (MiniDump,
LaunchINFSection, FileProtocolHandler) in the command line, in
DeviceProcessEvents."*

This is the same attack surface built into your live Composite — the hunt
version below is what you would have run *before* building that composite,
to validate the technique was actually present in your environment first.

```mermaid
flowchart TD
    A["Attacker has code execution"] --> B{"Choose rundll32 —\nsigned, allowlisted everywhere"}
    B --> C1["comsvcs.dll,MiniDump\n→ LSASS credential dump"]
    B --> C2["advpack.dll,LaunchINFSection\n→ INF-based execution"]
    B --> C3["url.dll,FileProtocolHandler\n→ remote payload fetch"]
    C1 & C2 & C3 --> D["Why this surface:\ndefenders trust the SIGNED BINARY,\nnot the export being called"]
```

```kql
// ============================================================================
// HUNT QUERY: rundll32.exe — Dangerous Export Sweep
// ============================================================================
// PEAK Type: E — Entity | TaHiTI Phase: 5 — Execution
// MITRE: T1218.011, T1003.001
// ⚠ HUNT MODE — NOT FOR PRODUCTION DEPLOYMENT ⚠
// Schema Confidence: DeviceProcessEvents fields confirmed.
// ============================================================================

let lookback = 30d;
let DangerousExports = dynamic([
    "minidump", "launchinfsection", "fileprotocolhandler",
    "shellexec_rundll", "runhtmlapplication", "control_rundll"
]);

DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "rundll32.exe"
| where isnotempty(ProcessCommandLine)
| extend CmdLower = tolower(ProcessCommandLine)
| where CmdLower has_any (DangerousExports)
    or CmdLower matches regex @"(?i)(\\users\\|\\temp\\|\\appdata\\)"
| extend
    HasMiniDump      = toint(CmdLower has "minidump" or CmdLower matches regex @"#24"),
    HasLaunchINF     = toint(CmdLower has "launchinfsection"),
    HasRemoteURL     = toint(CmdLower matches regex @"(?i)(https?|ftp)://"),
    HasWritablePath  = toint(CmdLower matches regex @"(?i)(\\users\\|\\temp\\|\\appdata\\)")
| extend HuntSignals = strcat(
    iif(HasMiniDump == 1,     "[MINIDUMP] ", ""),
    iif(HasLaunchINF == 1,    "[LAUNCHINF] ", ""),
    iif(HasRemoteURL == 1,    "[REMOTE_URL] ", ""),
    iif(HasWritablePath == 1, "[WRITABLE_PATH] ", "")
)
| project
    Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, HuntSignals, DeviceId
| sort by Timestamp desc
| take 10000

// HUNT ANALYST NOTES:
// HIGH CONFIDENCE: [MINIDUMP] tag — treat as credential theft until proven
// otherwise, per MTDF's "false negative worse than false positive" doctrine.
// NOISE: SCCM/Intune service contexts triggering Control_RunDLL — check
// InitiatingProcessFileName against known management tooling before discarding.
// PROMOTION TRIGGER: this is the exact hunt that should precede building
// the rundll32 Composite documented elsewhere in your Rule Library —
// confirms which sub-techniques are ACTUALLY present before committing
// scoring weights to each one.
```

---

### Example 4 — OAuth Consent Grant / Token Abuse Hunt (T1528 / T1621 / T1078.004)

**PEAK Type:** A — Anomaly (situational: following an MFA fatigue campaign
advisory) — this is the exact TaHiTI walkthrough scenario from the primary
source material, adapted to MTDF's Architecture 4 shape.

**TaHiTI Phase 3 Hypothesis:** *"I hypothesise that an MFA fatigue attack
succeeded because a user received an unusually high volume of MFA prompts in
a short window followed by a successful authentication, which would be visible
as a failure-then-success pattern within 10 minutes in SigninLogs, followed by
a new OAuth application consent grant in AuditLogs."*

```mermaid
flowchart LR
    A["Attacker has valid\nstolen credentials"] --> B["Repeated MFA push\nevery 30-60 seconds"]
    B --> C["User approves\nout of frustration"]
    C --> D["Attacker authenticates\nwith valid MFA token"]
    D --> E["Consents to malicious\nOAuth app for persistence"]
    E --> F["Why this surface:\nno malicious binary, no suspicious\nprocess — pure identity attack,\nexploits human fatigue not software"]
```

```kql
// ============================================================================
// HUNT QUERY: MFA Fatigue → OAuth Consent Grant Correlation
// ============================================================================
// PEAK Type: A — Anomaly | TaHiTI Phase: 5 — Execution
// MITRE: T1621 (MFA Request Generation), T1528 (Steal Application Access Token)
// ⚠ HUNT MODE — NOT FOR PRODUCTION DEPLOYMENT ⚠
// Schema Confidence: SigninLogs/AuditLogs fields confirmed against MTDF
// Schema Reference (Sentinel section).
// ============================================================================

let lookback = 14d;

// HUNT PHASE 1: HYPOTHESIS SURFACE — MFA failure burst per user
let MFABursts =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType in ("50074", "50076") or tostring(Status.errorCode) == "500121"
    | summarize
        FailCount = count(),
        FirstFail = min(TimeGenerated),
        LastFail  = max(TimeGenerated)
      by UserPrincipalName
    | where FailCount >= 5;

// HUNT PHASE 2: CONTEXT ENRICHMENT — success shortly after the burst
let SuccessAfterBurst =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0"
    | join kind=inner (MFABursts) on UserPrincipalName
    | where TimeGenerated > LastFail and TimeGenerated < LastFail + 1h
    | extend MinutesAfterBurst = datetime_diff("minute", TimeGenerated, LastFail);

// HUNT PHASE 3: SIGNAL TAGGING — correlate with new OAuth consent
let NewConsents =
    AuditLogs
    | where TimeGenerated > ago(lookback)
    | where OperationName has_any ("Consent to application", "Add app role assignment")
    | project ConsentTime = TimeGenerated, ConsentUser = tostring(InitiatedBy.user.userPrincipalName),
              TargetApp = tostring(TargetResources[0].displayName);

SuccessAfterBurst
| join kind=leftouter (NewConsents) on $left.UserPrincipalName == $right.ConsentUser
| extend
    HasConsentNearby = toint(isnotempty(ConsentTime) and
                          ConsentTime between (TimeGenerated .. TimeGenerated + 1h))
| extend HuntSignals = strcat(
    "[MFA_BURST_", tostring(FailCount), "] ",
    iif(MinutesAfterBurst < 10, "[RAPID_SUCCESS] ", ""),
    iif(HasConsentNearby == 1, "[OAUTH_CONSENT_NEARBY] ", "")
)
| project
    TimeGenerated, UserPrincipalName, FailCount, MinutesAfterBurst,
    TargetApp, HuntSignals
| sort by FailCount desc
| take 10000

// HUNT ANALYST NOTES:
// HIGH CONFIDENCE: [OAUTH_CONSENT_NEARBY] tag — this is the exact pattern
// from the TaHiTI primary source's worked example. Treat as confirmed
// account takeover, not just suspicious.
// PIVOT: once flagged, check TargetApp's publisher verification status and
// requested scopes — a newly-registered app with broad mail/files scope
// requesting consent minutes after an MFA burst is near-certain malicious.
// PROMOTION TRIGGER: per the TaHiTI walkthrough, this exact pattern should
// become a permanent Composite — "more than 3 MFA challenges in under 5
// minutes" was the threshold that worked in the source material's own
// post-hunt detection rule.
```

---

## Part 6 — Investigation Methodology: The Entity Key Model

Every advanced investigation pivots on shared identifiers across telemetry
surfaces — this is what turns isolated hunt findings into a full attack story.

```mermaid
flowchart TD
    subgraph Keys["Entity Keys"]
        DN["DeviceName"]
        AN["AccountName"]
        SHA["SHA256"]
        IP["RemoteIP"]
    end
    subgraph Pivots["What Each Key Unlocks"]
        P1["All activity on this host,\n±48h of the anchor event"]
        P2["All auth events for this identity,\nacross every host"]
        P3["Where else has this binary\nrun, in the last 30 days?"]
        P4["What else connected to\nthis IP — other victims?"]
    end
    DN --> P1
    AN --> P2
    SHA --> P3
    IP --> P4
```

---

## Part 7 — Summary: What This Guide Adds to MTDF

| Addition | Why It Matters |
|---|---|
| Corrected 7-phase TaHiTI numbering | Your doctrine's `T1-T6` labelling was missing a real phase — now fixed |
| Confirmed B/M PEAK split is accurate | Verified against primary source, not just internally consistent |
| Open-source intel sourcing answered directly | CISA/MITRE/CERT-EU are legitimate; live feed ingestion is a roadmap item, not built yet |
| Four worked KQL hunts | Registry persistence, scheduled task run-once, rundll32 multi-vector, OAuth/MFA fatigue — spanning Persistence, Execution, Credential Access, and Identity tactics |
| Entity key investigation model | Makes explicit what was implicit in MTDF's "stitch via entity keys" doctrine |
