# Threat Hunting
### A Senior Analyst's Complete Reference — Detection, Investigation & Incident Response

**Author:** Ala Dabat | 2026  
**Framework:** [Minimum Truth Detection Framework](https://github.com/azdabat/Minimum-Truth-Detection-Framework-ADX-Validated-Composite-Rules)  
**License:** [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)

---

> *"Threat hunting is not the absence of alerts. It is the deliberate search for adversary behaviour that has not yet produced an alert — and the engineering of detections so that next time, it does."*

---

## Table of Contents

- [What Is Threat Hunting?](#what-is-threat-hunting)
- [The Hunting Frameworks](#the-hunting-frameworks)
- [The MTDF Hunting Doctrine](#the-mtdf-hunting-doctrine)
- [Threat Hunt Types](#threat-hunt-types)
- [The Hunt Lifecycle](#the-hunt-lifecycle)
- [Data Sources & Telemetry](#data-sources--telemetry)
- [Hypothesis Generation](#hypothesis-generation)
- [Advanced Threat Catalogue — 2026](#advanced-threat-catalogue--2026)
- [Investigation Methodology](#investigation-methodology)
- [Incident Response Integration](#incident-response-integration)
- [Repository Structure](#repository-structure)

---

## What Is Threat Hunting?

Threat hunting is the proactive, analyst-driven search for attacker activity that has bypassed automated detection. It is distinct from alert triage (reactive), detection engineering (proactive-automated), and penetration testing (adversarial simulation).

```mermaid
graph LR
    subgraph Reactive["Reactive Security Operations"]
        R1["Alert fires"]
        R2["Analyst investigates"]
        R3["Contain + remediate"]
        R1 --> R2 --> R3
    end

    subgraph Proactive["Proactive Threat Hunting"]
        P1["Analyst forms hypothesis\n'What if X is already in our environment?'"]
        P2["Query telemetry\nLook for evidence"]
        P3["Confirm or refute\nhypothesis"]
        P4["If confirmed: IR\nIf refuted: detection gap identified"]
        P5["Engineer detection\nso next occurrence alerts automatically"]
        P1 --> P2 --> P3 --> P4 --> P5
    end

    subgraph Value["The Value of Hunting"]
        V1["Finds intrusions that\nhave no alert"]
        V2["Establishes baseline\nfor what is normal"]
        V3["Produces new\ndetection rules"]
        V4["Reduces attacker\ndwell time"]
    end

    Proactive --> Value
```

### The Core Principle

Every threat hunt starts with a question that cannot be answered by existing alerts:

> *"Is there evidence that [specific adversary behaviour] has occurred in our environment that we have not yet detected?"*

The answer is either:
- **Yes** → incident response begins
- **No** → the hunt produced a detection gap analysis — which techniques would have evaded our current coverage?

Both outcomes are valuable. A hunt that finds nothing is not a failed hunt — it is evidence of either clean environment or detection gaps. The distinction is determined by the quality of the hypothesis and the completeness of the telemetry coverage.

---

## The Hunting Frameworks

### PEAK — The Primary Hunt Execution Framework

```mermaid
graph LR
    subgraph PEAK["PEAK Framework"]
        P["PREPARE\n• Define hypothesis\n• Identify data sources\n• Scope the hunt\n• Define success criteria"]
        E["EXECUTE\n• Run hunt queries\n• Analyse results\n• Pivot on findings\n• Document observations"]
        A["ACT\n• Escalate to IR if confirmed\n• Engineer detection if missed\n• Update threat intel\n• Feed back to next hunt"]
        P --> E --> A --> P
    end
```

**PREPARE phase deliverables:**
- Written hypothesis statement
- Data sources required (MDE tables, Sentinel tables, network logs)
- Time window and scope (which business units, which device types)
- Success criteria (what does "found" look like vs "not found")
- Estimated time

**EXECUTE phase deliverables:**
- Hunt queries with results
- Pivots taken and why
- Anomalies observed (including benign findings that need baselining)
- IOBs (Indicators of Behaviour) identified

**ACT phase deliverables:**
- IR referral if confirmed
- Detection rule engineered if missed
- Hunt report for documentation
- Next hypothesis derived from findings

### TAHITI — Threat-Intelligence Driven Hunting

```mermaid
graph TD
    T["TARGET\nIdentify specific threat actor\nor technique family to hunt"]
    A["ATTACK PATTERNS\nMap actor TTPs from CTI\nto MITRE ATT&CK techniques"]
    H["HUNT\nExecute targeted queries\nagainst mapped techniques"]
    I["INVESTIGATE\nAnalyse findings\nCorrelate across surfaces"]
    T2["TEST\nValidate detection coverage\nagainst known TTPs"]
    I2["ITERATE\nRefine hypothesis\nExpand or narrow scope"]

    T --> A --> H --> I --> T2 --> I2 --> T
```

### MTDF Alignment to PEAK and TAHITI

| PEAK Phase | MTDF Equivalent | TAHITI Phase | MTDF Equivalent |
|-----------|----------------|-------------|----------------|
| Prepare | Minimum truth identification | Target | Threat actor TTP mapping |
| Execute | Hunt query (low threshold composite) | Attack Patterns | Cousin technique ecosystem |
| Act | Detection rule engineering | Hunt | 4-phase composite rule |
| → | Cousin rule generation | Investigate | Atomic primitive collector |
| → | ADX validation + receipt | Test | ADX-Docker validation |
| → | GitHub commit | Iterate | Threshold calibration |

---

## The MTDF Hunting Doctrine

### Minimum Truth Applied to Hunting

The Minimum Truth doctrine — originally designed for continuous detection rules — applies equally to threat hunting. Every hunt hypothesis has a minimum truth: the irreducible behavioural condition that must be true if the suspected activity occurred.

```mermaid
graph TD
    Q{"Does the suspected\ntechnique carry visible\nintent in telemetry?"}
    Q -->|"No — WMI fileless,\nBYOVD, injection"| SF["SUBSTRATE-FIRST HUNT\nSearch for the physical\nexecution substrate\nExample: scrcons.exe loading DLL\nDriverLoadEvent from writable path"]
    Q -->|"Yes — PowerShell,\nLOLBins, OAuth"| IF["INTENT-FIRST HUNT\nSearch for the explicit\nmalicious primitive\nExample: -Enc + IEX\nRC4 ticket burst"]
    SF --> R["REINFORCEMENT\nAdd context signals\nto reduce false positives"]
    IF --> R
    R --> C["CONFIRM or REFUTE\nHypothesis"]
    C -->|"Confirmed"| IR["Incident Response"]
    C -->|"Refuted"| DE["Detection Engineering\nClose the gap"]
```

### Hunt Threshold vs Detection Threshold

A fundamental distinction that determines hunt query design:

| Parameter | Detection Rule | Hunt Query |
|-----------|---------------|-----------|
| Purpose | Continuous alert generation | One-time hypothesis testing |
| Threshold | High (RiskScore ≥ 75) | Lower (RiskScore ≥ 45) |
| False positives | Minimised | Acceptable — analyst reviews all |
| Time window | Rolling (24h, 7d) | Specific to hunt period |
| Output | Alert for every match | Dataset for analyst analysis |
| Action | Automated SOC ticket | Analyst investigation |

---

## Threat Hunt Types

### Type 1 — Intelligence-Led Hunt

Triggered by external threat intelligence: a new CVE, a published campaign report, a government advisory, or a vendor threat brief.

**Process:**
1. Receive CTI (e.g. CISA advisory on SilverFox BYOVD)
2. Map TTPs to MITRE ATT&CK techniques
3. Identify which techniques the environment has telemetry for
4. Build hypotheses for each technique
5. Execute hunts in priority order (highest-impact techniques first)
6. Engineer detections for any gaps found

### Type 2 — Baseline Anomaly Hunt

Driven by deviation from established baseline behaviour. Requires a documented baseline.

**Process:**
1. Establish what "normal" looks like for a process, account, or system
2. Query for deviations from that baseline
3. Investigate deviations that cannot be explained by known operational changes
4. Update baseline when legitimate changes occur

**Example hypotheses:**
- *"Are there PowerShell processes running on hosts where PowerShell has never run before?"*
- *"Are there accounts authenticating from new geographic locations?"*
- *"Are there new scheduled tasks created in the last 30 days that are not in our approved list?"*

### Type 3 — Post-Incident Retroactive Hunt

Triggered after a confirmed incident. Looks for the same techniques across the wider estate.

**Process:**
1. Extract IOBs (Indicators of Behaviour) from confirmed incident
2. Scope retroactive hunt to 30–90 days
3. Hunt for same behaviour on all other hosts
4. Determines whether incident was isolated or widespread

### Type 4 — Coverage Gap Hunt

Designed to identify what the current detection estate would miss. No specific threat in mind — testing resilience.

**Process:**
1. Select a MITRE ATT&CK technique family
2. Simulate the technique in a lab environment
3. Check whether existing detections fire
4. If they do not: build the detection
5. Document coverage gaps in the MTDF roadmap

---

## The Hunt Lifecycle

```mermaid
flowchart TD
    A["HYPOTHESIS\nStatement of suspected behaviour\n'We believe X may have occurred\nbecause of Y intelligence/baseline deviation'"] --> B

    B["DATA SOURCE MAPPING\nWhich tables contain evidence?\nWhat fields are relevant?\nWhat time window?"] --> C

    C["QUERY DESIGN\nWrite initial hunt queries\nStart broad — narrow later\nDocument every query run"] --> D

    D["INITIAL ANALYSIS\nReview results\nIdentify anomalies\nSeparate noise from signal"] --> E

    E{Anomalies found?}
    E -->|Yes| F["PIVOT INVESTIGATION\nFollow the anomaly\nCorrelate across surfaces\nBuild timeline"]
    E -->|No| G["DOCUMENT NULL RESULT\nRecord what was searched\nRecord what was not found\nIdentify coverage gaps"]

    F --> H{Confirmed?}
    H -->|Yes — evidence of attack| I["ESCALATE TO IR\nDocument IOBs\nInitiate response"]
    H -->|No — benign explanation| J["BASELINE UPDATE\nDocument legitimate behaviour\nUpdate allowlists if needed"]

    G --> K["DETECTION ENGINEERING\nIf gap found: engineer rule\nIf covered: validate coverage\nUpdate MTDF roadmap"]

    I --> L["HUNT REPORT\nHypothesis + findings\nTimeline + IOBs\nDetection improvements"]
    J --> L
    K --> L
    L --> M["NEXT HYPOTHESIS\nDerived from findings\nFeed into next sprint"]
    M --> A
```

---

## Data Sources & Telemetry

### MDE Advanced Hunting — Priority Tables for Threat Hunting

| Table | Primary Use | Key Hunting Fields |
|-------|-------------|-------------------|
| `DeviceProcessEvents` | Process execution, LOLBin chains, injection markers | FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSignerType |
| `DeviceNetworkEvents` | C2 beaconing, data exfil, lateral movement | RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName |
| `DeviceFileEvents` | Malware staging, credential files, persistence artefacts | FileName, FolderPath, ActionType, InitiatingProcessFileName |
| `DeviceRegistryEvents` | Persistence (Run keys, Services, TaskCache) | RegistryKey, RegistryValueData, InitiatingProcessFileName |
| `DeviceImageLoadEvents` | DLL sideloading, BYOVD precursor, WMI fileless | FileName, Signer, InitiatingProcessFileName, IsSigned |
| `DeviceEvents` | AMSI bypass, DriverLoadEvent, LSASS access | ActionType, AdditionalFields, FileName |
| `DeviceLogonEvents` | Lateral movement, credential use, anomalous auth | LogonType, RemoteIP, AccountName, IsLocalAdmin |
| `IdentityLogonEvents` | Kerberoasting, pass-the-hash, identity anomalies | Protocol, AccountName, FailureReason, LogonType |
| `IdentityQueryEvents` | LDAP enumeration, BloodHound-style recon | QueryType, QueryTarget, AccountName |
| `CloudAppEvents` | Cloud lateral movement, SaaS abuse | ActionType, AccountUpn, IPAddress, Application |
| `AlertEvidence` | Correlate with existing detections | AlertId, EntityType, SHA256, RemoteIP |

### Sentinel — Priority Tables

| Table | Primary Use | Key Fields |
|-------|-------------|-----------|
| `SecurityEvent` | Windows auth, process creation (4688), service install (7045) | EventID, Account, ProcessName, CommandLine |
| `WindowsEvent` (Sysmon) | Rich process/network/file/registry telemetry | EventID, EventData (parse_xml) |
| `AuditLogs` | Entra ID changes, consent grants, app assignments | OperationName, InitiatedBy, TargetResources |
| `SigninLogs` | Authentication anomalies, MFA fatigue, impossible travel | UserPrincipalName, RiskDetail, IPAddress, Location |
| `IdentityInfo` | Account context enrichment | AccountUpn, Department, JobTitle, IsAdmin |
| `CommonSecurityLog` | Network/proxy/firewall traffic | SourceIP, DestinationIP, RequestURL, DeviceVendor |

### Telemetry Gaps — What EDR Cannot See

Understanding what is NOT in your telemetry is as important as knowing what is. These are the most common structural blind spots:

| Blind Spot | Reason | Compensating Control |
|-----------|--------|---------------------|
| Kernel-level activity after BYOVD | EDR minifilter removed | ETW kernel provider, Sysmon (if not also killed) |
| Direct syscall execution | Bypasses usermode hooks | Memory scanning, ETW |
| Encrypted C2 content | TLS termination not at endpoint | Proxy inspection, network metadata |
| Blockchain C2 channel | No suspicious domain | Process + frequency analysis |
| WMI fileless payload content | DLL load only, no cmdline | Registry EventConsumer query |
| In-memory process activity | No disk artefact | AMSI events, ETW, memory acquisition |
| Pre-sensor activity | Before EDR deployed | Log retention check, cloud audit logs |

---

## Hypothesis Generation

### From Threat Intelligence

```mermaid
graph TD
    CTI["Threat Intelligence Input\n• CISA advisories\n• Vendor threat reports\n• ISAC feeds\n• Dark web intelligence\n• Incident sharing"] --> TTP

    TTP["TTP Extraction\nMap to MITRE ATT&CK\nIdentify specific techniques\nfor the threat actor"] --> ENV

    ENV["Environment Mapping\n• Do we have telemetry for this technique?\n• What does normal look like?\n• What would malicious look like?"] --> HYP

    HYP["Hypothesis Formation\n'If [threat actor] targeted us using\n[technique], we would expect to see\n[observable] in [data source]\nduring [time window]'"]
```

### Hypothesis Template

Every hunt hypothesis should be written in this format before any queries are run:

```
HUNT ID:        HUNT-2026-001
DATE:           2026-01-01
ANALYST:        Ala Dabat
TRIGGER:        [Intelligence source / baseline deviation / coverage gap]

HYPOTHESIS:
If [specific adversary / technique] is present in our environment,
we expect to see [specific observable behaviour] in [specific data source]
during [time window], because [rationale].

NULL HYPOTHESIS:
If no evidence is found, this indicates either:
(a) The technique has not been used against us, OR
(b) Our telemetry does not cover this technique (detection gap)

DATA SOURCES:   [List tables and log sources]
TIME WINDOW:    [Start → End]
SCOPE:          [Business units, device types, accounts]
SUCCESS CRITERIA: [What does a positive finding look like?]
PRIORITY:       [CRITICAL / HIGH / MEDIUM / LOW]
```

### Hypothesis Examples by Threat Type

| Threat | Hypothesis | Key Data Source |
|--------|-----------|----------------|
| BYOVD staging | Signed driver dropped to temp path in last 30 days | DeviceFileEvents |
| Kerberoasting | RC4 TGS volume spike from user account | IdentityLogonEvents |
| C2 beaconing | Regular outbound HTTPS to first-seen domain by non-browser | DeviceNetworkEvents |
| Credential dumping | Non-AV process opened LSASS with read rights | DeviceEvents |
| Persistence | New scheduled task or run key created by non-admin process | DeviceRegistryEvents |
| Lateral movement | Network logon type 3 from workstation to workstation | DeviceLogonEvents |
| Data staging | Large archive created in temp by user process | DeviceFileEvents |
| Supply chain | Build agent spawning shells or accessing credential files | DeviceProcessEvents |

---

## Advanced Threat Catalogue — 2026

### Threat 1 — BYOVD: SilverFox / ValleyRAT

**Why it evades EDR:** Kernel-level execution kills the EDR from a layer it cannot defend. After Stage 6, the attacker operates in a detection vacuum.

**Minimum truth anchor:** `DriverLoadEvent` from a user-writable path, preceded by the sideload → stage → service registration chain.

**Hunt priority:** CRITICAL. If this fires, assume EDR is blind.

**Full R&D documentation:** [Advanced_Threat_Hunting_RD.md](./Advanced_Threat_Hunting_RD.md)

---

### Threat 2 — Blockchain C2: EtherRAT

**Why it evades EDR:** The C2 channel uses public blockchain infrastructure. Every IP and domain involved is legitimate. No suspicious network IOC exists.

**Minimum truth anchor:** A non-crypto process polling Ethereum RPC endpoints at regular intervals consistent with a beacon pattern.

**Hunt priority:** HIGH. Long dwell time expected — retroactive hunting essential.

**Full R&D documentation:** [Advanced_Threat_Hunting_RD.md](./Advanced_Threat_Hunting_RD.md)

---

### Threat 3 — AI-Generated Polymorphic Malware

**Why it evades EDR:** Each payload variant has a unique hash and structure. Signature-based controls have no applicable signature. Byte-flip variants preserve valid driver signatures.

**Minimum truth anchor:** Behavioural sequence — what the attack must do regardless of the payload's appearance.

**Hunt priority:** HIGH. Requires behavioural composite rules, not IOC-based detection.

**Full R&D documentation:** [AI_Accelerated_Attack_Surface_Evolution.md](https://github.com/azdabat/-AI-LLM-Autonomous-Systems/blob/main/AI-Accelerated%20Attack%20Surface%20Evolution.md)

---

### Threat 4 — MFA Fatigue / Push Bombing (2026 Critical)

**Why it evades detection:** Attacker uses valid stolen credentials and repeatedly pushes MFA prompts until the user approves out of frustration. No malicious binary. No suspicious process. Pure identity attack.

**Attack flow:**

```mermaid
graph LR
    A["Credential theft\nPhishing / breach data"] --> B
    B["Repeated MFA push\nEvery 30-60 seconds"] --> C
    C["User approves\nout of frustration"] --> D
    D["Attacker authenticates\nwith valid MFA token"] --> E
    E["Cloud access\nEmail / SharePoint / VPN"]
```

**Minimum truth anchor:** Unusual volume of MFA requests from a single account in a short window, followed by a successful authentication from an anomalous IP or location.

**Hunt queries:**

```kql
// MFA Fatigue Hunt 1: Push bombing pattern detection

SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "50074"  // MFA required but failed
      or ResultType == "50076"
      or Status.errorCode == 500121  // Auth interrupted
| summarize
    FailedMFA     = count(),
    UniqueIPs     = dcount(IPAddress),
    Locations     = make_set(tostring(Location.countryOrRegion), 10),
    FirstAttempt  = min(TimeGenerated),
    LastAttempt   = max(TimeGenerated)
  by UserPrincipalName
| extend WindowMinutes = datetime_diff("minute", LastAttempt, FirstAttempt)
| extend AttemptsPerMin = iff(WindowMinutes > 0,
    todouble(FailedMFA) / WindowMinutes, todouble(FailedMFA))
| where FailedMFA > 5
| extend Severity = case(
    FailedMFA > 20 or AttemptsPerMin > 3, "CRITICAL",
    FailedMFA > 10, "HIGH",
    "MEDIUM"
)
| order by FailedMFA desc
```

```kql
// MFA Fatigue Hunt 2: Success after repeated failures (the critical pattern)
// A success after 5+ failures = likely MFA fatigue attack succeeded

let MFAFailures =
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType in ("50074", "50076") or
            Status.errorCode == 500121
    | summarize FailCount = count(), LastFail = max(TimeGenerated)
      by UserPrincipalName;

SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"  // Successful sign-in
| join kind=inner (MFAFailures) on UserPrincipalName
| where FailCount >= 5
| where TimeGenerated > LastFail
| extend MinutesSinceFail = datetime_diff("minute", TimeGenerated, LastFail)
| where MinutesSinceFail < 60
| project
    TimeGenerated, UserPrincipalName, IPAddress,
    Location = tostring(Location.countryOrRegion),
    AppDisplayName, FailCount, MinutesSinceFail,
    HunterDirective = strcat(
        "CRITICAL: MFA fatigue pattern — ",
        tostring(FailCount), " failed MFA attempts followed by success ",
        tostring(MinutesSinceFail), " minutes later. ",
        "Verify with user immediately. If not user-initiated: revoke session tokens."
    )
| order by FailCount desc
```

**Cousin techniques:** Adversary-in-the-Middle (T1557), Token theft (T1528), Pass-the-cookie, Cloud lateral movement.

---

### Threat 5 — LSASS Protection Bypass via PPL Downgrade (2026)

**Why it evades detection:** Windows Protected Process Light (PPL) prevents standard LSASS dumps. Modern attackers bypass PPL using BYOVD or by patching the PPL flag in kernel memory — achieving LSASS access that many detection rules miss because they assume PPL protection is intact.

**Attack flow:**

```mermaid
graph TD
    A["Standard LSASS dump blocked\nPPL protection active"] --> B
    B{Bypass method?}
    B -->|"BYOVD route"| C["Load vulnerable driver\nPatch PPL flag from kernel\nT1068"]
    B -->|"Mimidrv route"| D["Load mimidrv.sys\nRemove PPL protection\nT1562.001"]
    B -->|"Direct syscall route"| E["Bypass PPL via\nNtOpenProcess direct syscall\nT1055.001"]
    C --> F["LSASS now accessible\nStandard dump succeeds\nT1003.001"]
    D --> F
    E --> F
    F --> G["Credentials extracted\nAll logged-on users\nAll cached credentials"]
```

**Hunt queries:**

```kql
// PPL Bypass Hunt 1: mimidrv.sys or PPL-related driver loads

DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DriverLoadEvent"
| where FileName =~ "mimidrv.sys"
      or SHA256 in (
        // Known mimidrv hashes — supplement with current TI
        "d0e93e75aacbe55b1a75b9c879b1f5a78d2cebe8"
      )
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256
```

```kql
// PPL Bypass Hunt 2: LSASS access after kernel driver load
// Sequence: DriverLoadEvent → LSASS handle → dump

let DriverLoads =
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "DriverLoadEvent"
    | project DeviceId, DriverTime = Timestamp, DriverFile = FileName;

let LsassAccess =
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("OpenProcessApiCall", "AccessProcessHandle")
    | where FileName =~ "lsass.exe"
    | where InitiatingProcessFileName !in~ (
        "MsMpEng.exe", "SenseIR.exe", "csrss.exe", "wininit.exe"
    )
    | project DeviceId, AccessTime = Timestamp,
              AccessorProcess = InitiatingProcessFileName,
              AccessorHash    = InitiatingProcessSHA256;

DriverLoads
| join kind=inner (LsassAccess) on DeviceId
| where AccessTime between (DriverTime .. DriverTime + 15m)
| project DriverTime, AccessTime, DeviceId,
          DriverFile, AccessorProcess, AccessorHash,
          HunterDirective = "CRITICAL: Kernel driver load followed by LSASS access — PPL bypass suspected. Acquire memory immediately."
| order by DriverTime desc
```

---

### Threat 6 — DNS-over-HTTPS C2 Tunnelling

**Why it evades detection:** DNS tunnelling via traditional DNS is detectable through DNS query volume and length anomalies. DNS-over-HTTPS (DoH) encrypts DNS traffic inside HTTPS — indistinguishable from normal web browsing at the network layer.

**Minimum truth anchor:** A non-browser process making high-frequency HTTPS requests to known DoH providers (1.1.1.1, 8.8.8.8, dns.google, cloudflare-dns.com) with a pattern inconsistent with normal DNS resolution.

```kql
// DoH C2 Hunt: Non-browser processes using DoH providers

let DoHProviders = dynamic([
    "dns.google", "cloudflare-dns.com", "doh.opendns.com",
    "doh.cleanbrowsing.org", "dns.nextdns.io", "1.1.1.1", "8.8.8.8"
]);

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (DoHProviders)
      or RemoteIP in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222")
| where RemotePort == 443
// Exclude browsers and known DNS tools
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "iexplore.exe", "svchost.exe"
)
| summarize
    RequestCount = count(),
    FirstSeen    = min(Timestamp),
    LastSeen     = max(Timestamp),
    UniqueURLs   = dcount(RemoteUrl)
  by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256
| extend DwellMins   = datetime_diff("minute", LastSeen, FirstSeen)
| extend ReqPerMin   = iff(DwellMins > 0, todouble(RequestCount)/DwellMins, todouble(RequestCount))
| where RequestCount > 20
| order by RequestCount desc
```

---

## Investigation Methodology

### The Senior Analyst Investigation Process

```mermaid
flowchart TD
    A["INITIAL SIGNAL\nAlert or hunt finding"] --> B

    B["STEP 1 — VERIFY\nIs this a true positive?\nCan it be explained by legitimate activity?\nIs the data source reliable?"] --> C

    C["STEP 2 — SCOPE\nWhat is the blast radius?\nHow many hosts/accounts affected?\nWhat is the estimated dwell time?"] --> D

    D["STEP 3 — TIMELINE\nWhen did this start?\nWhat happened before the alert?\nWhat has happened since?"] --> E

    E["STEP 4 — TECHNIQUE MAPPING\nWhat MITRE technique is this?\nWhat are the cousin techniques?\nHas anything adjacent fired?"] --> F

    F["STEP 5 — PIVOT\nCorrelate across all telemetry surfaces\nFollow entity keys (DeviceName, AccountName, SHA256)\nExpand scope if lateral movement detected"] --> G

    G["STEP 6 — CONTAIN\nDecide containment approach\nIsolate vs monitor (dwell time consideration)\nCoordinate with IR lead"] --> H

    H["STEP 7 — EVIDENCE\nPreserve all evidence before remediation\nMemory dump if kernel tamper suspected\nExport telemetry with timestamps"] --> I

    I["STEP 8 — ERADICATE\nRemove persistence mechanisms\nRotate exposed credentials\nRestore security products\nPatch exploited vectors"] --> J

    J["STEP 9 — DETECT\nEngineer detection for this technique\nValidate in ADX\nDeploy to production\nUpdate coverage matrix"]
```

### The Entity Key Investigation Model

All advanced investigation pivots on entity keys — the common identifiers that connect events across different telemetry surfaces.

```mermaid
graph TD
    subgraph Keys["Primary Entity Keys"]
        DN["DeviceName\nConnects all events\nto one host"]
        AN["AccountName\nConnects all events\nto one identity"]
        SHA["SHA256\nConnects binary\nacross hosts + time"]
        IP["RemoteIP\nConnects C2\ninfrastructure"]
        PID["ProcessId\nConnects events\nwithin one session"]
    end

    subgraph Pivots["Investigation Pivots"]
        P1["DeviceName →\nAll activity on this host\n±48h of anchor event"]
        P2["AccountName →\nAll auth events for this identity\nAcross all hosts"]
        P3["SHA256 →\nWhere else has this binary run?\nIn last 30 days"]
        P4["RemoteIP →\nWhat else connected to this IP?\nAny other hosts?"]
        P5["ProcessId →\nWhat did this specific\nprocess instance do?"]
    end

    DN --> P1
    AN --> P2
    SHA --> P3
    IP --> P4
    PID --> P5
```

### Attacks Hidden in Legitimate System Files

One of the most challenging investigation scenarios is when malicious payloads are hidden inside or executed through legitimate system components. Key techniques and investigation approaches:

| Technique | How It Hides | Detection Surface | Hunt Approach |
|-----------|-------------|------------------|--------------|
| DLL Sideloading | Malicious DLL same name as legitimate, loaded first | DeviceImageLoadEvents — signer mismatch | Check Signer ≠ InitiatingProcessSigner |
| Process Hollowing | Legitimate process memory replaced with malicious code | DeviceEvents — memory anomalies | NtUnmapViewOfSection + WriteProcessMemory sequence |
| Atom Bombing | Inject via Windows Atom Tables — no API hooks | ETW kernel events | Rare — look for GlobalAddAtom + NtQueueApcThread |
| Heaven's Gate | 32-bit process switches to 64-bit to bypass hooks | Memory forensics | Unusual WoW64 transitions |
| Reflective DLL | DLL loaded from memory, never written to disk | AMSI events, ETW | ProcessCommandLine has Reflection.Assembly |
| COM Hijacking | Malicious COM server registered in HKCU | DeviceRegistryEvents — CLSID in HKCU | HKCU\Software\Classes\CLSID writes |
| PEB Stomping | Fake process name in Process Environment Block | Memory forensics | PEB.ImagePathName ≠ actual executable path |

---

## Incident Response Integration

### When a Hunt Becomes an Incident

```mermaid
flowchart TD
    A["Hunt Query Returns Results"] --> B{Confidence Level?}

    B -->|"High confidence\nClear attack evidence"| C["INCIDENT DECLARED\nAssign IR ticket\nEscalate to IR lead\nBegin containment timeline"]

    B -->|"Medium confidence\nAnomaly, unclear intent"| D["INVESTIGATION PHASE\nAdditional pivots\nSeek corroborating evidence\nTime-box to 2 hours"]

    B -->|"Low confidence\nMay be legitimate"| E["BASELINE REVIEW\nIs this new normal?\nDocument and monitor\nAdd to baseline"]

    C --> F["IR PHASE 0 — IMMEDIATE\nIs EDR operational?\nIsolate if BYOVD suspected\nNotify stakeholders"]

    D --> G{Corroborated?}
    G -->|Yes| C
    G -->|No| E

    F --> H["IR PHASE 1 — SCOPE\nBlast radius assessment\nTimeline construction\nCredential exposure check"]

    H --> I["IR PHASE 2 — CONTAIN\nIsolate affected hosts\nRevoke compromised credentials\nBlock C2 infrastructure"]

    I --> J["IR PHASE 3 — ERADICATE\nRemove persistence\nPatch vulnerabilities\nRestore security products"]

    J --> K["IR PHASE 4 — RECOVER\nMonitor for reinfection\nUpdate detections\nPost-incident review"]
```

### The Detection Improvement Loop

Every incident must produce at least one detection improvement:

```mermaid
graph LR
    INC["Incident\nConfirmed"] --> IOB
    IOB["Extract IOBs\nIndicators of Behaviour\n(not IOCs — behaviour based)"] --> GAP
    GAP["Identify Detection Gap\nWhy didn't this alert?"] --> RULE
    RULE["Engineer Detection Rule\nMTDF 4-phase composite\nADX validation"] --> DEPLOY
    DEPLOY["Deploy to Production\nMDE Custom Detection\nor Sentinel Analytics Rule"] --> MONITOR
    MONITOR["Monitor for\nFalse Positive Rate"] --> TUNE
    TUNE["Tune Thresholds\nUpdate Cousin Rules\nUpdate MTDF Matrix"] --> INC
```

---

## Repository Structure

```
Threat-Hunting/
│
├── README.md                              ← This file — comprehensive reference guide
│
├── Advanced_Threat_Hunting_RD.md          ← Deep-dive R&D: BYOVD, EtherRAT, Kerberoasting,
│                                             LOLBin fileless, supply chain + full IR methodology
│
├── hunt-queries/
│   ├── byovd/
│   │   ├── silverfox_tier1_atomic.kql
│   │   ├── silverfox_tier2_chain.kql
│   │   └── silverfox_tier3_fullchain.kql
│   ├── c2/
│   │   ├── etherrat_blockchain_c2.kql
│   │   └── doh_tunnelling.kql
│   ├── identity/
│   │   ├── kerberoasting.kql
│   │   ├── asrep_roasting.kql
│   │   └── mfa_fatigue.kql
│   ├── execution/
│   │   ├── lolbin_chains.kql
│   │   ├── fileless_injection.kql
│   │   └── wmi_fileless.kql
│   └── ir/
│       ├── master_timeline.kql
│       └── blast_radius.kql
│
├── playbooks/
│   ├── BYOVD_IR_Playbook.md
│   ├── Kerberoasting_IR_Playbook.md
│   └── Fileless_IR_Playbook.md
│
└── methodology/
    ├── Hunt_Hypothesis_Templates.md
    └── Blast_Radius_Assessment_Guide.md
```

---

## Framework Alignment

This repository aligns with:

| Framework | Alignment |
|-----------|-----------|
| **MITRE ATT&CK** | All hunt queries map to specific technique IDs |
| **PEAK** | Hunt lifecycle follows Prepare → Execute → Act |
| **TAHITI** | Intelligence-led hunts follow Target → Attack → Hunt → Investigate → Test → Iterate |
| **NIST CSF** | Detect (DE.AE, DE.CM) and Respond (RS.AN, RS.MI) functions |
| **MTDF** | All composites follow Minimum Truth → Reinforcement → Scoring → Hunter Directive |

---

*Author: Ala Dabat | [github.com/azdabat](https://github.com/azdabat)*  
*Licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)*  
*Part of the [Minimum Truth Detection Framework](https://github.com/azdabat/Minimum-Truth-Detection-Framework-ADX-Validated-Composite-Rules) ecosystem*
