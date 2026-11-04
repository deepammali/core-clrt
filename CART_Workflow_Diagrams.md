# CART — Workflow Diagrams (Mermaid)

Continuous Red Teaming Platform · Deepam Mali · DIAT, Pune

Scope: the 5 engines and 4 stores from the project presentation, expanded into per-engine internal flows and sub-diagrams. Two gaps from the deck are fixed here: (1) mission execution can loop back into recon and re-planning, so the flow is continuous rather than a single pass; (2) operator-configurable options (model backend, execution mode, autonomy tier, KB update mode) are shown as explicit decision points.

Paste any block into https://mermaid.live to view or export. Individual files are in `cart_diagrams/`.

---

## 1. System context (three tiers)

Interfaces drive Engines; Engines read and write Stores. Matches the High-Level Architectural Components in the deck (5 engines, 4 stores, 3 interfaces).

```mermaid
flowchart TB
  subgraph UI["Interfaces"]
    OP["Operator and admin dashboard"]
    MPD["Mission planning dashboard"]
    RPD["Reports dashboard"]
  end
  subgraph ENG["Engines"]
    TI["Threat intelligence"]
    RE["Recon and enumeration"]
    MPL["Mission planning"]
    MEX["Mission execution"]
    RPT["Reporting"]
  end
  subgraph ST["Stores"]
    SO[("OSINT and adversary TTPs")]
    SE[("Exploit repository")]
    SG[("Target organisation graph")]
    SV[("Vuln asset to CVE or CWE map")]
  end
  OP --> MPL
  MPD --> MPL
  TI --> SO
  TI --> MPL
  RE --> SG
  RE --> SV
  RE --> MPL
  MPL --> SG
  MPL --> SO
  MPL --> SV
  MPL --> MEX
  MEX --> SE
  MEX --> SG
  MEX --> RPT
  RPT --> RPD
```

---

## 2. Master mission workflow (closed loop)

Deck page 12 (left) made continuous: execution can loop back for more recon or a re-plan, and repeats until the objective is met. RoE plus human approval gate sits before execution.

```mermaid
flowchart TD
  START(("Start")) --> DASH["User dashboard: target and objective"]
  DASH --> RECON["Recon and enumeration"]
  TI["OSINT and threat intel"] --> MPL["Mission planning"]
  RECON --> MPL
  MPL --> GATE{"RoE and HITL approval"}
  GATE -->|approved| MEX["Mission execution"]
  GATE -->|revise| MPL
  MEX --> EVAL["Continuous monitoring and evaluation"]
  EVAL --> DEC{"objective met"}
  DEC -->|yes| RPT["Report generation and evaluation"]
  DEC -->|need more recon| RECON
  DEC -->|surface changed, re-plan| MPL
  DEC -->|continue| MEX
  RPT --> STOP(("Stop"))
```

---

## 3. Threat intelligence internal flow

Deck page 13 (right) expanded with an online vs air-gapped update-mode switch, TTP extraction, and provenance/trust scoring before publishing to the OSINT store.

```mermaid
flowchart TD
  subgraph TIF["Threat intelligence internal flow"]
    A["Source selection and data collection"] --> MODE{"KB update mode"}
    MODE -->|online| A2["Pull live feeds and OSINT"]
    MODE -->|air-gapped| A3["Import signed update package"]
    A2 --> B["Data processing and extraction"]
    A3 --> B
    B --> C["Analysis and enrichment"]
    C --> D["TTP extraction to MITRE ATTACK"]
    D --> E["Dedup, provenance, trust score"]
    E --> F["Intelligence publishing and memory update"]
  end
  F --> SO[("OSINT and adversary TTPs store")]
  F --> MPL["Mission planning"]
```

---

## 4. Recon and enumeration internal flow

New detail: layered discovery (L2 to L7), RoE-gated active scanning, assumption nodes for what cannot be confirmed, bitemporal writes to the org graph. Re-invoked whenever execution finds a new host or segment.

```mermaid
flowchart TD
  subgraph REF["Recon and enumeration internal flow"]
    IN["Recon request: initial or from execution"] --> PASV["Passive recon: OSINT, DNS, banners"]
    PASV --> ACT{"active scan allowed by RoE"}
    ACT -->|no| ASMN["Mark as assumption node"]
    ACT -->|yes| L2["L2 ARP and VLAN adjacency"]
    L2 --> L3["L3 topology and reachability"]
    L3 --> L4["L4 port and service discovery"]
    L4 --> L7["L7 service fingerprint and version"]
    L7 --> MAPV["Map assets to CVE or CWE"]
    MAPV --> WR["Write bitemporal facts to graph"]
    ASMN --> WR
  end
  WR --> SG[("Target organisation graph")]
  WR --> MPL["Mission planning"]
```

---

## 5. Mission planning internal flow

Deck page 12 (right) expanded neuro-symbolically: LLM backend is selectable; hypotheses are verified against the belief state; unknown preconditions spawn assumption nodes that call recon back.

```mermaid
flowchart TD
  subgraph MPF["Mission planning internal flow"]
    IN["Inputs: graph, TTPs, operator seeds"] --> LSEL{"LLM backend"}
    LSEL -->|local small| HG["Hypothesis generation"]
    LSEL -->|local large| HG
    LSEL -->|cloud| HG
    HG --> AGG["Attack graph generation"]
    AGG --> VER{"preconditions hold"}
    VER -->|unknown| ASM["Assumption node, request recon"]
    VER -->|unsound| REJ["Reject or dedup"]
    VER -->|yes| CHAIN["Attack chaining"]
    CHAIN --> CRIT["Success and failure criterion"]
  end
  ASM --> RECON["Recon and enumeration"]
  OSINT["OSINT and threat intel"] --> HG
  RECON2["Recon and enumeration"] --> AGG
  CRIT --> MEX["Mission execution"]
```

---

## 6. Hypothesis generation (sub-flow)

Zoom into the first planning box. Three hypothesis sources feed one pool: auto-derived, operator-seeded (threat actor profile), and operator-injected (manual). Pool is scored and ranked.

```mermaid
flowchart TD
  subgraph HGF["Hypothesis generation sub-flow"]
    S1["Auto: from TTPs and graph gaps"] --> POOL["Candidate hypothesis pool"]
    S2["Operator-seeded: threat actor profile"] --> POOL
    S3["Operator-injected: manual hypothesis"] --> POOL
    POOL --> SCORE["Score and prioritise: impact x plausibility"]
    SCORE --> OUT["Ranked hypotheses to attack graph generation"]
  end
```

---

## 7. Attack graph generation and verification (sub-flow)

Zoom into the second planning box. Each hypothesis is checked for preconditions and logical soundness; missing facts become recon tasks, verified steps extend the attack graph with coverage accounting.

```mermaid
flowchart TD
  subgraph AGF["Attack graph generation and verification sub-flow"]
    H["Incoming hypothesis"] --> PRE{"preconditions in belief state"}
    PRE -->|missing| ASM["Create assumption node"]
    ASM --> RQ["Queue recon task"]
    PRE -->|present| SND{"logically sound"}
    SND -->|no| DROP["Drop or mark redundant"]
    SND -->|yes| ADD["Add verified edge to attack graph"]
    ADD --> COV["Update coverage accounting"]
  end
  RQ --> RECON["Recon and enumeration"]
  COV --> CHAIN["Attack chaining"]
```

---

## 8. Mission execution internal flow

Deck page 13 (left) corrected. The loop is no longer a dead end: it can call recon for more information or send a re-plan to mission planning. Execution mode (emulated vs real) and the autonomy/HITL gate are explicit.

```mermaid
flowchart TD
  subgraph MEF["Mission execution internal flow"]
    IN["Approved plan fragment"] --> GATE{"RoE, HITL, autonomy tier"}
    GATE -->|deny| HALT["Halt or escalate to operator"]
    GATE -->|approve| MSEL{"execution mode"}
    MSEL -->|emulated| DEP["Attack deployment: emulated"]
    MSEL -->|real| DEP2["Attack deployment: real payload, isolated range"]
    DEP --> EXEC["Attack execution"]
    DEP2 --> EXEC
    EXEC --> C2["C2 and session handling"]
    C2 --> MON["Continuous monitoring and evaluation"]
    MON --> LOOP{"objective achieved"}
    LOOP -->|no, continue| GATE
    LOOP -->|need more recon| RECON["Recon and enumeration"]
    LOOP -->|precondition broke or new asset| MPL["Mission planning re-plan"]
    LOOP -->|yes| DONE["Exit to report generation"]
  end
  MON -->|logs| RPT["Reporting"]
```

---

## 9. Attack deployment (sub-flow)

Zoom into deployment. If no reliable payload exists it is built and verified in an isolated VM before use; the emulated vs real switch decides how the action actually runs. Reads and updates the exploit repository.

```mermaid
flowchart TD
  subgraph DPF["Attack deployment sub-flow"]
    STEP["Plan step to required capability"] --> SEL["Select exploit from repository"]
    SEL --> HAVE{"reliable payload available"}
    HAVE -->|no| BUILD["Build or adapt payload"]
    BUILD --> VMV["Verify in isolated VM"]
    VMV --> OKV{"verified"}
    OKV -->|no| SEL
    OKV -->|yes| CFG["Configure payload params"]
    HAVE -->|yes| CFG
    CFG --> MODE{"emulated or real"}
    MODE -->|emulated| EMU["Emulated action"]
    MODE -->|real| REAL["Real payload execution"]
  end
  SEL --> SE[("Exploit repository")]
```

---

## 10. Reporting and evaluation internal flow

Deck's Report Generation and Evaluation expanded: logs and the attack graph become metrics (coverage, time, detection signal) plus compliance checks, rolled into a posture summary and artefacts.

```mermaid
flowchart TD
  subgraph RPF["Reporting and evaluation internal flow"]
    IN["Logs, attack graph, outcomes"] --> MET["Compute metrics"]
    MET --> M1["Coverage and attack surface exercised"]
    MET --> M2["Campaign time and steps"]
    MET --> M3["Detection events: purple signal"]
    MET --> COMP["Compliance checks"]
    M1 --> POS["Security posture summary"]
    M2 --> POS
    M3 --> POS
    COMP --> POS
    POS --> ART["Reports, alerts, status"]
  end
  ART --> RPD["Reports dashboard"]
```

---

## 11. HITL and autonomy decision (cross-cutting)

How any state-changing action is routed. The deck lists HITL approvals as mandatory; this shows it as a gate combining autonomy tier and RoE. Irreversible or out-of-scope actions are denied or escalated.

```mermaid
flowchart TD
  ACT["Proposed action"] --> TIER{"autonomy tier"}
  TIER -->|T0 automated| RO{"passive recon or post-ex read?"}
  RO -->|yes| AUTO["Execute automatically"]
  RO -->|no| ROE{"within RoE envelope"}
  TIER -->|T1 assisted| ROE
  TIER -->|T2 bounded| ROE
  ROE -->|reversible and in-scope| ASK{"needs approval"}
  ROE -->|irreversible or out-of-scope| DENY["Deny or escalate"]
  ASK -->|no| AUTO
  ASK -->|yes| HITL["Operator approval HITL"]
  HITL -->|approve| AUTO
  HITL -->|reject| BACK["Return to planning"]
```

---

## 12. Configurability overview

The four operator switches and which engines each one affects. This is the 'nor is configurable' gap made explicit: model backend, execution mode, autonomy tier, and KB update mode.

```mermaid
flowchart LR
  subgraph CFG["Deployment configuration"]
    C1["LLM backend: local-small, local-large, cloud"]
    C2["Execution mode: emulated or real"]
    C3["Autonomy tier: T0, T1, T2"]
    C4["KB update: online or air-gapped"]
  end
  C1 --> MPL["Mission planning"]
  C1 --> TI["Threat intelligence"]
  C2 --> MEX["Mission execution"]
  C3 --> MEX
  C3 --> GATE["HITL and RoE gate"]
  C4 --> TI
```

---

## 13. Stores and data relationships

The four deck stores and how they reference each other. Graph assets key into the CVE/CWE map, which keys into the exploit repository. Every graph fact is bitemporal (valid_from plus observed_from).

```mermaid
flowchart TB
  SO[("OSINT and adversary TTPs")]
  SE[("Exploit repository")]
  SG[("Target organisation graph")]
  SV[("Vuln asset to CVE or CWE map")]
  SG -->|assets| SV
  SV -->|CVE match| SE
  SO -->|TTP context| SG
  NOTE["Every fact stamped valid_from and observed_from: bitemporal"]
  NOTE -. applies to .-> SG
```

---
