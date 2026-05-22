# 📊 MARL Pentest Agent - Visual Architecture

## 🏗️ Kiến Trúc Tổng Thể Hệ Thống

```mermaid
graph TB
    USER["👤 USER<br/>Input Target"]
    
    subgraph "🕷️ RECON PHASE"
        CRAWL["CrawlAgent<br/>Crawl Website"]
        RECON["📄 recon.md<br/>enriched"]
        CRAWL --> RECON
    end
    
    subgraph "🔍 DETECTION PHASE"
        VH["VulnHunterAgent<br/>Phát hiện Lỗ"]
        BUGS["📋 risk-bug.json"]
        VH --> BUGS
    end
    
    subgraph "🎭 ORCHESTRATION LAYER"
        MGR["👨‍💼 ManageAgent<br/>Điều Phối"]
        POLICY["⚖️ PolicyAgent<br/>Kiểm Luật"]
        MGR -.-> POLICY
    end
    
    subgraph "🎯 DEBATE LAYER"
        RED["🔴 RedTeamAgent<br/>Lập Chiến Lược"]
        BLUE["🔵 BlueTeamAgent<br/>Phản Biện"]
        RED --> BLUE
    end
    
    subgraph "⚙️ EXECUTION LAYER"
        EXEC["⚡ ExecAgent<br/>Thực Thi + Tự Verify"]
        SCRIPT["📝 bug-*.py"]
        RESULT["📊 result.json"]
        EXEC --> SCRIPT
        EXEC --> RESULT
    end
    
    subgraph "📄 REPORT PHASE"
        REPORT["📋 report_final_vi.md"]
    end
    
    USER --> CRAWL
    RECON --> VH
    BUGS --> MGR
    MGR --> RED
    RED --> BLUE
    BLUE -->|APPROVED| EXEC
    BLUE -->|REJECTED| RED
    SCRIPT --> MGR
    RESULT --> MGR
    MGR --> REPORT
    
    style USER fill:#FFE6CC
    style CRAWL fill:#87CEEB
    style VH fill:#FFD700
    style MGR fill:#FFD700,stroke:#333,stroke-width:3px
    style RED fill:#FFB6C6
    style BLUE fill:#B6D6FF
    style EXEC fill:#C6FFC6
    style REPORT fill:#F0F0F0
```

---

## 🔄 Luồng Chạy Chi Tiết (Main Pipeline)

```mermaid
graph LR
    A["🕷️ CRAWL<br/>anonymous +<br/>authenticated"] --> B["📄 RECON.MD<br/>enriched<br/>context"]
    
    B --> C["🎯 VULNHUNTER<br/>LLM: phát hiện<br/>BAC/BLF"]
    
    C --> D["📋 RISK-BUG.JSON<br/>candidate<br/>list"]
    
    D --> E["👨‍💼 MANAGER<br/>select bug"]
    
    E --> F["🔴 RED STRATEGY<br/>LLM: lập<br/>kế hoạch"]
    
    F --> G["📋 SHOT PLAN<br/>=== EXECUTION<br/>SHOT PLAN ==="]
    
    G --> H["🔵 BLUE REVIEW<br/>LLM: phản biện<br/>strategy"]
    
    H -->|APPROVED| I["⚡ EXEC<br/>gen Python<br/>self-verify"]
    
    H -->|REJECTED| F
    
    I --> J["📝 bug-*.py<br/>📊 output.txt<br/>📊 result.json"]
    
    J --> K["👨‍💼 MANAGER<br/>read FINAL/result"]
    
    K -->|❌ FAILED/PARTIAL| E
    
    K -->|✅ EXPLOITED| M["🎉 NEXT BUG"]
    
    M --> N["📄 REPORT<br/>report_final_vi.md"]
    
    style A fill:#87CEEB
    style B fill:#87CEEB
    style C fill:#FFD700
    style D fill:#FFD700
    style E fill:#FFD700,stroke:#333,stroke-width:3px
    style F fill:#FFB6C6
    style G fill:#FFB6C6
    style H fill:#B6D6FF
    style I fill:#C6FFC6
    style J fill:#C6FFC6
    style K fill:#FFB6C6
    style L fill:#C6FFC6
    style M fill:#90EE90
    style N fill:#F0F0F0
```

---

## 🎬 State Machine - Manager Decisions

```mermaid
stateDiagram-v2
    [*] --> RED_STRATEGY
    
    RED_STRATEGY --> BLUE_REVIEW: strategy valid
    RED_STRATEGY --> STOP: budget hết
    
    BLUE_REVIEW --> EXECUTE: APPROVED ✅
    BLUE_REVIEW --> RED_STRATEGY: REJECTED ❌
    BLUE_REVIEW --> STOP: STOPPED ⏹️
    
    EXECUTE --> NEXT_BUG: EXPLOITED 🏆
    EXECUTE --> RETRY_EXEC: script error / partial
    EXECUTE --> STOP: failed / no signal
    
    RETRY_EXEC --> NEXT_BUG: EXPLOITED 🏆
    RETRY_EXEC --> STOP: still failed / partial
    
    STOP --> NEXT_BUG
    NEXT_BUG --> RED_STRATEGY: có bug
    NEXT_BUG --> REPORT: hết bug
    
    REPORT --> [*]
    
    note right of RED_STRATEGY
        🔴 Red Team
        Lập chiến lược
    end note
    
    note right of BLUE_REVIEW
        🔵 Blue Team
        Phản biện
    end note
    
    note right of EXECUTE
        ⚡ Exec Agent
        Chạy exploit
    end note
    
    note right of RETRY_EXEC
        🔧 Retry một lần
        nếu script/partial
    end note
```

---

## 🔴 🔵 Red Team - Blue Team Debate

```mermaid
sequenceDiagram
    participant Manager as 👨‍💼 Manager
    participant Red as 🔴 Red Team
    participant Blue as 🔵 Blue Team
    participant Exec as ⚡ Exec Agent

    Manager->>Red: Giao bug dossier
    Note over Red: Đọc recon.md<br/>Đọc context<br/>LLM: lập strategy
    Red->>Red: Viết EXECUTION SHOT PLAN
    Red-->>Manager: Strategy + Shot Plan
    
    Manager->>Blue: Gửi strategy để review
    Note over Blue: Kiểm tra:<br/>Logic hợp lý?<br/>Feasible không?<br/>Có risk không?
    Blue-->>Manager: APPROVED / REJECTED / STOPPED
    
    alt Blue APPROVED
        Manager->>Exec: Chạy exploit
        Note over Exec: Parse shot plan<br/>Gen script<br/>Bash -n (syntax)<br/>Bash (run)
        Exec-->>Manager: output + artifact
    else Blue REJECTED
        Manager->>Red: Sửa strategy
        Note over Red: Red refine plan
    else Blue STOPPED
        Manager->>Manager: Stop bug
    end
```

---

## ⚡ Execution Flow - One Exploit

```mermaid
graph TB
    A["⚡ Exec nhận<br/>approved strategy"]
    
    B["📝 Gen Python exploit<br/>từ strategy"]
    
    C["🔍 py_compile<br/>Check syntax"]
    
    D{"Syntax<br/>valid?"}
    
    D -->|❌ NO| E["❌ SYNTAX ERROR<br/>→ Manager"]
    
    D -->|✅ YES| F["🚀 Python script<br/>Chạy exploit"]
    
    F --> G["💾 Save:<br/>bug-*.py<br/>output.txt<br/>result.json"]
    
    G --> H["👨‍💼 Manager đọc<br/>FINAL/result.json"]
    
    H -->|❌ FAIL/PARTIAL| I["❌ STOP/RETRY<br/>theo budget"]
    
    H -->|✅ EXPLOITED| J["✅ NEXT_BUG<br/>ghi finding"]
    
    style A fill:#C6FFC6
    style B fill:#C6FFC6
    style C fill:#C6FFC6
    style F fill:#C6FFC6
    style G fill:#C6FFC6
    style J fill:#90EE90
    style E fill:#FFB6C6
    style I fill:#FFB6C6
```

---

## 🛡️ Evidence Guard - Contradiction Checks

```mermaid
graph TB
    INPUT["📊 Input:<br/>Exec Output<br/>+ Artifact"]
    
    C1{"❌ 405/403<br/>nhưng claim<br/>success?"}
    
    C2{"Chỉ gửi<br/>request<br/>không verify?"}
    
    C3{"HTTP code<br/>khác<br/>expected?"}
    
    C4{"Stateful bug<br/>missing<br/>baseline?"}
    
    C5{"Data leaked<br/>tương ứng<br/>role?"}
    
    FAIL["❌ CONTRADICTION<br/>→ Manager"]
    
    PASS["✅ CANDIDATE OK<br/>→ Verify Mode"]
    
    INPUT --> C1
    INPUT --> C2
    INPUT --> C3
    INPUT --> C4
    INPUT --> C5
    
    C1 -->|YES| FAIL
    C2 -->|YES| FAIL
    C3 -->|YES| FAIL
    C4 -->|YES| FAIL
    C5 -->|NO| FAIL
    
    C1 -->|NO| C2
    C2 -->|NO| C3
    C3 -->|NO| C4
    C4 -->|NO| C5
    C5 -->|YES| PASS
    
    style INPUT fill:#FFE6CC
    style PASS fill:#90EE90
    style FAIL fill:#FFB6C6
```

---

## 👨‍💼 Manager Decision - Minimum Proof

```mermaid
graph TB
    A["Exec SEND block<br/>+ result.json<br/>+ artifacts"]
    A --> B{"FINAL/SUCCESS<br/>EXPLOITED?"}
    B -->|YES| DONE["🎉 NEXT_BUG"]
    B -->|NO| C{"2xx + marker<br/>khớp hypothesis?"}
    C -->|YES| DONE
    C -->|NO| D{"SCRIPT_ERROR<br/>or PARTIAL?"}
    D -->|YES| RETRY["🔧 RETRY_EXEC<br/>max 1"]
    D -->|NO| STOP["⏸️ STOP_BUG"]

    style A fill:#C6FFC6,stroke:#333,stroke-width:2px
    style DONE fill:#90EE90
    style RETRY fill:#FFF0CC
    style STOP fill:#FFCCCC
```

---

## 🔄 Per-Bug Collaboration Loop

```mermaid
graph TB
    START["Start Bug"]
    DOSSIER["Bug Dossier<br/>+ recon context"]
    style A2 fill:#90EE90
    style A3 fill:#90EE90
    style A4 fill:#90EE90
    style B1 fill:#FFB6C6
    style B2 fill:#FFB6C6
    style B3 fill:#FFB6C6
    style RESULT fill:#90EE90,stroke:#333,stroke-width:2px
```

---

## 📁 Artifact Structure

```mermaid
graph TB
    ROOT["📁 workspace/<br/>target.com_20260509/"]
    
    LOG["📋 marl.log"]
    
    subgraph "🕷️ CRAWL"
        C1["crawl_data.txt"]
        C2["crawl_raw.json"]
        C3["recon.md ⭐"]
    end
    
    subgraph "🔍 DETECT"
        D1["risk-bug.json"]
    end
    
    subgraph "💥 EXPLOIT"
        E1["exploits/"]
        E1A["bug-001-exploit1.sh"]
        E1B["bug-001-exploit1.sh.output.txt"]
        E2["exploit_state/"]
        E2A["BUG-001/baseline.req"]
        E2B["BUG-001/baseline.resp"]
        E2C["BUG-001/result.json"]
    end
    
    subgraph "📄 REPORT"
        R1["report.md"]
        R2["report_final_vi.md ⭐"]
    end
    
    ROOT --> LOG
    ROOT --> C1
    ROOT --> C2
    ROOT --> C3
    ROOT --> D1
    ROOT --> E1
    E1 --> E1A
    E1 --> E1B
    ROOT --> E2
    E2 --> E2A
    E2 --> E2B
    E2 --> E2C
    ROOT --> R1
    ROOT --> R2
    
    style ROOT fill:#FFE6CC,stroke:#333,stroke-width:2px
    style C3 fill:#87CEEB,stroke:#333,stroke-width:2px
    style R2 fill:#F0F0F0,stroke:#333,stroke-width:2px
    style E2C fill:#90EE90
```

---

## 🎯 Bug Processing Workflow

```mermaid
graph TB
    START["📋 Bug từ<br/>risk-bug.json"]
    
    DOSSIER["📎 Manager tạo<br/>Bug Dossier<br/>+ context"]
    
    RED["🔴 RED:<br/>Strategy +<br/>Shot Plan"]
    
    BLUE["🔵 BLUE:<br/>Review<br/>decision"]
    
    APPROVED{"Blue<br/>APPROVED?"}
    
    EXEC["⚡ EXEC:<br/>Python exploit<br/>self-verify"]
    
    DECIDE{"Manager:<br/>minimum proof?"}
    
    DONE["🎉 Next Bug<br/>or Report"]
    
    START --> DOSSIER
    DOSSIER --> RED
    RED --> BLUE
    BLUE --> APPROVED
    
    APPROVED -->|NO| RED
    APPROVED -->|YES| EXEC
    
    EXEC --> DECIDE
    
    DECIDE -->|NO / retry| RED
    DECIDE -->|YES| DONE
    
    style START fill:#FFE6CC
    style RED fill:#FFB6C6
    style BLUE fill:#B6D6FF
    style EXEC fill:#C6FFC6
    style DECIDE fill:#C6FFC6
    style DONE fill:#90EE90,stroke:#333,stroke-width:2px
```

---

## 💾 Memory & Context Flow

```mermaid
graph LR
    A["🔴 Red<br/>scratchpad<br/>+ findings"]
    
    B["🔵 Blue<br/>decision log<br/>+ notes"]
    
    C["⚡ Exec<br/>session log<br/>+ attempts"]
    
    MS["💾 MemoryStore<br/>findings"]
    
    LED["📊 Ledger<br/>attempts"]
    
    CM["🧠 ContextMgr<br/>summary only"]
    
    A --> MS
    A --> LED
    A --> CM
    
    B --> MS
    B --> LED
    B --> CM
    
    C --> MS
    C --> LED
    C --> CM
    
    MS --> NEXT_AGENT["➡️ Next Agent"]
    LED --> NEXT_AGENT
    CM --> NEXT_AGENT
    
    NEXT_AGENT -->|❌ NO full history| SAVE["✅ Token saved<br/>40-50%"]
    
    style MS fill:#E6F3FF
    style LED fill:#E6F3FF
    style CM fill:#E6F3FF
    style SAVE fill:#90EE90,stroke:#333,stroke-width:2px
```

---

## 📊 Result JSON Schema

```mermaid
graph TB
    ROOT["result.json"]
    
    ROOT --> BID["bug_id"]
    ROOT --> TYPE["type<br/>Horizontal IDOR"]
    ROOT --> STATUS["status<br/>EXPLOITED"]
    ROOT --> VAL["exec_result_status<br/>EXPLOITED"]
    ROOT --> EV["evidence"]
    ROOT --> SCRIPT["exploit_script<br/>exploits/bug-001-exploit1.py"]
    ROOT --> TIME["timestamp"]
    
    EV --> BASELINE["baseline_response_code<br/>200"]
    EV --> PROBE["probe_response_code<br/>200"]
    EV --> LEAKED["data_leaked<br/>user_id, email, phone"]
    EV --> FINAL["final_reason<br/>minimum proof reached"]
    
    style ROOT fill:#FFE6CC,stroke:#333,stroke-width:2px
    style EV fill:#E6F3FF
    style BASELINE fill:#90EE90
    style PROBE fill:#90EE90
    style LEAKED fill:#90EE90
    style FINAL fill:#90EE90
```

---

## 🎓 Presentation Flow

```mermaid
graph TB
    TITLE["🎤 MARL Pentest Agent<br/>Multi-Agent LLM System<br/>for BAC/BLF Testing"]
    
    ARCH["🏗️ Architecture<br/>Show component diagram<br/>7 agents + 2 guards"]
    
    FLOW["🔄 Pipeline Flow<br/>Show main pipeline<br/>Crawl → Report"]
    
    DEBATE["🎯 Red/Blue Debate<br/>Show sequence diagram<br/>Strategy → Review → Exec"]
    
    DEMO["🎬 Live/Video Demo<br/>recon.md → bug<br/>→ strategy → exploit<br/>→ result → report"]
    
    METRIC["📊 Metrics<br/>Token saved: 40-50%<br/>E2E time: ~2min/bug<br/>Validation: 25-35%"]
    
    QA["❓ Q&A<br/>Token compression<br/>False positive handling<br/>Future work"]
    
    TITLE --> ARCH
    ARCH --> FLOW
    FLOW --> DEBATE
    DEBATE --> DEMO
    DEMO --> METRIC
    METRIC --> QA
    
    style TITLE fill:#FFD700,stroke:#333,stroke-width:3px
    style ARCH fill:#87CEEB
    style FLOW fill:#87CEEB
    style DEBATE fill:#FFE6E6
    style DEMO fill:#C6FFC6
    style METRIC fill:#E6F3FF
    style QA fill:#FFF9E6
```

---

**Created**: 09/05/2026 | **Format**: Pure Mermaid Diagrams | **Purpose**: Visual Architecture Overview
