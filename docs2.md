# Enterprise AI Data Security / AI Security Posture Management Specification

## Deliverable

Saya telah menyelesaikan deep research dan menyusunnya menjadi **satu file `spec.md`** yang dapat langsung dipakai sebagai baseline PRD, Software Requirement Specification, architecture specification, dan engineering implementation plan.

**[Download spec.md](sandbox:/mnt/data/spec.md)**

File berisi sekitar **1.900 baris** spesifikasi teknis, termasuk Mermaid diagrams, ER schema, sequence diagrams, API contracts, algoritma detection, target performa, testing strategy, dan estimasi engineering.

## Basis Riset

Arsitektur dalam spesifikasi tidak hanya mengambil pola dari Forcepoint. Saya membandingkan beberapa pendekatan enterprise.

Forcepoint menempatkan discovery, classification, dan policy enforcement sebagai fondasi AI data security untuk sanctioned AI, shadow AI, dan AI agents. Forcepoint juga memperlakukan prompt, file upload, response, dan agent activity sebagai jalur perpindahan data yang perlu dikontrol. citeturn16view0turn16view1

Microsoft Purview DSPM memberi pola yang lebih luas. Microsoft menggabungkan discovery, sensitive data posture, DLP, AI apps, AI agents, activity investigation, oversharing detection, remediation, audit, dan posture trend dalam satu pendekatan data-centric. citeturn15view1 Microsoft juga secara eksplisit mendefinisikan Shadow AI sebagai AI applications atau standalone agents yang berjalan tanpa visibility atau approval dari IT. citeturn15view2

Netskope memberikan referensi penting untuk enforcement architecture. CASB mereka menggabungkan visibility untuk managed dan unmanaged cloud or AI applications dengan inline inspection. AI Gateway mereka menempatkan authentication, traffic control, DLP, guardrails, prompt inspection, response inspection, dan audit pada jalur app-to-LLM. Untuk autonomous AI, Agentic Broker memperluas pola itu ke MCP traffic, tool calls, agent inventory, DLP, least privilege, dan session audit. citeturn15view3turn15view4turn15view5

Bagian prompt security mengikuti pendekatan defense-in-depth OWASP. OWASP mencakup direct dan indirect prompt injection, encoded dan multilingual attacks, sensitive-information disclosure, serta excessive agency. Panduan tersebut mendukung sanitization, redaction, least privilege, output validation, dan human approval untuk aksi berisiko tinggi. citeturn16view2turn16view3turn16view4

Desain juga mempertimbangkan hasil penelitian tentang indirect prompt injection, goal hijacking, prompt leaking, transferable adversarial suffix, dan pemisahan trusted instructions dari untrusted data melalui structured queries. Hal ini menjadi dasar keputusan agar platform tidak mengandalkan regex atau keyword filtering saja. citeturn16view7turn16view8turn16view9turn16view10

## Isi Utama `spec.md`

Spesifikasi mencakup seluruh area yang diminta, dengan keputusan teknis yang cukup konkret untuk mulai membuat backlog engineering:

| Area | Cakupan dalam file |
|---|---|
| Product definition | Vision, problem statement, principles, non-goals, success metrics |
| Users | CISO, SOC, security admin, DLP analyst, compliance, AI engineer, agent owner, auditor |
| MVP | P0, P1, P2 priorities, phased deliverables, Definition of Done |
| AI discovery | App catalog, domain/API fingerprinting, sanctioned status, confidence scoring |
| Shadow AI | Unknown AI discovery, personal/corporate context, device context, risk factors |
| Data discovery | Connector SDK, incremental scan, ACL analysis, oversharing, data-at-rest scanning |
| Classification | PII, PHI, PCI, credentials, code, IP, financial, legal, HR, custom taxonomy |
| Prompt security | Direct/indirect injection, jailbreak, prompt exfiltration, encoding, role confusion |
| DLP | Allow, warn, redact, tokenize, block, quarantine, approval, remediation |
| Policy engine | OPA/Rego model, versioning, simulation, rollback, exception expiry |
| Agent governance | Agent identity, MCP/API tools, short-lived credentials, HITL approval, kill switch |
| Risk scoring | Weighted 0 to 100 model plus critical overrides |
| Incident management | Correlation, deduplication, state machine, evidence, containment |
| Compliance | Evidence mapping, posture reporting, control history, audit integrity |
| Architecture | Control plane, data plane, detection plane, analytics plane |
| Microservices | Service boundaries, storage ownership, scaling characteristics |
| Enforcement | AI gateway, web proxy, endpoint agent, browser extension, SaaS API, MCP gateway |
| Database | PostgreSQL model plus complete Mermaid ER diagram |
| Sequences | Prompt enforcement and AI agent tool-call sequence diagrams |
| APIs | Text scan, file scan, policy simulation, app inventory, incidents, agent authorization |
| ML pipeline | Regex, checksum, secret detection, NER, embeddings, injection classifier |
| Training | Corpus requirements, synthetic data, customer data isolation, labeling requirements |
| Evaluation | Precision, recall, F1, PR-AUC, FPR, calibration, attack detection metrics |
| Security | Encryption, tenant isolation, RBAC, ABAC, SSO, SCIM, KMS, audit hashing |
| Privacy | No raw content by default, retention TTL, pseudonymization, model-training controls |
| Integrations | IAM, cloud, M365/Google Workspace, SIEM, SOAR, ITSM, EDR, secrets, AI providers |
| Infrastructure | Kubernetes, Kafka, PostgreSQL, OpenSearch, OPA, Redis, object storage |
| CI/CD | SAST, SCA, SBOM, signing, IaC scanning, progressive rollout |
| Observability | OpenTelemetry model, metrics, tracing, security telemetry |
| Testing | Unit, integration, adversarial AI, fuzzing, isolation, load, chaos, DR, pentest |
| Performance | p95/p99 latency, availability, policy propagation, file limits |
| Roadmap | Milestones, person-weeks, phased schedule, Mermaid Gantt |
| Unknowns | Budget, exact team size, cloud, data residency, certification and traffic marked `unspecified` |

Policy evaluation sengaja dipisahkan dari enforcement. OPA cocok untuk pola ini karena menyediakan policy-as-code dan memisahkan policy decision dari komponen yang menjalankan keputusan. citeturn16view6 Risk governance juga mengikuti pendekatan NIST AI RMF yang memasukkan risk management dan trustworthiness ke lifecycle AI. NIST menyatakan AI RMF 1.0 sedang menjalani revisi pada 2026, sehingga framework mapping dalam produk dirancang versioned, bukan hard-coded. citeturn16view5

## Rekomendasi Arsitektur Utama

Kesimpulan teknis utama dalam `spec.md` adalah menggunakan **hybrid enforcement architecture**, bukan satu agent atau satu proxy.

```text
Users / Browsers ───────► Inline Web Proxy ──────┐
                                                  │
Internal AI Apps ───────► AI API Gateway ────────┤
                                                  │
AI Agents ──────────────► Agent / MCP Gateway ───┤
                                                  ├─► Detection
Managed Endpoints ──────► Endpoint Controls ─────┤    Classification
                                                  │    Prompt Security
Cloud / SaaS ───────────► API Connectors ─────────┤    Risk Scoring
                                                  │
                                                  ▼
                                            Policy Engine
                                                  │
                    ┌─────────────────────────────┼──────────────────────────┐
                    ▼                             ▼                          ▼
                  Allow                      Redact/Warn                    Block
                    │                             │                          │
                    └─────────────────────────────┼──────────────────────────┘
                                                  ▼
                                      Event + Incident Pipeline
                                                  ▼
                              Posture / Investigation / Compliance
```

AI Gateway menjadi **P0** karena memberikan enforcement paling deterministik untuk aplikasi internal dan app-to-LLM traffic. Web/proxy discovery menangani public and shadow AI. SaaS connectors menangani posture dan remediation. Endpoint agent ditempatkan pada **P2** karena biaya engineering, deployment, OS compatibility, serta maintenance jauh lebih tinggi. Agent/MCP gateway masuk **P1** agar autonomous agents tidak memakai privilege dan tool access tanpa governance.

Pendekatan ini selaras dengan pola modern yang terlihat pada Forcepoint untuk data-centric AI controls, Microsoft untuk AI observability dan posture management, serta Netskope untuk CASB, AI Gateway, dan agentic traffic control. citeturn16view0turn15view1turn15view4turn15view5

**File final:** **[spec.md](sandbox:/mnt/data/spec.md)**
