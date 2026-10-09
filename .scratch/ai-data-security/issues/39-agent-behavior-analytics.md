# 39: Agent behavior analytics

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M4
Blocked by: 28
Spec: `../spec.md` §3.1 P2; ASI08, ASI10

## Konteks
Deteksi rogue agent dan cascading failure dari pola tool call.

## Scope
- Baseline urutan tool call per agent.
- Deteksi anomali (tool baru, lonjakan volume, urutan tidak lazim) → event dan risk signal.

## Acceptance criteria
- [x] Evaluasi pada skenario rogue agent sintetis. *(`TestRogueAgentEval`: tiga agent (cs-bot, payments-bot, report-bot) menjalankan workflow Markov normal selama 5 hari kerja simulasi, 10 seed. Empat skenario disuntikkan ke salinan baseline: bulk export yang belum pernah dipakai (`new_tool`), transfer tanpa validasi penerima (`rare_sequence`), loop query report 120x (`volume_spike`, ASI08), dan burst lookup akun (`volume_spike`). Semua tertangkap di 10/10 seed. Benign setelah baseline 5 hari: 0 dari 21.442 call diflag; baseline 1 hari: 0,046%.)*
- [x] Alert terhubung ke incident. *(Gateway mengirim `agent.behavior_anomalies` ke PDP dan ke decision event. Floor risk `agent-behavior-anomaly` = 60 ≥ `incident.MinRisk` (40), jadi event membuka insiden. `TestBehaviorThroughGateway` memakai policy risk asli; replay `PDPInput` membawa sinyal yang sama.)*

## Keputusan
- **Baseline per agent, in-memory di gateway:** tool yang pernah dipakai, transisi tool→tool per trace (session), dan laju call per menit (EWMA). Dinilai hanya setelah warm-up 50 call; transisi dinilai setelah tool asal punya ≥ 20 transisi keluar; spike = > max(5× laju biasa, 20) call/menit. Baseline terus belajar, jadi tool baru diflag pada call-call pertamanya, tidak selamanya.
- **Semua percobaan dihitung**, termasuk yang diblok: rogue agent terlihat dari apa yang dicobanya.
- **Sinyal, bukan blok:** anomali menaikkan risk ke floor 60 (insiden). Memblok tetap urusan rule policy.
- **Batas yang diketahui:** profil per replika dan hilang saat restart (warm-up ulang). Persist profil atau pindahkan analisis ke consumer event stream bila agent harus diawasi sejak call pertama setelah deploy.
