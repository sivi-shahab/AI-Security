# 20: Posture dashboard v1

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 16, 17, 18
Spec: `../spec.md` §4.11 FR-COMP-5; §1.5

## Konteks
CISO butuh gambaran posture dan tren.

## Scope
- Skor posture per domain (discovery, data, prompt, agent, policy hygiene) + tren 90 hari.
- Top risks, shadow AI top apps, exception yang akan kedaluwarsa.
- Metrik sukses §1.5 yang sudah bisa diukur di M1.

## Acceptance criteria
- [x] Dashboard dapat diakses sesuai RBAC (CISO read-only). *(`GET /posture` butuh `dashboard.read`; matriks route × role (ticket 06) mencakupnya; test: role `ciso` hanya memegang permission `*.read`.)*
- [x] Angka dashboard cocok dengan query langsung ke store analitik (test rekonsiliasi). *(`TestReconciliation`: fixture event di OpenSearch + data Postgres; setiap pembilang/penyebut domain, total tren 90 hari, incident terbuka, MTTD, hygiene, shadow AI dicocokkan dengan query DSL/SQL yang ditulis terpisah di test, dan dengan nilai fixture. Mutation check: membuang `redact` dari aksi "terlindungi" membuat test gagal.)*

## Keputusan
- API `GET /posture` (JSON); UI menyusul bersama admin UI. Setiap skor domain dikembalikan bersama pembilang, penyebut, dan definisinya, sehingga bisa diperiksa. Penyebut 0 = skor `null` (tidak diketahui), bukan 100.
- Rumus (spec tidak memberi):
  - discovery = event AI 30 hari ke app yang statusnya sudah diputuskan bank / semua event AI;
  - data = event sensitif (ada class, atau confidential/restricted) yang di-block/redact/tokenize/quarantine/approval / semua event sensitif;
  - prompt = percobaan injection/jailbreak (skor ≥ 0,8) yang di-block/quarantine/approval / semua percobaan;
  - agent = event agent dari agent terdaftar / semua event agent (tidak dikirim = tidak terdaftar);
  - policy hygiene = kontrol berbatas waktu yang sehat / semua (exception aktif tidak kedaluwarsa ≤ 7 hari, review katalog tidak lewat, incident tidak lewat SLA ack).
  - overall = rata-rata domain yang punya data.
- Tren 90 hari per hari dari OpenSearch untuk 4 domain berbasis event (agregasi yang sama dengan ringkasan); hygiene hanya titik waktu sekarang.
- Top risks: incident terbuka paling berat + app dengan event sensitif terbanyak. Shadow AI: app terpakai yang statusnya belum diputuskan (termasuk yang di luar katalog). Inventory AI: jumlah per status, flag offshore tanpa OJK, review lewat, app di luar katalog.
- Metrik §1.5 yang terukur di M1: app top-100 yang sudah diberi status; MTTD incident critical (event pertama → incident). Sisanya dilaporkan `not_measured` dengan ticket yang mengukurnya.

## Hasil verifikasi lokal (2026-10-03)
- Seluruh suite `-race` dengan semua service integrasi; golangci-lint bersih; image ter-build.

## Sisa / follow-up
- UI dashboard (admin UI) dan snapshot harian untuk tren policy hygiene.
- Bobot/ambang skor perlu dikonfirmasi dengan CISO; rumus ada di `internal/posture/posture.go` (`Def*`).
- Domain discovery memakai himpunan app "decided" saat ini untuk seluruh tren (bukan status historis).
