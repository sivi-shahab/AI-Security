# 43: Paksa trafik LLM lewat AI gateway (egress + deteksi bypass)

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 13
Spec: `../spec.md` §5.4; `docs/threat-model.md` §4.1, G4

## Konteks
Threat model (tiket 02) G4: tanpa aturan egress, AI gateway bersifat opsional. App bisa memanggil provider LLM langsung dengan key pribadi developer.

## Scope
- Aturan egress (firewall/SWG, dikelola tim jaringan bank) yang mengizinkan domain API provider LLM di katalog hanya dari IP egress AI gateway. Repo menyediakan daftar domain dari katalog (`hosting_region`, kategori API).
- Sinyal posture: trafik langsung dari subnet server ke domain API provider (dari log SWG/DNS, tiket 03) → event + temuan posture.

## Acceptance criteria
- [x] Ekspor daftar domain API provider dari katalog, dengan test. *(`catalog.ProviderDomains` dan `GET /catalog/egress` (JSON atau `?format=txt`, `config.read`). Diuji di `TestProviderDomains` dan `TestGatewayBypassAPI`: domain provider ada, app tanpa API tidak ikut, daftar terurut dan unik, subdomain yang sudah tercakup induknya dibuang, cocok ke subdomain, tidak terkecoh trik sufiks.)*
- [x] Trafik langsung ke provider di log sintetis menghasilkan temuan posture "gateway bypass". *(`TestGatewayBypass` (shadow) memakai log Squid/BIND/JSONL sintetis: server → `api.openai.com`, `api.anthropic.com`, dan `generativelanguage.googleapis.com` terdeteksi. Yang tidak dilaporkan: IP egress gateway, workstation, host non-AI, app tanpa API, dan log tanpa IP klien. Temuan dikirim lewat `POST /catalog/gateway-bypass`, lalu muncul di `GET /posture` (`gateway_bypass` dan metrik target 0, `TestReconciliation`). Setiap pasangan server/domain baru diaudit (`catalog.gateway_bypass` → SIEM).)*
- [x] Runbook aturan egress diserahkan ke tim jaringan. *(`docs/runbooks/egress-ai-gateway.md`: daftar domain, tabel aturan, uji, deteksi dari log, dan tindak lanjut. Penyerahan ke tim jaringan dilakukan oleh manusia.)*

## Keputusan
- **Domain yang diekspor:** semua domain dari app katalog yang punya `api_endpoints`, termasuk domain web-nya (server tidak punya alasan membuka `chatgpt.com`). Subdomain yang sudah tercakup domain induk dibuang. App tanpa API (image, meeting, dll.) tetap urusan SWG untuk pengguna, bukan aturan egress server ini. Sumbernya katalog efektif (feed + app lokal), jadi app lokal yang ditambah bank ikut terekspor.
- **Deteksi:** `shadow-baseline -servers <CIDR> -gateways <IP>` menandai klien di subnet server (selain IP egress gateway) yang mengakses domain provider. Record log kini membawa `Client` (IP). Squid dan BIND selalu punya; JSONL lewat field `client_ip` (bisa dipetakan). Alamat server dilaporkan apa adanya karena infrastruktur, bukan orang. User dan workstation tetap di-HMAC.
- **Jalur ke posture:** shadow-baseline tetap CLI batch (seperti tiket 03). Temuannya dikirim ke `POST /catalog/gateway-bypass` (`config.write`) dan disimpan per server+domain (`catalog.gateway_bypass`, request dijumlahkan). Pasangan baru diaudit (event SIEM), dan posture menampilkan pasangan dengan trafik dalam 30 hari plus metrik jumlah server (target 0).

## Hasil verifikasi lokal (2026-10-10)
- Paket yang tersentuh (`catalog`, `shadow`, `posture` dengan OpenSearch 2.19.3, `compliance`) hijau. `go vet ./...` dan golangci-lint v2.5.0 0 issue.
- `go test -race ./...`: tiga test timing di paket yang tidak disentuh tiket ini (`agents.TestKillSwitchPropagation`, `mcpgw.TestKillSwitch`, `policysvc` timeout) gagal saat load average host ~50 dari pekerjaan paralel. Perlu dijalankan ulang di host yang sepi atau CI.

## Sisa
- Aturan firewall/SWG dipasang oleh tim jaringan (runbook). Repo tidak bisa memverifikasinya.
- Penjadwalan shadow-baseline dan POST temuan (CronJob) belum dibuat. Saat ini manual sesuai runbook.
- Threat model G4 perlu diperbarui statusnya setelah aturan egress terpasang.
