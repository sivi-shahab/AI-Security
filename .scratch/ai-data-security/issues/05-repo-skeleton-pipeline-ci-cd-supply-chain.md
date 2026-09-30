# 05: Repo skeleton + pipeline CI/CD & supply chain

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 01
Spec: `../spec.md` §5.3 DEC-3; §12.2

## Konteks
Fondasi build untuk semua service. Control plane berupa modular monolith; PEP dan detection terpisah.

## Scope
- Struktur repo: control-plane (modular monolith), ai-gateway, detection-svc, model-inference, deploy/ (Helm/Kustomize).
- Pipeline: lint → unit → SAST → SCA → secret scan → build distroless → SBOM CycloneDX → cosign sign → IaC scan.
- Admission policy di cluster: hanya image bertanda tangan.
- Test privasi bersama: assert log/trace tidak mengandung field konten terlarang.

## Acceptance criteria
- [ ] Pipeline hijau untuk service hello-world di tiap komponen.
- [ ] SBOM dan signature terlampir di setiap image.
- [ ] Deploy image tanpa tanda tangan ditolak cluster.
