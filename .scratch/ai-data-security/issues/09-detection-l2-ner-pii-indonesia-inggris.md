# 09: Detection L2: NER PII Indonesia/Inggris

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 08
Spec: `../spec.md` §9.2; §9.4

## Konteks
Entitas tanpa pola tetap (nama, alamat, diagnosis) butuh model NER.

## Scope
- Fine-tune encoder multibahasa kecil, lalu distilasi ke ONNX int8.
- Serving lewat model-inference (Triton/ONNX Runtime) di CPU.
- Integrasi ke detection-svc dengan timeout dan fallback ke hasil L1.
- Model card + versi model di setiap respons.

## Acceptance criteria
- [ ] F1 per entitas dilaporkan; ECE ≤ 0,05.
- [ ] p95 L2 ≤ 50 ms (bersama classifier injection).
- [ ] Model dirilis lewat shadow mode dulu.
