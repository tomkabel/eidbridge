# PACKET-RELEASE local evidence (2026-11-20)

All numbers measured in the build sandbox on 2026-11-20; nothing was published, tagged or pushed to a registry.

## Static binaries (CGO_ENABLED=0, -trimpath -s -w)

| Target | Bytes | `file` |
|---|---|---|
| linux/amd64 | 9797816 | ELF 64-bit, statically linked, stripped |
| linux/arm64 | 9306296 | ELF aarch64, statically linked, stripped |
| darwin/arm64 | 9553346 | not inspected beyond build |
| windows/amd64 | 10106368 | not inspected beyond build |

## Images

| Image | `docker image inspect .Size` | User | Base |
|---|---|---|---|
| Dockerfile (compose) eidbridge | 14303474 | 65532:65532 | scratch |
| goreleaser snapshot amd64 | 14281673 | 65532:65532 | scratch + alpine CA bundle |
| goreleaser snapshot amd64, before fix | 20093519 (over target) | 65532:65532 | distroless static |
| demo-rp | 12509705 | 65532:65532 | scratch |

The goreleaser arm64 image reports 3875136 on the amd64 host; that figure is the compressed layer size of a foreign-platform image and is not compared to the target.

## goreleaser snapshot

`goreleaser v2.12.7 release --snapshot --clean --skip=publish,sign`: "release succeeded after 9s". Produced linux and darwin amd64/arm64 archives, `checksums.txt` and one SPDX-2.3 SBOM per archive (syft). `docker run ... --version` printed `eidbridge 0.0.1-snapshot (unofficial)`.

## Clean clone to completed demo login

`git clone -b feat/full-build` into an empty directory, `docker builder prune -af`, project images removed, then `scripts/e2e-demo.sh` (compose build, up, scripted browser login against the fixture upstream). Base images (golang:1.24-alpine, alpine) were already in the local image store.

- stack up in 43s
- login completed in 0.52s
- total wall clock from clone start to verified claims: 43.4 s (target: under 5 minutes)
- `PRODUCTION=1` demo-rp: "refused: demo identities are refused in production" (HTTP 403)

Not run: QR scan with a real phone (human), Smart-ID demo environment through compose (live run exists separately: cmd/eidbridge TestLiveDemoBridgeLogin), pushes to GHCR (out of scope).

## Accessibility (Story 3.4, NFR-010)

`scripts/a11y.py` with axe-core 4.10.3 (axe.min.js sha256 880970c081707360e64f34cea25ff91892f5bc95675b0776925b9709dd8a68bb, rules wcag2a/aa, wcag21a/aa, best-practice) in Chrome via Playwright, bridge in demo mode against the fixture upstream. Exit 0:

```
choose[en]: passes=36 serious/critical=0 other=[]
  keyboard: reached 'Show a QR code to scan with Smart-ID' after 5 Tab(s), focus solid 3px
pending-qr[en]: passes=37 serious/critical=0 other=[]
  keyboard cancel -> /callback error=access_denied
outcome-or-restart[en]: passes=33 serious/critical=0 other=[]
restart-no-cookie[en]: passes=33 serious/critical=0 other=[]
choose[et]: passes=36 serious/critical=0 other=[]
choose[ru]: passes=36 serious/critical=0 other=[]
error[en]: passes=33 serious/critical=0 other=[]
```

The keyboard-only check found a real defect: Chrome applies CSP `form-action` to the redirects after a form POST, so a keyboard (or mouse) Cancel ended on the restart page and the client never received `access_denied`. Fixed by adding the client's redirect origin to `form-action` on flow pages (TestLoginPageCSPAllowsOnlyThisClientOriginForForms) and by stopping status polling once a form is submitted. Not run: screen-reader pass (NVDA/VoiceOver) and a manual 200 % zoom review – human follow-ups.

### Rerun with two methods (Story 4.1 keyboard AC)

Bridge with `EIDBRIDGE_METHODS=smartid,mobileid` (both mock), Smart-ID device-link and notification. Exit 0:

```
choose[en]: passes=40 serious/critical=0 other=[]
  keyboard: reached 'Show a QR code to scan with Smart-ID' after 5 Tab(s), focus solid 3px
  keyboard: all 9 controls in main reachable by Tab
pending-qr[en]: passes=37 serious/critical=0 other=[]
  keyboard cancel -> /callback error=access_denied
outcome-or-restart[en]: passes=33 serious/critical=0 other=[]
restart-no-cookie[en]: passes=33 serious/critical=0 other=[]
choose[et]: passes=40 serious/critical=0 other=[]
choose[ru]: passes=40 serious/critical=0 other=[]
  notification by keyboard -> pending page, verification code shown: True
pending-notification[en]: passes=35 serious/critical=0 other=[]
error[en]: passes=33 serious/critical=0 other=[]
```
