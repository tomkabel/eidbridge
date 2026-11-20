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
