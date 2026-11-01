# FINDINGS.md: Container Security Improvement Ladder (steps A to F)

> Fill in every `TBD`. Record raw evidence (JSON scan output, command logs) in `./evidence/` and reference it here.
> Rule: never report a number without the scanner name, scanner version, DB date, and image identifier.
> Method: **one change per step, scan after every step.** Numbers come from `scripts/summarize.sh` (`evidence/ladder.csv`). Before you report or present any comparison, run `scripts/rescan-all.sh` so every step is scanned the same day with the same vulnerability databases.
> Naming: a step's letter is its ID. Step `A` = image `hello:a-baseline` = evidence files `evidence/A.*`. Optional side-by-sides use `Ealt`, `Ebuild`, `Eapko`.
> Image identifier: until an image is pushed to a registry, use the **local image ID** (`docker image inspect -f '{{.Id}}'`). After a push (Bonus A), record the registry **digest** and say which one you are quoting.

---

## 0. Executive summary (write last, put first)

3-4 sentences: the starting point, what I changed and in what order, the headline numbers (A to F), and the single most important thing I learned.

The baseline (A: single-stage on `golang:1.18`, root, 1,486.5 MB) shows 2,341 Grype findings (753 Critical+High) and 14,144 Trivy findings. Changing one thing at a time (multi-stage with Alpine at B, Go 1.27.3 at C, Gin v1.12.0 and updated modules at D, Chainguard `static` at E, hardening flags at F) brought Grype to 0 findings and Trivy to 1 (an UNKNOWN-severity advisory) at 35.8 MB, running as UID 65532; Grype's drop was 2,262 at B (OS packages and the shipped Go toolchain), 59 at C (stdlib), 16 at D (modules) and only 3 at E (the Alpine busybox CVE), so the base image, the compiler and the dependencies are separate problems with separate fixes, and E was a small count change for this static Go binary. F changed no image (counts are taken from E) but the kernel shows the privilege ceiling going from the Docker default (`CapBnd 00000000a80425fb`) to zero with `NoNewPrivs 1`. The most important lesson is that counts are findings, not risk: the scanners differ by up to 6x at A and share no finding at D, and the value of E is mostly what a count cannot show. Limitations: one run per step on arm64, one static Go binary with one route (best case for a minimal base), and the F image ID and F scans were not captured.

---

## 1. Environment and decisions

| Item | Choice | Version | Why (one sentence) | Tradeoff accepted |
|---|---|---|---|---|
| Virtualization platform | Multipass | TBD (user): `multipass version` is not in evidence | Fast way to get a clean, scriptable Ubuntu LTS VM on a Mac. One command to create, snapshot, and destroy, and it mirrors how containers are usually run in production: on cloud Linux VMs. | UTM: GUI, more control, slower to set up. Lima: great, more config. VirtualBox: weak on Apple Silicon. |
| Guest OS | Ubuntu Server 24.04 LTS | kernel: 6.8.0-147-generic; CPUs: 4; RAM: 8 GB; Disk: 40 GB | TBD | TBD |
| CPU architecture (host / guest) | aarch64 (Apple Silicon host; arm64 guest) | TBD | TBD | amd64 is most common in production, but I'm on Apple Silicon and want to run at full speed without fully emulating |
| Container engine | Docker Engine (`docker-ce`, installed from Docker's apt repository inside the VM) | TBD (user): `docker version` is not in evidence | TBD | TBD |
| Scanner 1 | Grype | 0.121.0 | TBD | TBD |
| Scanner 2 | Trivy | 0.76.1 | TBD | Shows scanner discrepancy |
| Scanner 3 (reachability) | govulncheck | v1.9.0 | Separates "present" from "called" | Source mode uses the VM's Go, not the image's (see Section 7) |
| SBOM tool | Syft | 1.55.0 | TBD | TBD |
| Signing tool | cosign | v3.1.4 | TBD | TBD |
| Experiment design | One change per step (A to F) | n/a | Every delta has exactly one cause | Each step is measured *given the steps before it* (order-dependent attribution; the total is not) |
| Go toolchain used in the images (baseline / patched) | go1.18.10 / go1.27.3 | `A.buildinfo.txt` / `C.buildinfo.txt`, `D.buildinfo.txt`, `E.buildinfo.txt` | Newest Go available in the builder tag at step C | The patched images embed Go 1.27.3; this is separate from the `go` line in `go.mod` |
| Go toolchain installed in the VM (for `go get` and govulncheck source mode) | Go 1.27.3 | | Needed to patch `go.mod` and run source-mode reachability | Source-mode results reflect this newer Go, not the Go 1.18 in the baseline image |
| Gin version (baseline / patched) | v1.8.1 / v1.12.0 | `go/go.mod` at `a6ff36e` / `64db612` | Latest Gin at the time of the bump (step D-a) | Gin 1.8 to 1.12 is a large minor jump with no tests to catch behaviour changes |
| `go` line in go.mod (baseline / patched) | 1.18 / 1.26.10 (D-a set 1.25.0, D-b raised it to 1.26.10) | `git diff a6ff36e 64db612 -- go/go.mod` | Set automatically by `go get` | Yes in principle: a builder older than Go 1.26.10 cannot build the patched module. Step C had already moved the builder to 1.27.3, so no extra builder change was needed at D (the old `golang:1.18` builder was not retried; inferred, not tested). |
| Step B runtime base | alpine:3 (assumption; edit if different) | Resolved to Alpine 3.24.3 (`alpine-release 3.24.3-r0`, `B.syft.json`); registry digest not captured | Minimal but conventional; keeps a shell and package manager | Runs as root by default |
| Step E runtime base | cgr.dev/<org>/static (Chainguard "distroless") | Used `cgr.dev/checkmarx.com/static:latest` (`E.build.txt`); scanners identify the distro as `chainguard 20230214`; digest not captured | Same app, same compiler; only the base changes | Access/plan limits; vendor dependency; runs non-root by default, so E changes two things (base and default user) |
| Optional side-by-side (Ealt) | gcr.io/distroless/static-debian12 | Not built (no `evidence/Ealt.*`) | Evidence for "we already use distroless"; fallback if Chainguard access is delayed | Debian cadence; no SLA; default tag runs as root |

---

## 2. The ladder (variants under test)

### 2a. Definition (each step changes exactly one thing)

| ID | Step | The ONE change vs. previous | Dockerfile + build args | Build stage base | Runtime base | App deps | Go toolchain | Runs as | Image tag / evidence | Comments |
|---|---|---|---|---|---|---|---|---|---|---|
| **A** | Baseline: single-stage, golang base | (starting point) | `Dockerfile.single`, `GO_VERSION=1.18` | `golang:1.18`, digest `sha256:50c889275d26f816b5314fc99f55425fa76b18fcaf16af255f5d57f09e1f48da` (Debian GNU/Linux 11 (bullseye), linux/arm64) | Same as build (single stage) | Vulnerable (original): Gin v1.8.1 plus the original indirect deps, `go.mod`/`go.sum` untouched | Original: Go **1.18.10** | root | `hello:a-baseline`, `evidence/A.*` | Full Go toolchain, source, Debian userland, shell and `apt` all shipped. `COPY . .` before `go mod download` defeats layer caching. Exec-form `CMD` (app is PID 1). Static binary (`CGO_ENABLED=0`). The "typical team" starting point. |
| **B** | Multi-stage, minimal runtime base | Multi-stage build; runtime becomes Alpine | `Dockerfile.multi`, `GO_VERSION=1.18`, `RUNTIME_IMAGE=alpine:3` | `golang:1.18` (same image as A) | `alpine:3`, resolved to Alpine 3.24.3 (digest not captured; `docker buildx imagetools inspect alpine:3`) | Original (same as A) | Go 1.18.10 | root | `hello:b-multistage`, `evidence/B.*` | Expect OS-package findings and size to collapse; module and stdlib findings unchanged. Still has a shell and package manager. |
| **C** | Go toolchain updated | Newer Go in the builder | `Dockerfile.multi`, `GO_VERSION=1.27.3`, `RUNTIME_IMAGE=alpine:3` | `golang:1.27.3` (digest not captured; `docker buildx imagetools inspect golang:1.27.3`) | `alpine:3` (same as B) | Original | Go **1.27.3** (`C.buildinfo.txt`) | root | `hello:c-go-updated`, `evidence/C.*` | Expect stdlib findings to drop sharply; nothing else should move. If the build fails on old dependencies, log the friction. |
| **D** | Modules bumped | `go get` Gin and transitive deps; `go mod tidy` | Same args as C; **source changed** | `golang:1.27.3` (same as C) | `alpine:3` | **Patched:** Gin **v1.12.0** plus updated indirect deps (`go` line 1.26.10) | Go 1.27.3 (same as C) | root | `hello:d-mods-bumped`, `evidence/D.*` | Record the `go` line in `go.mod` before and after. Did the dependency update force a toolchain update? No tests exist; the only check is `curl` returning `Hello World!`. |
| **E** | **Chainguard "distroless" runtime base** | Runtime base Alpine to Chainguard `static` | `Dockerfile.multi`, `RUNTIME_IMAGE=cgr.dev/<org>/static:latest` | `golang:1.27.3` (same as D) | `cgr.dev/<org>/static` (Chainguard OS / Wolfi-based; used `cgr.dev/checkmarx.com/static:latest`; digest not captured: `docker buildx imagetools inspect cgr.dev/checkmarx.com/static:latest`) | Patched | Go 1.27.3 (`E.buildinfo.txt`) | 65532 (image default; verify with `docker image inspect`) | `hello:e-chainguard`, `evidence/E.*` | No shell, no package manager. Expect a small change in counts, because Alpine's package set was already tiny. Runs non-root **by default**, so non-root arrives here, not in F. Check what ships with the image (signature, SBOM, provenance) in Bonus A. |
| **F** | Hardened runtime | **No image change.** Run flags only | `docker run` flags (see Section 10b) | (same as E) | (same as E) | Patched | Go 1.27.3 (same image as E; F image ID not captured) | 65532 | `hello:f-hardened` (same image as E), `evidence/F.runtime.txt` | Zero change in CVE counts expected (same image as E). What changes: read-only filesystem, no capabilities, `no-new-privileges`, pids/memory/CPU limits, `GIN_MODE=release`. Evidence comes from `/proc`. |

**Optional side-by-sides (not part of A to F; delete any you skip):**

| ID | Step | The ONE change vs. E | Dockerfile + build args | Runtime base | Image tag / evidence | Comments |
|---|---|---|---|---|---|---|
| **Ealt** | Google distroless runtime | Chainguard `static` to Google `distroless/static` | `Dockerfile.multi`, `RUNTIME_IMAGE=gcr.io/distroless/static-debian12` | `distroless/static` (not built; digest N/A) | `hello:ealt-google-distroless`, `evidence/Ealt.*` | Debian-based, free, widely used. Evidence for the "we already use distroless" objection. Its default tag runs as root (the `:nonroot` tag runs as 65532): say which you used. |
| **Ebuild** | Chainguard builder too | Builder `golang` to `cgr.dev/<org>/go` | `BUILD_IMAGE=cgr.dev/<org>/go:latest` | `cgr.dev/<org>/static` | `hello:ebuild-chainguard-builder`, `evidence/Ebuild.*` | Shows that migration is mostly `FROM` lines. Record the Go version it ships; it may differ from step C's. |
| **Eapko** | melange + apko build (Bonus C) | No Dockerfile; image assembled by apko from Wolfi packages | `chainguard-way/*.yaml` | Wolfi packages | `hello:eapko-melange`, `evidence/Eapko.*` | Chainguard's own open source tooling, done by hand. |

**How to read the deltas:** A to B isolates **image composition**. B to C isolates the **Go compiler**. C to D isolates the **application dependencies**. D to E isolates the **runtime base** (Alpine vs. Chainguard "distroless", plus its non-root default). E to F isolates **runtime hardening** (expected to change no CVE counts). Ealt vs. E (if done) isolates **Google distroless vs. Chainguard**. Present these effects separately.

**Step A base facts (recorded):** `golang:1.18` resolved to `go1.18.10 linux/arm64` on Debian GNU/Linux 11 (bullseye). Tag digest: `golang@sha256:50c889275d26f816b5314fc99f55425fa76b18fcaf16af255f5d57f09e1f48da` (multi-arch index digest; the arm64 image beneath it has its own digest).

### 2b. Hypotheses (write these BEFORE scanning each step) and outcomes

| Step | My hypothesis (written before the scan) | What actually happened | Did it hold? Why / why not? |
|---|---|---|---|
| A | Huge image, hundreds of OS-package findings, plus app and stdlib findings | Image 1,486.5 MB, 11 layers, 259 packages (201 deb), runs as root. Grype: 2,341 findings (106 Critical, 647 High): 1,823 OS (deb), 383 stdlib, 17 modules, 118 on the `go` toolchain binary. Trivy: 14,144 findings (139 Critical, 2,733 High). | Yes, and stronger than "hundreds": thousands. Caveat: 324 of the 383 Grype stdlib findings sit on the Go toolchain binaries in `/usr/local/go`, not on `hello-server` (59). Trivy scans 20 Go binaries in the image and repeats stdlib CVEs on each (2,060 stdlib findings, 103 of them on `hello-server`). Counts are findings, not risk. |
| B | OS findings and size collapse; module and stdlib findings unchanged | Size 1,486.5 MB to 28.4 MB (2 layers). Grype 2,341 to 79: OS 1,823 to 3, modules 17 to 17, stdlib 383 to 59, `go` binary 118 to 0. Trivy 14,144 to 166 (OS 12,021 to 0; modules 63; stdlib 2,060 to 103). | Mostly. OS and size collapsed and module findings were unchanged. "stdlib unchanged" held for the application binary (59 findings on `/app/hello-server` in A and 59 in B, identical IDs) but the bucket fell 383 to 59 because the builder's Go toolchain binaries are no longer shipped. New at B: busybox, busybox-binsh and ssl_client (3 findings, 1 CVE, CVE-2025-60876, no fix). Trivy reports 0 Alpine findings, so the scanners disagree on the OS layer. |
| C | stdlib findings drop sharply; nothing else moves | Go 1.18.10 to 1.27.3. Grype 79 to 19: stdlib 59 to 0, modules 17 to 16, OS 3 to 3. Trivy 166 to 63: stdlib 103 to 0, modules 63 to 63. Size 28.4 to 31.6 MB. The build succeeded with the old dependencies (cold 50 s). | Yes for stdlib (0 in both scanners). One unexpected move: Grype lost one module finding (`GHSA-ppp9-7jff-5vj2`, golang.org/x/text v0.3.6) although the module version is unchanged; I cannot explain it from the evidence. Trivy's module count did not move. |
| D | Module findings drop; the `go` line rises; some findings may be new | Gin v1.8.1 to v1.12.0; `go` line 1.18 to 1.26.10. Grype 19 to 3 (modules 16 to 0, OS 3 to 3), Critical+High 10 to 0. Trivy 63 to 1 (one UNKNOWN advisory on `golang.org/x/crypto` v0.58.0). Size 31.6 to 44.3 MB. No new findings (computed; `diff-C-D.new.tsv` is also empty). | Yes. Module findings went to 0 in Grype and the `go` line rose by eight minor versions. Not predicted: the image grew by 12.7 MB because the binary now embeds more modules (quic-go, sonic, mongo-driver in `D.buildinfo.txt`; Syft packages 33 to 37). |
| E | Small change in counts (Alpine's package set was already tiny); shell and package manager gone; runs non-root by default | Grype 3 to 0 (the 3 busybox findings, 1 CVE); Trivy 1 to 1 (same x/crypto advisory). Size 44.3 to 35.8 MB, 3 layers, OS packages 16 to 5, total packages 37 to 26, `shell_present: no`, user `65532`; no `apk-tools` in Syft. Runtime: Uid 65532, HTTP 200. | Yes: the count change is small (3 Grype findings, 0 for Trivy) because D was already near zero; the larger E differences are structural (no shell, no package manager, non-root). E changed two things (base and default user), so the user change cannot be separated from the base change in this data. Grype reporting 0 is a statement about this scanner and database, not about the absence of vulnerabilities. |
| F | Zero change in CVE counts; large change in privileges (read-only, no capabilities, no-new-privileges) | No F scan and no F image ID were captured, so F's counts are E's by assumption. Kernel view (`F.runtime.txt` vs `E.runtime.txt`): CapBnd `00000000a80425fb` to `0000000000000000`, NoNewPrivs 0 to 1, ReadonlyRootfs false to true, Memory 128 MiB, PidsLimit 100, NanoCpus 500000000; CapEff was already 0 at E; HTTP 200 `Hello World!` still returned. | Privilege part: yes, measured. Count part: expected but not independently verified (no `docker image inspect` ID for `hello:f-hardened`). |

---

## 3. Image properties

F uses the same image as E. Fill F as "= E" where the property is a property of the image.

| Metric | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| Image ID / registry digest (`sha256:...`) | `sha256:f99506e782255b3f575229e89d4202e12e0df50237f3869321fb0c68b06c8edd` | `sha256:99f356dca086597f94484bcdcb0e94cf3b3334ac8b7d93fbea11b03b6dc0a9f6` | `sha256:4d888563e7ea724b03924c6114bdbc0f9a9641c4de0b9428281de1379e1a8e0d` | `sha256:3f729573193bf10920d73d5602224b70cfeb165482dde922d9259e309e391637` | `sha256:18508429b30f42828661aa9c6788716f6a4c5e399b73515ea979a0461214e795` | = E (verify equal; F image ID not captured) |
| Image size (MB) | 1486.5 | 28.4 | 31.6 | 44.3 | 35.8 | = E |
| Layer count | 11 | 2 | 2 | 2 | 3 | = E |
| OS package count (Syft, deb/apk/rpm) | 201 (deb) | 16 (apk) | 16 (apk) | 16 (apk) | 5 (apk) | = E |
| Total package count (Syft, all types) | 259 | 33 | 33 | 37 | 26 | = E |
| Go version embedded in binary (`go version -m`) | go1.18.10 | go1.18.10 | go1.27.3 | go1.27.3 | go1.27.3 | = E |
| Runs as (user:uid), image default | root (`user` empty) | root | root | root | 65532 | = E (flags add no change to user) |
| Shell present? (Y/N) | Y | Y | Y | Y | N | = E |
| Package manager present? (Y/N) | Y (apt/dpkg) | Y (apk-tools 3.0.8-r0) | Y (apk-tools) | Y (apk-tools) | N (no package manager in Syft) | = E |
| Compiler/toolchain present? (Y/N) | Y (Go 1.18.10, gcc) | N | N | N | N | = E |
| Source code present? (Y/N) | Y (`COPY . .` into `/app`) | N | N | N | N | = E |
| Entrypoint form (exec / shell) | exec (`CMD ["/app/hello-server"]`) | exec (`ENTRYPOINT ["/hello-server"]`) | exec | exec | exec | = E |
| Build time, cold (s) | 12 | 10 | 50 | 19 | 19 | n/a |
| Build time, warm cache (s) | 0 | 1 | 0 | 1 | 0 | n/a |
| Pull time (s) | Not measured | Not measured | Not measured | Not measured | Not measured | n/a |
| Libc | libc6 (glibc) | musl | musl | musl | none reported by Syft (static binary; only `glibc-2.44-locale-posix` locale data is listed) | = E |

Source: `evidence/<ID>.props.txt`, `evidence/<ID>.build.txt`, `evidence/<ID>.buildinfo.txt`, `evidence/<ID>.syft.json` (package types). Size = `size_bytes` / 1,000,000 (decimal MB). IDs are local image IDs (not registry digests); builds used `--provenance=false`. The package-manager, compiler and source rows are inferred from the Syft package list and the Dockerfiles, not from running the image (confirm with the command below). F is the same image as E by construction, but `hello:f-hardened` was not inspected, so equality is not verified. One run per step on arm64; cold build times (12, 10, 50, 19, 19 s) depend on cache state (the 50 s at C includes a new builder image) and are indicative only. D is 12.7 MB larger than C because the binary embeds more modules. Manual checks (package manager, compiler, source present) use `docker run --rm --entrypoint sh <image> -c 'command -v apt-get apk go gcc; ls /app'`; an error means no shell.

---

## 4. Scan metadata (fill once per scan run)

Re-scan every step the same day (`scripts/rescan-all.sh`) before reporting comparisons. F reuses E's scan because the image is identical.

| Scan ID | Step | Scanner | Scanner version | DB build date | Exact command | Raw output file |
|---|---|---|---|---|---|---|
| A-G | A | Grype | 0.121.0 | 2026-11-01T06:20:12Z (scan 2026-11-01T17:35:10Z) | `grype hello:a-baseline -o json` | `evidence/A.grype.json` |
| A-T | A | Trivy | 0.76.1 | Not recorded: `A.scan-meta.txt` has no DB lines (scan 2026-11-01T17:35:10Z) | `trivy image --quiet --format json --output evidence/A.trivy.json hello:a-baseline` | `evidence/A.trivy.json` |
| B-G | B | Grype | 0.121.0 | 2026-11-01T06:20:12Z (scan 2026-11-01T17:59:39Z) | `grype hello:b-multistage -o json` | `evidence/B.grype.json` |
| B-T | B | Trivy | 0.76.1 | 2026-11-01 13:02:34 UTC (DB UpdatedAt) | `trivy image --quiet --format json --output evidence/B.trivy.json hello:b-multistage` | `evidence/B.trivy.json` |
| C-G | C | Grype | 0.121.0 | 2026-11-01T06:20:12Z (scan 2026-11-01T18:18:28Z) | `grype hello:c-go-updated -o json` | `evidence/C.grype.json` |
| C-T | C | Trivy | 0.76.1 | 2026-11-01 13:02:34 UTC | `trivy image --quiet --format json --output evidence/C.trivy.json hello:c-go-updated` | `evidence/C.trivy.json` |
| D-G | D | Grype | 0.121.0 | 2026-11-01T06:20:12Z (scan 2026-11-01T18:27:42Z) | `grype hello:d-mods-bumped -o json` | `evidence/D.grype.json` |
| D-T | D | Trivy | 0.76.1 | 2026-11-01 13:02:34 UTC | `trivy image --quiet --format json --output evidence/D.trivy.json hello:d-mods-bumped` | `evidence/D.trivy.json` |
| E-G | E (= F) | Grype | 0.121.0 | 2026-11-01T06:20:12Z (scan 2026-11-01T18:34:51Z) | `grype hello:e-chainguard -o json` | `evidence/E.grype.json` |
| E-T | E (= F) | Trivy | 0.76.1 | 2026-11-01 13:02:34 UTC | `trivy image --quiet --format json --output evidence/E.trivy.json hello:e-chainguard` | `evidence/E.trivy.json` |

Each scan's tool versions and DB status are saved in `evidence/<ID>.scan-meta.txt`. All five steps were scanned the same day (A 17:35Z, B 17:59Z, C 18:18Z, D 18:27Z, E 18:34Z) with the same Grype DB (schema v6.1.10, built 2026-11-01T06:20:12Z, `Status: valid`), so the Grype comparison is not confounded by database drift. Trivy B to E share one DB (UpdatedAt 2026-11-01 13:02:34 UTC); A's Trivy DB date was not recorded, so the A-to-B Trivy delta cannot be proven to be same-DB (likely, unproven). All `*.log` files are empty (no scanner errors); `db-update.log` files only record DB refreshes. F has no scan of its own. The image identifier in each scan is the local image ID listed in Section 3. Source: `evidence/<ID>.scan-meta.txt`. Side-by-sides (`Ealt`, `Ebuild`, `Eapko`) get their own rows if you build them.

---

## 5. Vulnerability counts

Counts are findings (matches), as produced by `scripts/summarize.sh` (`evidence/ladder.csv`). "Other" = Negligible / Unknown / unrecognized severity.

### 5a. Grype (all findings)

| Severity | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| Critical | 106 | 6 | 1 | 0 | 0 | = E |
| High | 647 | 41 | 9 | 0 | 0 | = E |
| Medium | 656 | 31 | 9 | 3 | 0 | = E |
| Low | 89 | 1 | 0 | 0 | 0 | = E |
| Negligible / Unknown | 843 | 0 | 0 | 0 | 0 | = E |
| **Total** | 2341 | 79 | 19 | 3 | 0 | = E |
| **Fixable (fix available)** | 1108 | 76 | 16 | 0 | 0 | = E |
| **Not fixable** | 1233 | 3 | 3 | 3 | 0 | = E |

### 5b. Trivy (all findings)

| Severity | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| Critical | 139 | 4 | 0 | 0 | 0 | = E |
| High | 2733 | 72 | 32 | 0 | 0 | = E |
| Medium | 8798 | 82 | 27 | 0 | 0 | = E |
| Low | 2427 | 4 | 0 | 0 | 0 | = E |
| Unknown | 47 | 4 | 4 | 1 | 1 | = E |
| **Total** | 14144 | 166 | 63 | 1 | 1 | = E |
| **Fixable** | 7209 | 166 | 63 | 0 | 0 | = E |
| **Not fixable** | 6935 | 0 | 0 | 1 | 1 | = E |

Source for 5a/5b: `evidence/<ID>.grype.json` (unit: each element of `.matches[]`; severity `.vulnerability.severity`; fixable = `.vulnerability.fix.state == "fixed"`) and `evidence/<ID>.trivy.json` (unit: each element of `.Results[].Vulnerabilities[]`; fixable = non-empty `FixedVersion`). Severities sum to the total in every column (checked) and agree with `evidence/ladder.csv`. These are findings, not unique CVEs: one CVE on several packages or binaries counts several times. Unique IDs: Grype A 818, B 73, C 17, D 1, E 0; Trivy A 10,755, B 155, C 63, D 1, E 1. Trivy A status split: 7,209 fixed, 6,603 affected, 215 fix_deferred, 117 will_not_fix. F column = E (same image; no F scan).

### 5c. Scanner discrepancy (the "which one is right?" slide)

| Step | Grype total | Trivy total | Delta | Likely cause (data source, unfixed handling, matching method, binary detection) |
|---|---|---|---|---|
| A | 2341 | 14144 | +11,803 (Trivy 6.0x) | Trivy reports 12,021 OS findings vs. Grype's 1,823 on the same Debian 11 layer, and repeats Go stdlib CVEs on every Go binary it finds (20 binaries: 2,060 stdlib findings vs. Grype's 383). Trivy includes unfixed Debian findings (6,603 `affected`, 215 `fix_deferred`, 117 `will_not_fix`). By CVE ID: 708 in both, 25 only in Grype, 10,047 only in Trivy. Hypothesis (not provable from the files): different Debian data handling (per binary package against the Debian tracker, including unfixed). |
| B | 79 | 166 | +87 | Trivy sees 0 Alpine OS findings; Grype sees 3 (busybox, busybox-binsh, ssl_client, all CVE-2025-60876, no fix). Trivy counts 103 stdlib findings on one binary vs. Grype's 59, and 63 module findings vs. 17. By CVE: 67 in both, 2 only in Grype, 88 only in Trivy. Hypothesis: Trivy matches every module in the binary's buildinfo including `golang.org/x/crypto` (25 findings at C) and `x/sys`, `protobuf`; Grype produced no `x/crypto` match although Syft cataloged it (`C.syft.json`). |
| C | 19 | 63 | +44 | Same pattern: Trivy 63 module findings (x/net 29, x/crypto 25, x/text 4, gin 2, x/sys 2, protobuf 1) vs. Grype 16 (x/net 14, gin 1, x/text 1) plus 3 Alpine. 15 CVEs in both, 2 only in Grype (CVE-2023-44487, CVE-2025-60876), 48 only in Trivy. |
| D | 3 | 1 | -2 | Disjoint: Grype's 3 findings are 1 CVE (CVE-2025-60876, busybox) on 3 Alpine packages; Trivy's 1 is GO-2026-5932 (`x/crypto/openpgp` unmaintained, severity UNKNOWN). No overlap; neither scanner reports the other's item. |
| E | 0 | 1 | +1 | Grype matched nothing (it identifies the distro as `chainguard 20230214` and reports 0 matches, 0 ignored matches); Trivy reports the same single GO-2026-5932 advisory as at D. The Alpine busybox CVE is gone because busybox is not in the image. Both scanners agree there are no CVE-numbered findings with a fix; they disagree only on whether an "unmaintained package" advisory counts. |

Source: `evidence/<ID>.grype.json`, `evidence/<ID>.trivy.json`; overlap computed by mapping Grype GHSA/GO IDs to CVE IDs through `.relatedVulnerabilities[].id`, Trivy IDs as reported. Explanations marked hypothesis are not provable from the files alone. Takeaway: the scanners agree on the broad shape (OS and stdlib collapse, modules persist until D) and disagree on absolute counts by up to 6x at A, so compare within one scanner.

### 5d. The waterfall: what moved at each step (your key slide)

Primary scanner for this table: **Grype** (default; Trivy figures appear in the takeaways as a cross-check). Deltas are from `scripts/diff-steps.sh` and `evidence/ladder.csv`.

| Transition | The one change | Total delta | Critical+High delta | Fixable delta | Bucket that moved (OS / modules / stdlib / none) | One-sentence takeaway |
|---|---|---|---|---|---|---|
| A to B | Multi-stage + alpine runtime | -2262 (2341 to 79) | -706 (753 to 47) | -1032 (1108 to 76) | OS -1820 (1823 to 3); stdlib -324 (383 to 59, toolchain binaries no longer shipped); `go` binary -118; modules 0 | Not shipping the build image removed 97% of Grype findings; this is image composition, not the app. Trivy: -13,978. New: 3 busybox findings (CVE-2025-60876). |
| B to C | Go toolchain updated | -60 (79 to 19) | -37 (47 to 10) | -60 (76 to 16) | stdlib -59 (to 0); modules -1 (unexplained, x/text); OS 0 | One build argument cleared every stdlib finding. Trivy: -103. |
| C to D | Modules bumped | -16 (19 to 3) | -10 (10 to 0) | -16 (16 to 0) | modules -16 (x/net 14, x/text 1, gin 1); OS 0 | Only 3 findings (1 unfixable Alpine CVE) remain. Trivy: -62. |
| D to E | Alpine to Chainguard "distroless" (and non-root default) | -3 (3 to 0) | 0 (0 to 0) | 0 (0 to 0) | OS -3 (busybox, busybox-binsh, ssl_client) | A small count change, as predicted: the residue at D was one unfixable CVE. Trivy: 1 to 1 (unchanged). The structural changes (no shell, no package manager, non-root) are not visible in counts. |
| E to F | Hardened runtime (no image change) | 0 (expected) | 0 (expected) | 0 (expected) | none | Not independently verified: no F scan or F image ID. The kernel evidence shows the privilege change (Section 10b). |
| **A to F (cumulative)** | Everything | -2341 (2341 to 0) | -753 (753 to 0) | -1108 (1108 to 0) | OS -1823, stdlib -383, modules -17, `go` binary -118 | Equals the sum of step deltas (-2262 -60 -16 -3 = -2341). Counted at E; F assumed equal. Trivy A to E: -14,143 (14,144 to 1). |
| Ealt vs. E *(optional)* | Google distroless vs. Chainguard | Not built | Not built | Not built | N/A | Optional; not attempted. |

Source: `evidence/ladder.csv` and `evidence/<ID>.grype.json`, cross-checked against my own unique (vulnerability ID, package) sets: A to B gone 1,968 / still 76 / new 3; B to C gone 60 / still 19 / new 0; C to D gone 16 / still 3 / new 0; D to E gone 3 / still 0 / new 0; A to E gone 2,044 / still 0 / new 0. Note: `diff-D-E.*.tsv` are all empty, which is wrong (3 should be "gone"): `scripts/diff-steps.sh` uses `NR==FNR` in awk, which misbehaves when the second (target) file is empty (E has 0 matches); and its key is the CVE id only, so counts can differ by one from mine at A to B. Attribution is order-dependent: each delta is measured given the steps before it; the cumulative total is not.

---

## 6. Findings by source (where do the CVEs come from?)

This table is the most important one. It shows that **the base image, the dependencies, and the compiler are three different problems**, each fixed by a different step.

| Source category | A | B | C | D | E | F | Fixed by | Step that should move it |
|---|---|---|---|---|---|---|---|---|
| OS packages (base image) | 1823 | 3 | 3 | 3 | 0 | = E | Changing base image | B, E |
| Go modules (Gin and transitive dependencies) | 17 | 17 | 16 | 0 | 0 | = E | `go get` / `go mod tidy` | D |
| Go stdlib (compiled in, from the builder's Go version) | 383 | 59 | 0 | 0 | 0 | = E | Updating Go in the builder | C |
| Other (binaries, misc.) | 118 | 0 | 0 | 0 | 0 | = E | The Go toolchain binary (`go` 1.18.10) matched as a `binary` artifact; only in A | |
| **Total** | 2341 | 79 | 19 | 3 | 0 | = E | | |

Scanner used: **Grype** (primary). Buckets computed directly from `evidence/<ID>.grype.json`: OS = `artifact.type` in {apk, deb, rpm}; stdlib = `artifact.name == "stdlib"`; modules = other `go-module`; other = everything else. This differs from `evidence/ladder.csv` only at A, where `ladder.csv` reports `go_modules` = 135 because it folds in the 118 `go` binary findings (135 = 17 + 118); B to E agree. Trivy buckets (OS / modules / stdlib): A 12,021 / 63 / 2,060; B 0 / 63 / 103; C 0 / 63 / 0; D 0 / 1 / 0; E 0 / 1 / 0. Of A's 383 Grype stdlib findings, 59 are on `/app/hello-server` and 324 on the Go toolchain binaries under `/usr/local/go` (by artifact location). The buckets moved where predicted (OS at B and E, stdlib at C, modules at D); the surprises are that stdlib also fell at B (toolchain not shipped) and that the OS bucket was not zero at B to D because Alpine's busybox carries one unfixed CVE. Source: `evidence/<ID>.grype.json`.

---

## 7. Reachability (govulncheck)

Important: **source mode** analyzes your code and `go.mod` using *the Go toolchain installed in the VM* (the latest), so it will not show old stdlib problems. **Binary mode** reads the Go version and modules embedded in *the binary extracted from each image*, so it shows what was actually shipped. State which you are quoting.

| Target | Mode | Vulnerabilities found | Reachable (called by code) | Present but not called | Evidence file |
|---|---|---|---|---|---|
| Source, original deps (A state) | `govulncheck ./...` | 63 (11 + 8 + 44) | 11 (all `golang.org/x/net`) | 52 (8 in imported packages, 44 in required modules) | `evidence/A.govulncheck-source.txt` |
| Binary A (Go 1.18, original deps) | `-mode=binary` | 148 (61 + 32 + 55) | 61 (about 48 stdlib, 12 x/net, 1 x/text; "from 2 modules and the Go standard library") | 87 (32 imported packages, 55 required modules) | `evidence/A.govulncheck-binary.txt` |
| Binary B (Go 1.18, original deps, alpine) | `-mode=binary` | 148 (61 + 32 + 55) | 61 | 87 | `evidence/B.govulncheck-binary.txt` (byte-identical to A's: same binary) |
| Binary C (new Go, original deps) | `-mode=binary` | 61 (11 + 8 + 42) | 11 (all `golang.org/x/net`, no stdlib) | 50 (8 imported packages, 42 required modules) | `evidence/C.govulncheck-binary.txt` |
| Binary D (new Go, patched deps) | `-mode=binary` | 1 (0 + 0 + 1) | 0 | 1 (in a required module) | `evidence/D.govulncheck-binary.txt` |
| Binary E (Chainguard static, patched deps) | `-mode=binary` | 1 (0 + 0 + 1) | 0 | 1 (in a required module) | `evidence/E.govulncheck-binary.txt` (same text as D's; same module list) |
| Source, patched deps (D state) | `govulncheck ./...` | 1 (0 + 0 + 1) | 0 | 1 (in a required module) | `evidence/D.govulncheck-source.txt` |

**My prediction (written before running):** this app uses only `gin.Default()`, one `GET` route, and `c.String(...)`, so most module-level findings (SSH, protobuf, YAML, TOML) are present but not called; reachable ones are more likely in `net/http` and `x/net`. **Did it hold? Partly.** Present-but-not-called dominates as predicted (87 of 148 at A binary, 50 of 61 at C, the only remaining item at D and E), and the reachable module findings are in `x/net` HTTP/2 as guessed (all 11 reachable module findings at C are `x/net`, reached through `gin.Engine.Run`). Not predicted: the reachable count is not small (61 in the A binary, 11 at C) and `x/text` (`language.Parse`) is also reachable at A. Reachability is call-graph based and the traces run through HTTP/2 error-string methods (for example `http2.ConnectionError.Error`), so "reachable" means a vulnerable symbol is on a call path, not that an attacker can exploit it through this one route. After D and E: 0 reachable. Which advisory the remaining 1 is was not printed (`-show verbose` would show it); it may be Trivy's GO-2026-5932 (unconfirmed).

Key insight to state: "N findings in the scanner, M of them reachable from my code." From the data: at A (binary mode) 61 of 148 govulncheck advisories are reachable; at C, 11 of 61; at D and E, 0 of 1. govulncheck counts OSV advisories, not Grype findings, so do not equate the numbers.

Source: `evidence/{A,B,C,D,E}.govulncheck-binary.txt`, `evidence/{A,D}.govulncheck-source.txt`; counts quoted from the summary sentences ("Your code is affected by N vulnerabilities" / "also found P ... and Q ..."); "found" = N + P + Q (my sum). Source mode uses the VM's Go 1.27.3 and shows no stdlib findings; A's stdlib findings come from binary mode only. The A split (12 x/net, 1 x/text, stdlib by subtraction) is from the `Module:` lines.

---

## 8. Remediation log (one entry per step)

### 8a. Changes

| # | Step | Change (exact command or flag) | Why | Bucket addressed (OS / modules / stdlib / privileges) | Breaking change? | How I verified (`curl` returns `Hello World!`) | Time spent |
|---|---|---|---|---|---|---|---|
| 1 | B | Multi-stage `Dockerfile.multi`, `RUNTIME_IMAGE=alpine:3`: `docker build --provenance=false -f docker/Dockerfile.multi -t hello:b-multistage --build-arg GO_VERSION=1.18 --build-arg RUNTIME_IMAGE=alpine:3 go/` (commit `75d491c`) | Stop shipping the toolchain, source, and Debian userland | OS | No build failure in evidence or git history | `B.props.txt` (28.4 MB, 2 layers), B scans; the per-step `curl` output is not in `evidence/` | ~12 min (estimate from git timestamps: 17:53:10 to 18:05:34, includes scans) |
| 2 | C | `GO_VERSION=1.27.3` in the builder: `docker build --provenance=false -f docker/Dockerfile.multi -t hello:c-go-updated --build-arg GO_VERSION=1.27.3 --build-arg RUNTIME_IMAGE=alpine:3 go/` (commit `a6ff36e`) | stdlib CVEs are compiled into the binary | stdlib | No: built with the old dependencies (cold build 50 s) | `C.buildinfo.txt` shows go1.27.3; Grype stdlib 59 to 0 | ~16 min (estimate from git timestamps: 18:05:34 to 18:21:13) |
| 3 | D-a | `go get github.com/gin-gonic/gin@v1.12.0` (commit `cdfbe23`; `go` line became 1.25.0) | Gin v1.8.1 carries GHSA-3vp4-m3rf-835h (fixed in 1.9.0) and pulls old transitive modules | modules | No build failure recorded; no tests to detect behavioural change | D-a was not built or scanned on its own in evidence | ~2 min (estimate from git timestamps) |
| 4 | D-b | `go get -u ./...` and `go mod tidy` (commit `05df4b0`, message "update all dependencies"; `go` line became 1.26.10); the exact commands are not in `evidence/` | Transitive modules | modules | No build failure recorded; image grew 31.6 to 44.3 MB | `D.buildinfo.txt` (Gin v1.12.0, x/net v0.62.0, x/crypto v0.58.0, x/text v0.43.0); Grype modules 16 to 0; govulncheck 0 reachable | ~1.5 min for D-b, ~4 min to the D evidence commit (estimate from git timestamps) |
| 5 | E | `docker build --provenance=false -f docker/Dockerfile.multi -t hello:e-chainguard --build-arg GO_VERSION=1.27.3 --build-arg RUNTIME_IMAGE=cgr.dev/checkmarx.com/static:latest go/` (commit `85fee63`) | Remove shell and package manager; vendor-maintained base; non-root default | OS / attack surface | No: no code change; HTTP 200 `Hello World!` as UID 65532 (`E.runtime.txt`) | `E.runtime.txt` (endpoint, Uid 65532, shell exec fails), E scans (Grype 0, Trivy 1) | ~11 min (estimate from git timestamps: 18:28:57 to 18:40:01) |
| 6 | F | `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=100 --memory=128m --cpus=0.5 -e GIN_MODE=release` (`F.runtime.txt`; commit `aef4ea7`) | Limit blast radius | privileges | No: endpoint still returns HTTP 200 `Hello World!` under all flags | `F.runtime.txt`: `ReadonlyRootfs=true`, `CapBnd 0000000000000000`, `NoNewPrivs 1` | ~10 min (estimate from git timestamps: 18:40:01 to 18:49:53) |

Go line in `go.mod` before / after step D: 1.18 / 1.26.10 (D-a: 1.25.0). Did a dependency update force a toolchain update? The `go` line now requires Go 1.26.10 or newer, so a 1.18 builder cannot build D (inferred; not tested). Because step C had already moved the builder to 1.27.3 (and the Dockerfile sets `GOTOOLCHAIN=local`), no additional builder change was needed. Order-dependent attribution: had D come before C, the module bump would have forced the toolchain bump. There are no `step-*` git tags in this clone (`git tag` is empty), so commits are cited instead.

Source: `git log`, `git diff a6ff36e 64db612 -- go/go.mod`, `evidence/<ID>.build.txt`, `evidence/{E,F}.runtime.txt`. Times are estimates from commit timestamps and include scanning; A's scan (17:35Z) precedes its commit (17:53Z), so A is not estimable.

### 8b. CVE diff per transition (source: `scripts/diff-steps.sh`, Grype)

| Transition | Gone | Still present | New | Top "gone" packages (name, count) | Why they went away |
|---|---|---|---|---|---|
| A to B | 1,968 | 76 | 3 | `go` (118), binutils family (96 each across 6 packages: binutils, binutils-common, binutils-aarch64-linux-gnu, libbinutils, libctf0, libctf-nobfd0), libpython3.9 (70 each) | The Debian userland and the Go toolchain were not carried into the Alpine runtime; 27 stdlib IDs that matched only the toolchain binaries also went. New: CVE-2025-60876 on busybox, busybox-binsh, ssl_client. |
| B to C | 60 | 19 | 0 | stdlib (59), golang.org/x/text (1) | Newer Go compiled into the binary; the x/text disappearance is unexplained. |
| C to D | 16 | 3 | 0 | golang.org/x/net (14), golang.org/x/text (1), github.com/gin-gonic/gin (1) | Gin v1.12.0 and updated transitive modules (x/net v0.62.0, x/text v0.43.0). |
| D to E | 3 | 0 | 0 | busybox, busybox-binsh, ssl_client (1 each, CVE-2025-60876) | Busybox is not in the Chainguard `static` image. Computed by me from the Grype JSON; the repo's `diff-D-E.*.tsv` are empty because of a script bug (see note below). |
| Ealt vs. E *(optional)* | Not built | Not built | Not built | N/A | Optional; not attempted. |

Source: computed from `evidence/<ID>.grype.json` using unique (vulnerability ID, package name) keys; agrees with `evidence/diff-*.tsv` except D to E (see the note under 5d). Units are unique keys, not raw findings (A: 2,341 findings, 2,044 unique keys).

### 8c. Notable CVEs (what disappeared, and why)

| CVE ID | Package | Severity | In step | Gone in step | Reason it went away |
|---|---|---|---|---|---|
| CVE-2026-78663 (GO-2026-6612) | `stdlib` and `golang.org/x/net` (HTTP/2 flow-control double refund) | Critical | A, B (stdlib and x/net); C (x/net) | C for stdlib; D for x/net | stdlib copy fixed by Go 1.27.3; x/net copy fixed by x/net v0.62.0. Reachable per govulncheck at A and C. The only Critical still present at C. |
| CVE-2023-24538, CVE-2023-24540, CVE-2025-22871, CVE-2025-68121 (GO-2023-1703, GO-2023-1752, GO-2025-3563, GO-2026-4337) | `stdlib` | Critical | A, B | C | Go 1.18.10 stdlib; fixed in newer Go. Four of the five stdlib Criticals at B (the fifth is GO-2026-6612). |
| CVE-2026-78659, CVE-2026-78669, CVE-2026-97032 (GO-2026-6603, -6611, -6617) | `golang.org/x/net` | High | A, B, C | D | HTTP/2 issues; reachable via `gin.Engine.Run` at A and C (govulncheck). Fixed in x/net v0.60.0+ (D has v0.62.0). |
| CVE-2023-26125 (GHSA-3vp4-m3rf-835h) | `github.com/gin-gonic/gin` v1.8.1 | Medium | A, B, C | D | Fixed in Gin 1.9.0; bumped to 1.12.0. The only finding on the application's direct dependency. |
| CVE-2023-44487 (GHSA-qppj-fm5r-hxr3, HTTP/2 rapid reset) | `golang.org/x/net` | Medium | A, B, C | D | Fixed in x/net 0.17.0. One of the two CVEs Grype reports at C that Trivy does not. |
| CVE-2023-38545 | `curl`, `libcurl3-gnutls`, `libcurl4` | Critical | A | B | Debian userland not shipped in the Alpine runtime (83 unique Critical keys disappear at B). |
| CVE-2025-60876 | `busybox`, `busybox-binsh`, `ssl_client` | Medium | B, C, D | E | **New at B** (appears only with the Alpine runtime), no fix available, gone only when the base changed to Chainguard `static` (no busybox). Trivy never reported it. |
| GHSA-ppp9-7jff-5vj2 (CVE-2021-38561) | `golang.org/x/text` v0.3.6 | High | A, B | C | Unexpected: gone at C with the module version unchanged. Cause unknown from the evidence (hypothesis: a matching rule tied to toolchain-embedded buildinfo; not proven). |
| GO-2026-5932 | `golang.org/x/crypto` v0.58.0 (openpgp unmaintained) | Unknown (Trivy only) | D, E | Not gone (still at E) | An advisory about an unmaintained package, not a CVE with a fix; Grype does not report it. |

"New" findings after a step are normal (new transitive modules, database changes). Explain them; do not hide them.

---

## 9. Remaining findings: disposition

Dispositioned at the final image (E). Every remaining finding gets an explicit decision. A dispositioned list is stronger than a claim of "zero."

All dispositions below are **proposed, for the user's review**. At E, Grype reports 0 findings and Trivy reports 1.

| CVE ID | Package | Severity | Scanner(s) | Fix available? | Reachable? | Disposition | Rationale |
|---|---|---|---|---|---|---|---|
| GO-2026-5932 | `golang.org/x/crypto` v0.58.0 (`openpgp` package unmaintained) | Unknown (Trivy) | Trivy only | No (status `affected`, no fixed version) | govulncheck E reports 1 not-called vulnerability in a required module (unconfirmed to be this one) | Accept (proposed) | Advisory about an unmaintained sub-package, not an exploitable CVE; nothing in this app uses `openpgp` (not independently shown). Revisit if code starts using PGP. |

Context: the only residue at D, CVE-2025-60876 on busybox (3 Grype findings, no fix), is not present at E, so it needs no disposition at the final image.

---

## 10. Deployment and runtime validation

### 10a. Functional checks (final image, hardened: step F)

| Check | Command | Result | Pass/Fail |
|---|---|---|---|
| Container starts | `docker run -d ...` | Process running (host PID 24317 in `F.runtime.txt`) with F flags | Pass |
| Endpoint responds (`GET /` returns `Hello World!`, HTTP 200) | `curl -i http://localhost:8080/` | `HTTP 200`, body `Hello World!` (F, E and A) | Pass |
| Runs as non-root | `docker inspect --format '{{.Config.User}}' <name>` and `/proc` Uid | configured user `'65532'`; `Uid: 65532 65532 65532 65532` (F) | Pass |
| Read-only root FS works | `--read-only` (write test shown on B, which has a shell) | `ReadonlyRootfs=true`; app still serves HTTP 200. The B write test is not in evidence. | Pass (app works read-only); write-denied test not captured |
| All caps dropped | `--cap-drop=ALL`; `/proc` CapBnd | `CapDrop=[ALL]`; `CapBnd: 0000000000000000` | Pass |
| no-new-privileges | `--security-opt=no-new-privileges:true`; `/proc` NoNewPrivs | `SecurityOpt=[no-new-privileges:true]`; `NoNewPrivs: 1` | Pass |
| Graceful stop (SIGTERM, time to stop) | `time docker stop <name>` | `real 0m0.131s` (F); E 0.152 s; A 0.125 s (single run each) | Pass |
| Shell absent (expected on E and F) | `docker exec <name> sh` | `exec: "sh": executable file not found in $PATH` on E and F | Pass |
| Gin in release mode | `-e GIN_MODE=release`; no debug warning in logs | Flag was passed (`F.runtime.txt`); container logs were not captured | Not verified |

Source: `evidence/F.runtime.txt` (and `E.runtime.txt`). All checks were run once on one date (2026-11-01).

### 10b. Runtime security profile (measured from the VM's kernel, `scripts/runtime-profile.sh`)

| Property | A default run | E default run | F hardened |
|---|---|---|---|
| `Uid` (from `/proc/<pid>/status`) | 0 | 65532 | 65532 |
| `CapEff` (effective capabilities) | `00000000a80425fb` | `0000000000000000` | `0000000000000000` |
| `CapBnd` (bounding set: the ceiling) | `00000000a80425fb` | `00000000a80425fb` | `0000000000000000` |
| `NoNewPrivs` | 0 | 0 | 1 |
| `Seccomp` | 2 | 2 | 2 |
| ReadonlyRootfs | false | false | true |
| Memory / PidsLimit / NanoCpus | 0 / `<no value>` / 0 (no limits) | 0 / `<no value>` / 0 (no limits) | 134217728 (128 MiB) / 100 / 500000000 (0.5 CPU) |
| Shell exec attempt | "shell works" | fails: `"sh": executable file not found in $PATH` | fails (same message) |
| Time to stop (s) | 0.125 | 0.152 | 0.131 |
| Endpoint response | HTTP 200, `Hello World!` | HTTP 200, `Hello World!` | HTTP 200, `Hello World!` |

Evidence: `evidence/A.runtime.txt`, `E.runtime.txt`, `F.runtime.txt`. Reading tip: a non-root process already has `CapEff = 0` (so E and F match there); look at `CapBnd` and `NoNewPrivs` to see what the hardening flags added on top of E. Observed: A runs as root with CapEff = CapBnd = `a80425fb` (Docker's default set, inferred); E is non-root with CapEff 0 but still the same CapBnd; F adds CapBnd 0 and NoNewPrivs 1 and a read-only root, as expected, and no deviation from the expected pattern was found. Seccomp is 2 (filter mode) in all three. Stop times are single runs of about 0.13 to 0.15 s. Key sentence to state: "Hardening changed **zero** CVE counts (F is the same image as E). It changed exploitability and blast radius, and this is the kernel evidence."

---

## 11. Bonus: supply chain (if attempted)

| Item | Step/image | Tool | Result | Evidence |
|---|---|---|---|---|
| SBOM generated (SPDX / CycloneDX) | A, E | Syft | Not attempted (no `evidence/sbom/`; Syft JSON for A to E exists only as scan input) | `evidence/<ID>.syft.json` |
| SBOM scanned (`grype sbom:`) | | | Count matches image scan? | |
| Local registry running | | `registry:2` | | |
| Image pushed, digest recorded | | | | |
| Image signed (by digest) | | cosign | | |
| Signature verified | | cosign | | |
| **Failure demo** (unsigned image fails verification) | | cosign | | |
| SBOM attached as signed attestation | | cosign | | |
| Chainguard-provided signature/SBOM verified | E base | cosign | | |
| Build-time SBOM (apko) vs. reconstructed SBOM (Syft) differences | Eapko | apko / Syft | | |

## 12. Bonus: Kubernetes (if attempted)

| Item | Result |
|---|---|
| Cluster (kind/minikube) and version | Not attempted |
| Manifest security context (non-root, RO FS, drop ALL, seccomp RuntimeDefault, `GIN_MODE=release`) | |
| Deployment healthy | |
| Service reachable (port-forward) | |
| Debug via `kubectl debug` ephemeral container (no shell in image) | |
| Policy enforcement (e.g. block unsigned) | |

## 12b. Bonus: Chainguard-native build with melange + apko (if attempted)

| Item | Result |
|---|---|
| Tool versions (melange, apko) and where I got them | Not attempted |
| Time to get the 12-line app building | |
| Image comparison vs. D and E (findings, size, packages) | |
| Differences between apko's build-time SBOM and Syft's reconstructed SBOM | |
| Reproducibility check (same inputs, same digest?) | |
| What this did *not* give me that the Factory does (continuous rebuilds, tests, SLA, provenance) | |

---

## 13. Friction log (raw material for "production challenges")

Every problem you hit is a discovery question for a real customer.

| # | What happened | Time lost | Root cause | Customer discovery question it suggests |
|---|---|---|---|---|
| 1 | Docker apt repo file `/etc/apt/sources.list.d/docker.list` was emptied (ran `sudo tee` alone, then Ctrl+C), so `apt` reported "no installation candidate" for `docker-ce` | TBD (user) | A pipeline run in two parts | "How do you verify that a package repository is configured and signed correctly before an install runs in your build pipeline?" |
| 2 | `git clone` over SSH from the VM failed with `Permission denied (publickey)` | TBD (user) | SSH agent was not forwarded into the VM | "How do your build agents authenticate to source control, and where do their keys live?" |
| 3 | `docker build` failed with "the Dockerfile cannot be empty" | TBD (user) | Editor buffer was unsaved | "How do you ensure what's in Git is exactly what the build reads?" |
| 4 | The first `scripts/step.sh` stopped silently after printing `==> [A] scans` | TBD (user) | `grype db status` returns non-zero before the vulnerability DB exists and strict shell mode aborted with no message; a failing scanner looks like a clean scan | "How do you know your scan pipeline actually ran, and what alerts you when a scanner returns nothing?" |
| 5 | BuildKit attached a provenance attestation by default, so the image digest changed on every rebuild even for identical images | TBD (user) | Default provenance attestation; fixed with `--provenance=false` (present in every `build.txt` command) | "Which digest do you pin, and how do you keep it stable across rebuilds?" |
| 6 | `curl` seemed to return no body | TBD (user) | The app sends no trailing newline, so `Hello World!` ran into the prompt (observability note only) | "How do you verify a service's response in a pipeline, beyond a status code?" |
| 7 | Scanners disagree widely: Trivy 14,144 vs. Grype 2,341 at A; at D Grype 3 and Trivy 1 with no overlap; at E Grype 0 and Trivy 1 | None recorded | Different data sources, unfixed handling and matching (Section 5c) | "Which scanner is the source of truth for audits, and how do you reconcile two scanners that disagree?" |
| 8 | The Trivy scan of A recorded no DB date (`A.scan-meta.txt` ends at the version line) unlike B to E | None recorded | Scan metadata capture gap in the first run | "How do you record which vulnerability DB version a given scan result came from?" |
| 9 | The Gin bump raised the `go` line 1.18 to 1.25.0 (D-a) and 1.26.10 (D-b) | ~6 min between D-a and the D evidence commit (estimate from git timestamps) | A module upgrade changes the minimum language version | "When a dependency bump forces a language-version bump, who approves it and how is the builder image kept in sync?" |
| 10 | No tests exist; the bumps at C and D were checked only by "it builds" and `curl` | N/A | The challenge app has no test suite | "What proves a base-image or dependency bump did not break the app before it merges?" |
| 11 | Step C: Go 1.27.3 built the 2021-2022 dependencies with no error (cold build 50 s); no friction here | N/A | N/A (a non-event worth stating) | "How often do toolchain bumps fail on your oldest services?" |
| 12 | Image size grew with each bump: 28.4 MB (B), 31.6 MB (C), 44.3 MB (D) | N/A | New Go runtime and a much larger dependency set (quic-go, sonic, mongo-driver now in the binary) | "Who owns the size and attack-surface impact of dependency bumps?" |
| 13 | `alpine:3`, `golang:1.27.3` and `cgr.dev/checkmarx.com/static:latest` are tags; no digests were captured | N/A | Tag movement over time (Alpine resolved to 3.24.3 on the scan day) | "Do you pin base images by digest, and how do you refresh them?" |
| 14 | No `step-A` to `step-F` or `ladder-complete` git tags exist in this clone (`git tag` is empty) | N/A | Tags not created or not pushed | "How do you tie a deployed image back to the exact commit that built it?" |
| 15 | `scripts/diff-steps.sh` produced empty `diff-D-E.*.tsv` (3 findings should be "gone") because E has no matches and its awk `NR==FNR` idiom fails on an empty second file | None recorded | A tooling edge case: the output looked like "nothing changed" | "How does your pipeline tell an empty result from a failed comparison?" |
| 16 | Access to the Chainguard image worked (build used `cgr.dev/checkmarx.com/static:latest`); no friction recorded in evidence | N/A | N/A | "How does your team authenticate to a private registry in CI, and how is access revoked?" |

Candidate themes: a newer Go failed to build or link the old dependencies (C); bumping Gin raised the `go` line and forced a builder change (D); no tests, so every bump was a leap of faith; scanners disagreed; scan numbers changed between days with no image change (database drift); base tag changed between builds; hardening changed no CVE counts; shell-less debugging; non-root defaults broke a write path; access to the vendor image was not immediate; nothing triggered a rebuild when a CVE dropped.

---

## 14. Translating to business impact (Gap Selling / Value Selling)

| Dimension | Current state (A) | After app and toolchain fixes (D) | Future state (E / F) | Gap (A to F) | Business impact (customer-specific, to be confirmed) |
|---|---|---|---|---|---|
| Critical + High findings | Grype 753 (106 + 647); Trivy 2,872 (139 + 2,733) | Grype 0; Trivy 0 | Grype 0; Trivy 0 | A to F: -753 (Grype), -2,872 (Trivy) | Audit exposure, deal blockers. Hypothesis; confirm with: "Do open Critical/High findings block releases or sales questionnaires today?" |
| Total findings to triage | Grype 2,341; Trivy 14,144 | Grype 3 (1 unique CVE); Trivy 1 | Grype 0; Trivy 1 | A to F: -2,341 (Grype), -14,143 (Trivy); findings, not risk | Hours per week of triage toil. Hypothesis; confirm with: "How many scanner findings does a team triage per week and how long does each take?" |
| Image size | 1,486.5 MB | 44.3 MB | 35.8 MB | A to F: -1,450.7 MB (-97.6%) | Pull time, storage, cold starts. Hypothesis; confirm with: "Where does image pull time or registry cost hurt today?" (pull time itself was not measured) |
| Attacker tooling in image | Shell, apt/dpkg, Go toolchain, gcc, git, curl, perl, python (Syft, inferred) | Shell, busybox, apk-tools (Syft, inferred) | No shell (exec fails), no package manager, no compiler (`E.runtime.txt`, `E.props.txt`, Syft) | Toolchain, compiler and package manager removed by F | Post-compromise blast radius. Hypothesis; confirm with: "Could an attacker who lands in a container install or run tools?" |
| Privileges at runtime | root, CapBnd `a80425fb`, NoNewPrivs 0 | root (unchanged) | E: UID 65532, CapEff 0. F: also CapBnd 0, NoNewPrivs 1, read-only root FS, 128 MiB / 100 pids / 0.5 CPU | root to non-root with an empty capability ceiling | Blast radius if compromised. Hypothesis; confirm with: "Do your containers run as root by default?" |
| Provenance / SBOM | None | None | None produced by me; Chainguard-provided signature/SBOM/attestation not checked | No signing, attestation or published SBOM was done | Compliance evidence, questionnaires. Hypothesis; confirm with: "What SBOM/provenance evidence do customers or auditors ask you for?" |
| Remediation ownership | Self (manual) | Self (manual) | Base image owned by the vendor; app, toolchain and modules still self-owned | Not measured (no time-to-fix data) | Who rebuilds when a CVE drops? Hypothesis; confirm with: "Who rebuilds an image when a new CVE lands, and how long does that take?" |

**Honest reading of the ladder:** In Grype, 2,262 of the 2,341 findings removed (97%) went at B, by not shipping the build image (1,820 OS findings, 324 stdlib findings on the Go toolchain's own binaries, 118 on the `go` binary); C removed the 59 stdlib findings in the application binary with one build argument; D removed the last 16 module findings; E removed the last 3 (one unfixable Alpine busybox CVE). That is a statement about image composition, not about this app being unusually bad: any team that builds on a full language image will see numbers like A. The E delta is small for this static Go binary because Alpine was already tiny (16 packages, 3 findings); the E benefits that counts do not show are a 8.5 MB smaller image, no shell or package manager, and non-root by default (E changed two things at once). Trivy still reports one UNKNOWN advisory at E, so "zero" holds only for Grype on this database date. What a scan count does not show, and where the stronger Chainguard argument sits: continuous rebuilds when a CVE drops, who owns remediation (here: one person by hand, about 55 minutes of commits from A to F by git timestamps), signatures, SBOM and provenance (not checked here), and the same treatment across every language and image a customer runs [verify vendor claims at edu.chainguard.dev]. Limitations: one run per step, arm64 not amd64, same-day databases (Trivy A's DB date not recorded), F's image ID and scans not captured, a one-route static binary is the best case for any minimal base, and each delta is order-dependent.

Illustrative value model (replace with the customer's numbers): `hours/week triaging x weeks x loaded hourly cost x % reduction = annual toil saved`

---

## 15. What I did not do, and why

| Item | Reason | What I would do next |
|---|---|---|
| Independent F evidence (image ID, scans) | `F.runtime.txt` exists but no `F.props`, `F.grype.json` or `F.trivy.json`; F = E is assumed | `docker image inspect -f '{{.Id}}' hello:e-chainguard hello:f-hardened`; if equal, no rescan is needed |
| Gin release-mode check | Logs not captured | `docker logs <name>` from the F run, look for the debug warning |
| Pull time | Not measured | `time docker pull <image>` from a cleared cache, against a registry |
| Per-step `curl` output and the B read-only write test | Not saved in `evidence/` | Re-run `curl -i` per step and a write test on B; save to `evidence/` |
| Optional side-by-sides (Ealt, Ebuild, Eapko) | No evidence files | Build as in 2a, or delete the rows |
| Bonus: SBOM, signing, registry, Kubernetes, melange/apko | Not attempted (no `evidence/sbom/`, cosign or registry output) | `syft <image> -o spdx-json`, sign by digest after a registry push, verify, show a failure demo; check Chainguard-provided signatures and SBOM |
| amd64 validation | Built on arm64 only | Repeat A and E on amd64 |
| Repeat runs / variance | One run per step | Re-run `scripts/rescan-all.sh` and timings three times |
| Tests for the app | No tests in the repo | Add a minimal HTTP test so bumps C and D are verified by more than `curl` |
| Trivy DB date for A | Not captured in `A.scan-meta.txt` | `scripts/rescan-all.sh` |
| Environment versions (Multipass, Docker, host `uname`) | Not in evidence | Save `multipass version`, `docker version`, `uname -a`, `go version` to `evidence/environment.txt` |
| Base-image digests (`golang:1.27.3`, `alpine:3`, `cgr.dev/checkmarx.com/static:latest`) | Not captured | `docker buildx imagetools inspect <image>` for each |
| Git tags `step-A` to `step-F` | None exist in this clone | `git tag step-X <commit>` per step before presenting |
| Fix `scripts/diff-steps.sh` empty-file bug | `diff-D-E.*.tsv` are wrong | Handle an empty target file (for example `awk` with `FILENAME` checks or `comm`) |

---

## Appendix: commands to collect the data

The per-step scripts collect most of this automatically. Manual equivalents are below.

```bash
# The per-step routine (IDs are letters: A, B, C, D, E, F; optional: Ealt, Ebuild, Eapko)
scripts/step.sh <ID> <label> <Dockerfile> [--build-arg ...]     # build, properties, Grype, Trivy, Syft, binary + govulncheck
scripts/summarize.sh                                            # evidence/ladder.csv across all steps
scripts/diff-steps.sh <from-ID> <to-ID>                         # CVEs gone / still present / new  (e.g. B C)
scripts/rescan-all.sh                                           # re-scan every step today (DB drift)
scripts/runtime-profile.sh <ID> <image> [docker run flags]      # kernel view of the running process

# Image properties
docker images --format '{{.Repository}}:{{.Tag}}  {{.Size}}'
docker history <image>
docker image inspect -f '{{.Id}}  user={{.Config.User}}' <image>
docker run --rm --entrypoint sh <image> -c 'command -v apt-get apk go gcc; ls /app'   # error = no shell
syft <image> -o json | jq '.artifacts | length'                 # package count
time docker build --no-cache -f docker/Dockerfile.multi -t name:tag go/

# Scans (save raw JSON, record versions)
grype version && grype db status && trivy --version
grype <image> -o json > evidence/<ID>.grype.json
trivy image --format json -o evidence/<ID>.trivy.json <image>

# Severity counts
jq '[.matches[].vulnerability.severity] | group_by(.) | map({(.[0]): length}) | add' evidence/<ID>.grype.json
jq '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map({(.[0]): length}) | add' evidence/<ID>.trivy.json

# Fixable only
grype <image> --only-fixed
trivy image --ignore-unfixed <image>

# CVE ID lists and diff between steps
jq -r '.matches[].vulnerability.id' evidence/A.grype.json | sort -u > A.ids
jq -r '.matches[].vulnerability.id' evidence/E.grype.json | sort -u > E.ids
comm -23 A.ids E.ids   # in A, gone in E

# Go-specific
go version -m evidence/bin/<ID>-hello-server                    # embedded Go version and module list
(cd go && govulncheck ./...)
govulncheck -mode=binary evidence/bin/<ID>-hello-server

# Runtime profile (host kernel view of the container process)
PID=$(docker inspect -f '{{.State.Pid}}' <name>)
sudo grep -E '^(Uid|CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/$PID/status
capsh --decode=<hex>

# Supply chain
syft <image> -o spdx-json > evidence/sbom/<name>.spdx.json
grype sbom:./evidence/sbom/<name>.spdx.json
cosign generate-key-pair                                        # run inside keys/ (gitignored)
cosign sign --key keys/cosign.key <registry>/<image>@sha256:<digest>
cosign verify --key keys/cosign.pub <registry>/<image>@sha256:<digest>
```
