# FINDINGS.md: Container Security Improvement Ladder (steps A to F)

> Fill in every `TBD`. Record raw evidence (JSON scan output, command logs) in `./evidence/` and reference it here.
> Rule: never report a number without the scanner name, scanner version, DB date, and image identifier.
> Method: **one change per step, scan after every step.** Numbers come from `scripts/summarize.sh` (`evidence/ladder.csv`). Before you report or present any comparison, run `scripts/rescan-all.sh` so every step is scanned the same day with the same vulnerability databases.
> Naming: a step's letter is its ID. Step `A` = image `hello:a-baseline` = evidence files `evidence/A.*`. Optional side-by-sides use `Ealt`, `Ebuild`, `Eapko`.
> Image identifier: until an image is pushed to a registry, use the **local image ID** (`docker image inspect -f '{{.Id}}'`). After a push (Bonus A), record the registry **digest** and say which one you are quoting.

---

## 0. Executive summary (write last, put first)

3-4 sentences: the starting point, what I changed and in what order, the headline numbers (A to F), and the single most important thing I learned.

TBD

---

## 1. Environment and decisions

| Item | Choice | Version | Why (one sentence) | Tradeoff accepted |
|---|---|---|---|---|
| Virtualization platform | Multipass | TBD (`multipass version`) | Fast way to get a clean, scriptable Ubuntu LTS VM on a Mac. One command to create, snapshot, and destroy, and it mirrors how containers are usually run in production: on cloud Linux VMs. | UTM: GUI, more control, slower to set up. Lima: great, more config. VirtualBox: weak on Apple Silicon. |
| Guest OS | Ubuntu Server 24.04 LTS | kernel: 6.8.0-147-generic; CPUs: 4; RAM: 8 GB; Disk: 40 GB | TBD | TBD |
| CPU architecture (host / guest) | aarch64 (Apple Silicon host; arm64 guest) | TBD | TBD | amd64 is most common in production, but I'm on Apple Silicon and want to run at full speed without fully emulating |
| Container engine | Docker Engine (`docker-ce`, installed from Docker's apt repository inside the VM) | TBD (`docker version`) | TBD | TBD |
| Scanner 1 | Grype | 0.121.0 | TBD | TBD |
| Scanner 2 | Trivy | 0.76.1 | TBD | Shows scanner discrepancy |
| Scanner 3 (reachability) | govulncheck | v1.9.0 | Separates "present" from "called" | Source mode uses the VM's Go, not the image's (see Section 7) |
| SBOM tool | Syft | 1.55.0 | TBD | TBD |
| Signing tool | cosign | v3.1.4 | TBD | TBD |
| Experiment design | One change per step (A to F) | n/a | Every delta has exactly one cause | Each step is measured *given the steps before it* (order-dependent attribution; the total is not) |
| Go toolchain used in the images (baseline / patched) | go1.18.10 / TBD | | | |
| Go toolchain installed in the VM (for `go get` and govulncheck source mode) | Go 1.27.3 | | Needed to patch `go.mod` and run source-mode reachability | Source-mode results reflect this newer Go, not the Go 1.18 in the baseline image |
| Gin version (baseline / patched) | v1.8.1 / TBD | | | |
| `go` line in go.mod (baseline / patched) | 1.18 / TBD | | | Did the update force a toolchain change? |
| Step B runtime base | alpine:3 (assumption; edit if different) | TBD | Minimal but conventional; keeps a shell and package manager | Runs as root by default |
| Step E runtime base | cgr.dev/<org>/static (Chainguard "distroless") | TBD | Same app, same compiler; only the base changes | Access/plan limits; vendor dependency; runs non-root by default, so E changes two things (base and default user) |
| Optional side-by-side (Ealt) | gcr.io/distroless/static-debian12 | TBD | Evidence for "we already use distroless"; fallback if Chainguard access is delayed | Debian cadence; no SLA; default tag runs as root |

---

## 2. The ladder (variants under test)

### 2a. Definition (each step changes exactly one thing)

| ID | Step | The ONE change vs. previous | Dockerfile + build args | Build stage base | Runtime base | App deps | Go toolchain | Runs as | Image tag / evidence | Comments |
|---|---|---|---|---|---|---|---|---|---|---|
| **A** | Baseline: single-stage, golang base | (starting point) | `Dockerfile.single`, `GO_VERSION=1.18` | `golang:1.18`, digest `sha256:50c889275d26f816b5314fc99f55425fa76b18fcaf16af255f5d57f09e1f48da` (Debian GNU/Linux 11 (bullseye), linux/arm64) | Same as build (single stage) | Vulnerable (original): Gin v1.8.1 plus the original indirect deps, `go.mod`/`go.sum` untouched | Original: Go **1.18.10** | root | `hello:a-baseline`, `evidence/A.*` | Full Go toolchain, source, Debian userland, shell and `apt` all shipped. `COPY . .` before `go mod download` defeats layer caching. Exec-form `CMD` (app is PID 1). Static binary (`CGO_ENABLED=0`). The "typical team" starting point. |
| **B** | Multi-stage, minimal runtime base | Multi-stage build; runtime becomes Alpine | `Dockerfile.multi`, `GO_VERSION=1.18`, `RUNTIME_IMAGE=alpine:3` | `golang:1.18` (same image as A) | `alpine:3` (TBD: version and digest) | Original (same as A) | Go 1.18.10 | root | `hello:b-multistage`, `evidence/B.*` | Expect OS-package findings and size to collapse; module and stdlib findings unchanged. Still has a shell and package manager. |
| **C** | Go toolchain updated | Newer Go in the builder | `Dockerfile.multi`, `GO_VERSION=TBD`, `RUNTIME_IMAGE=alpine:3` | `golang:TBD` (exact version and digest) | `alpine:3` (same as B) | Original | TBD (latest, or newest that builds) | root | `hello:c-go-updated`, `evidence/C.*` | Expect stdlib findings to drop sharply; nothing else should move. If the build fails on old dependencies, log the friction. |
| **D** | Modules bumped | `go get` Gin and transitive deps; `go mod tidy` | Same args as C; **source changed** | `golang:TBD` (same as C) | `alpine:3` | **Patched:** Gin TBD plus updated indirect deps | TBD (same as C) | root | `hello:d-mods-bumped`, `evidence/D.*` | Record the `go` line in `go.mod` before and after. Did the dependency update force a toolchain update? No tests exist; the only check is `curl` returning `Hello World!`. |
| **E** | **Chainguard "distroless" runtime base** | Runtime base Alpine to Chainguard `static` | `Dockerfile.multi`, `RUNTIME_IMAGE=cgr.dev/<org>/static:latest` | `golang:TBD` (same as D) | `cgr.dev/<org>/static` (Chainguard OS / Wolfi-based; TBD: digest) | Patched | TBD | 65532 (image default; verify with `docker image inspect`) | `hello:e-chainguard`, `evidence/E.*` | No shell, no package manager. Expect a small change in counts, because Alpine's package set was already tiny. Runs non-root **by default**, so non-root arrives here, not in F. Check what ships with the image (signature, SBOM, provenance) in Bonus A. |
| **F** | Hardened runtime | **No image change.** Run flags only | `docker run` flags (see Section 10b) | (same as E) | (same as E) | Patched | TBD | 65532 | `hello:f-hardened` (same image as E), `evidence/F.runtime.txt` | Zero change in CVE counts expected (same image as E). What changes: read-only filesystem, no capabilities, `no-new-privileges`, pids/memory/CPU limits, `GIN_MODE=release`. Evidence comes from `/proc`. |

**Optional side-by-sides (not part of A to F; delete any you skip):**

| ID | Step | The ONE change vs. E | Dockerfile + build args | Runtime base | Image tag / evidence | Comments |
|---|---|---|---|---|---|---|
| **Ealt** | Google distroless runtime | Chainguard `static` to Google `distroless/static` | `Dockerfile.multi`, `RUNTIME_IMAGE=gcr.io/distroless/static-debian12` | `distroless/static` (TBD: digest) | `hello:ealt-google-distroless`, `evidence/Ealt.*` | Debian-based, free, widely used. Evidence for the "we already use distroless" objection. Its default tag runs as root (the `:nonroot` tag runs as 65532): say which you used. |
| **Ebuild** | Chainguard builder too | Builder `golang` to `cgr.dev/<org>/go` | `BUILD_IMAGE=cgr.dev/<org>/go:latest` | `cgr.dev/<org>/static` | `hello:ebuild-chainguard-builder`, `evidence/Ebuild.*` | Shows that migration is mostly `FROM` lines. Record the Go version it ships; it may differ from step C's. |
| **Eapko** | melange + apko build (Bonus C) | No Dockerfile; image assembled by apko from Wolfi packages | `chainguard-way/*.yaml` | Wolfi packages | `hello:eapko-melange`, `evidence/Eapko.*` | Chainguard's own open source tooling, done by hand. |

**How to read the deltas:** A to B isolates **image composition**. B to C isolates the **Go compiler**. C to D isolates the **application dependencies**. D to E isolates the **runtime base** (Alpine vs. Chainguard "distroless", plus its non-root default). E to F isolates **runtime hardening** (expected to change no CVE counts). Ealt vs. E (if done) isolates **Google distroless vs. Chainguard**. Present these effects separately.

**Step A base facts (recorded):** `golang:1.18` resolved to `go1.18.10 linux/arm64` on Debian GNU/Linux 11 (bullseye). Tag digest: `golang@sha256:50c889275d26f816b5314fc99f55425fa76b18fcaf16af255f5d57f09e1f48da` (multi-arch index digest; the arm64 image beneath it has its own digest).

### 2b. Hypotheses (write these BEFORE scanning each step) and outcomes

| Step | My hypothesis (written before the scan) | What actually happened | Did it hold? Why / why not? |
|---|---|---|---|
| A | Huge image, hundreds of OS-package findings, plus app and stdlib findings | TBD | |
| B | OS findings and size collapse; module and stdlib findings unchanged | TBD | |
| C | stdlib findings drop sharply; nothing else moves | TBD | |
| D | Module findings drop; the `go` line rises; some findings may be new | TBD | |
| E | Small change in counts (Alpine's package set was already tiny); shell and package manager gone; runs non-root by default | TBD | |
| F | Zero change in CVE counts; large change in privileges (read-only, no capabilities, no-new-privileges) | TBD | |

---

## 3. Image properties

F uses the same image as E. Fill F as "= E" where the property is a property of the image.

| Metric | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| Image ID / registry digest (`sha256:...`) | | | | | | = E (verify equal) |
| Image size (MB) | | | | | | = E |
| Layer count | | | | | | = E |
| OS package count (Syft, deb/apk/rpm) | | | | | | = E |
| Total package count (Syft, all types) | | | | | | = E |
| Go version embedded in binary (`go version -m`) | | | | | | = E |
| Runs as (user:uid), image default | | | | | | = E (flags add no change to user) |
| Shell present? (Y/N) | | | | | | = E |
| Package manager present? (Y/N) | | | | | | = E |
| Compiler/toolchain present? (Y/N) | | | | | | = E |
| Source code present? (Y/N) | | | | | | = E |
| Entrypoint form (exec / shell) | | | | | | = E |
| Build time, cold (s) | | | | | | n/a |
| Build time, warm cache (s) | | | | | | n/a |
| Pull time (s) | | | | | | n/a |
| Libc | | | | | | = E |

Source: `evidence/<ID>.props.txt`, `evidence/<ID>.build.txt`, `evidence/<ID>.buildinfo.txt`. Manual checks (package manager, compiler, source present) use `docker run --rm --entrypoint sh <image> -c 'command -v apt-get apk go gcc; ls /app'`; an error means no shell.

---

## 4. Scan metadata (fill once per scan run)

Re-scan every step the same day (`scripts/rescan-all.sh`) before reporting comparisons. F reuses E's scan because the image is identical.

| Scan ID | Step | Scanner | Scanner version | DB build date | Exact command | Raw output file |
|---|---|---|---|---|---|---|
| A-G | A | Grype | | | `grype hello:a-baseline -o json` | `evidence/A.grype.json` |
| A-T | A | Trivy | | | `trivy image --format json hello:a-baseline` | `evidence/A.trivy.json` |
| B-G | B | Grype | | | | `evidence/B.grype.json` |
| B-T | B | Trivy | | | | `evidence/B.trivy.json` |
| C-G | C | Grype | | | | `evidence/C.grype.json` |
| C-T | C | Trivy | | | | `evidence/C.trivy.json` |
| D-G | D | Grype | | | | `evidence/D.grype.json` |
| D-T | D | Trivy | | | | `evidence/D.trivy.json` |
| E-G | E (= F) | Grype | | | | `evidence/E.grype.json` |
| E-T | E (= F) | Trivy | | | | `evidence/E.trivy.json` |

Each scan's tool versions and DB status are saved in `evidence/<ID>.scan-meta.txt`. Side-by-sides (`Ealt`, `Ebuild`, `Eapko`) get their own rows if you build them.

---

## 5. Vulnerability counts

Counts are findings (matches), as produced by `scripts/summarize.sh` (`evidence/ladder.csv`). "Other" = Negligible / Unknown / unrecognized severity.

### 5a. Grype (all findings)

| Severity | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| Critical | | | | | | = E |
| High | | | | | | = E |
| Medium | | | | | | = E |
| Low | | | | | | = E |
| Negligible / Unknown | | | | | | = E |
| **Total** | | | | | | = E |
| **Fixable (fix available)** | | | | | | = E |
| **Not fixable** | | | | | | = E |

### 5b. Trivy (all findings)

| Severity | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| Critical | | | | | | = E |
| High | | | | | | = E |
| Medium | | | | | | = E |
| Low | | | | | | = E |
| Unknown | | | | | | = E |
| **Total** | | | | | | = E |
| **Fixable** | | | | | | = E |
| **Not fixable** | | | | | | = E |

### 5c. Scanner discrepancy (the "which one is right?" slide)

| Step | Grype total | Trivy total | Delta | Likely cause (data source, unfixed handling, matching method, binary detection) |
|---|---|---|---|---|
| A | | | | |
| B | | | | |
| C | | | | |
| D | | | | |
| E | | | | |

### 5d. The waterfall: what moved at each step (your key slide)

Primary scanner for this table: **TBD**. Deltas are from `scripts/diff-steps.sh` and `evidence/ladder.csv`.

| Transition | The one change | Total delta | Critical+High delta | Fixable delta | Bucket that moved (OS / modules / stdlib / none) | One-sentence takeaway |
|---|---|---|---|---|---|---|
| A to B | Multi-stage + alpine runtime | | | | | |
| B to C | Go toolchain updated | | | | | |
| C to D | Modules bumped | | | | | |
| D to E | Alpine to Chainguard "distroless" (and non-root default) | | | | | |
| E to F | Hardened runtime (no image change) | 0 (expected) | 0 (expected) | 0 (expected) | none | |
| **A to F (cumulative)** | Everything | | | | | |
| Ealt vs. E *(optional)* | Google distroless vs. Chainguard | | | | | |

---

## 6. Findings by source (where do the CVEs come from?)

This table is the most important one. It shows that **the base image, the dependencies, and the compiler are three different problems**, each fixed by a different step.

| Source category | A | B | C | D | E | F | Fixed by | Step that should move it |
|---|---|---|---|---|---|---|---|---|
| OS packages (base image) | | | | | | = E | Changing base image | B, E |
| Go modules (Gin and transitive dependencies) | | | | | | = E | `go get` / `go mod tidy` | D |
| Go stdlib (compiled in, from the builder's Go version) | | | | | | = E | Updating Go in the builder | C |
| Other (binaries, misc.) | | | | | | = E | | |
| **Total** | | | | | | = E | | |

Use the counts from whichever scanner you treat as primary (state which): **TBD**. Columns come from `os_pkgs`, `go_modules`, `go_stdlib` in `evidence/ladder.csv`.

---

## 7. Reachability (govulncheck)

Important: **source mode** analyzes your code and `go.mod` using *the Go toolchain installed in the VM* (the latest), so it will not show old stdlib problems. **Binary mode** reads the Go version and modules embedded in *the binary extracted from each image*, so it shows what was actually shipped. State which you are quoting.

| Target | Mode | Vulnerabilities found | Reachable (called by code) | Present but not called | Evidence file |
|---|---|---|---|---|---|
| Source, original deps (A state) | `govulncheck ./...` | | | | `evidence/A.govulncheck-source.txt` |
| Binary A (Go 1.18, original deps) | `-mode=binary` | | | | `evidence/A.govulncheck-binary.txt` |
| Binary C (new Go, original deps) | `-mode=binary` | | | | `evidence/C.govulncheck-binary.txt` |
| Binary D (new Go, patched deps) | `-mode=binary` | | | | `evidence/D.govulncheck-binary.txt` |
| Source, patched deps (D state) | `govulncheck ./...` | | | | `evidence/D.govulncheck-source.txt` |

**My prediction (written before running):** this app uses only `gin.Default()`, one `GET` route, and `c.String(...)`, so most module-level findings (SSH, protobuf, YAML, TOML) are present but not called; reachable ones are more likely in `net/http` and `x/net`. TBD: did it hold?

Key insight to state: "N findings in the scanner, M of them reachable from my code."

---

## 8. Remediation log (one entry per step)

### 8a. Changes

| # | Step | Change (exact command or flag) | Why | Bucket addressed (OS / modules / stdlib / privileges) | Breaking change? | How I verified (`curl` returns `Hello World!`) | Time spent |
|---|---|---|---|---|---|---|---|
| 1 | B | Multi-stage `Dockerfile.multi`, `RUNTIME_IMAGE=alpine:3` | Stop shipping the toolchain, source, and Debian userland | OS | | | |
| 2 | C | `GO_VERSION=TBD` in the builder | stdlib CVEs are compiled into the binary | stdlib | | | |
| 3 | D-a | `go get github.com/gin-gonic/gin@TBD` | | modules | | | |
| 4 | D-b | `go get -u ./...` and `go mod tidy` | Transitive modules | modules | | | |
| 5 | E | `RUNTIME_IMAGE=cgr.dev/<org>/static:latest` | Remove shell and package manager; vendor-maintained base; non-root default | OS / attack surface | | | |
| 6 | F | `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=100 --memory=128m --cpus=0.5 -e GIN_MODE=release` | Limit blast radius | privileges | | | |

Go line in `go.mod` before / after step D: TBD / TBD. Did a dependency update force a toolchain update? TBD.

### 8b. CVE diff per transition (source: `scripts/diff-steps.sh`, Grype)

| Transition | Gone | Still present | New | Top "gone" packages (name, count) | Why they went away |
|---|---|---|---|---|---|
| A to B | | | | | |
| B to C | | | | | |
| C to D | | | | | |
| D to E | | | | | |
| Ealt vs. E *(optional)* | | | | | |

### 8c. Notable CVEs (what disappeared, and why)

| CVE ID | Package | Severity | In step | Gone in step | Reason it went away |
|---|---|---|---|---|---|
| | | | | | |

"New" findings after a step are normal (new transitive modules, database changes). Explain them; do not hide them.

---

## 9. Remaining findings: disposition

Dispositioned at the final image (E). Every remaining finding gets an explicit decision. A dispositioned list is stronger than a claim of "zero."

| CVE ID | Package | Severity | Scanner(s) | Fix available? | Reachable? | Disposition | Rationale |
|---|---|---|---|---|---|---|---|
| | | | | | | Fix / Accept / False positive / Awaiting upstream | |

---

## 10. Deployment and runtime validation

### 10a. Functional checks (final image, hardened: step F)

| Check | Command | Result | Pass/Fail |
|---|---|---|---|
| Container starts | `docker run -d ...` | | |
| Endpoint responds (`GET /` returns `Hello World!`, HTTP 200) | `curl -i http://localhost:8080/` | | |
| Runs as non-root | `docker inspect --format '{{.Config.User}}' <name>` and `/proc` Uid | | |
| Read-only root FS works | `--read-only` (write test shown on B, which has a shell) | | |
| All caps dropped | `--cap-drop=ALL`; `/proc` CapBnd | | |
| no-new-privileges | `--security-opt=no-new-privileges:true`; `/proc` NoNewPrivs | | |
| Graceful stop (SIGTERM, time to stop) | `time docker stop <name>` | | |
| Shell absent (expected on E and F) | `docker exec <name> sh` | | |
| Gin in release mode | `-e GIN_MODE=release`; no debug warning in logs | | |

### 10b. Runtime security profile (measured from the VM's kernel, `scripts/runtime-profile.sh`)

| Property | A default run | E default run | F hardened |
|---|---|---|---|
| `Uid` (from `/proc/<pid>/status`) | | | |
| `CapEff` (effective capabilities) | | | |
| `CapBnd` (bounding set: the ceiling) | | | |
| `NoNewPrivs` | | | |
| `Seccomp` | | | |
| ReadonlyRootfs | | | |
| Memory / PidsLimit / NanoCpus | | | |
| Shell exec attempt | | | |
| Time to stop (s) | | | |
| Endpoint response | | | |

Evidence: `evidence/A.runtime.txt`, `E.runtime.txt`, `F.runtime.txt`. Reading tip: a non-root process already has `CapEff = 0` (so E and F match there); look at `CapBnd` and `NoNewPrivs` to see what the hardening flags added on top of E. Key sentence to state: "Hardening changed **zero** CVE counts (F is the same image as E). It changed exploitability and blast radius, and this is the kernel evidence."

---

## 11. Bonus: supply chain (if attempted)

| Item | Step/image | Tool | Result | Evidence |
|---|---|---|---|---|
| SBOM generated (SPDX / CycloneDX) | A, E | Syft | | `evidence/sbom/` |
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
| Cluster (kind/minikube) and version | |
| Manifest security context (non-root, RO FS, drop ALL, seccomp RuntimeDefault, `GIN_MODE=release`) | |
| Deployment healthy | |
| Service reachable (port-forward) | |
| Debug via `kubectl debug` ephemeral container (no shell in image) | |
| Policy enforcement (e.g. block unsigned) | |

## 12b. Bonus: Chainguard-native build with melange + apko (if attempted)

| Item | Result |
|---|---|
| Tool versions (melange, apko) and where I got them | |
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
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

Candidate themes: a newer Go failed to build or link the old dependencies (C); bumping Gin raised the `go` line and forced a builder change (D); no tests, so every bump was a leap of faith; scanners disagreed; scan numbers changed between days with no image change (database drift); base tag changed between builds; hardening changed no CVE counts; shell-less debugging; non-root defaults broke a write path; access to the vendor image was not immediate; nothing triggered a rebuild when a CVE dropped.

---

## 14. Translating to business impact (Gap Selling / Value Selling)

| Dimension | Current state (A) | After app and toolchain fixes (D) | Future state (E / F) | Gap (A to F) | Business impact (customer-specific, to be confirmed) |
|---|---|---|---|---|---|
| Critical + High findings | | | | | Audit exposure, deal blockers |
| Total findings to triage | | | | | Hours per week of triage toil |
| Image size | | | | | Pull time, storage, cold starts |
| Attacker tooling in image | | | | | Post-compromise blast radius |
| Privileges at runtime | | | | | Blast radius if compromised |
| Provenance / SBOM | | | | | Compliance evidence, questionnaires |
| Remediation ownership | | | | | Who rebuilds when a CVE drops? |

**Honest reading of the ladder (fill in with your data):** where were the big drops (expected: B for OS packages, C for stdlib, D for modules)? How small was the E delta for this static Go app? What does a scan count *not* show (continuous rebuilds, remediation SLA, provenance, coverage across languages and images)?

Illustrative value model (replace with the customer's numbers): `hours/week triaging x weeks x loaded hourly cost x % reduction = annual toil saved`

---

## 15. What I did not do, and why

| Item | Reason | What I would do next |
|---|---|---|
| | | |

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
