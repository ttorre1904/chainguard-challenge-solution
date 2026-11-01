# TASK: Populate FINDINGS.md from the evidence directory

You are working inside the repository `chainguard-challenge-solution` (my private solution to the Chainguard Solutions Engineer technical challenge). Your job is to **fill in `./FINDINGS.md` completely and accurately, using only the raw materials in `./evidence/`, the repo's own files, and git history.** I will use the finished document in a 30-45 minute technical panel, so it must be correct, traceable, and honest.

Read this whole prompt before doing anything. Then work through the procedure in order.

---

## 1. Hard rules (these override everything else)

1. **Never invent a number, version, digest, date, or finding.** Every value you write must trace to a file in `./evidence/`, a repo file, or git history. If a value cannot be sourced, write `N/A` or `Not measured` **with a one-line reason**, and add it to the "needs input from the user" list. Leaving a justified `N/A` is better than guessing. Quality over quantity is an explicit evaluation criterion of this challenge.
2. **Read-only on everything except `FINDINGS.md`** (and the two helper outputs listed in Section 9). Do not edit anything under `go/`, `docker/`, `scripts/`, or any raw file in `evidence/`. Do not delete files.
3. **Do not run Docker, build images, run scanners, pull images, use the network, or run `git commit` / `git push`.** This task is analysis of existing evidence. (Reading evidence with `jq`, `python3`, `awk`, `grep`, `sed`, and read-only `git log` / `git show` / `git diff` is fine. Regenerating the derived files `evidence/ladder.csv` and `evidence/diff-*.tsv` with the repo's `scripts/summarize.sh` and `scripts/diff-steps.sh` is allowed, but prefer computing independently and using those scripts only as a cross-check.)
4. **Preserve my existing content in `FINDINGS.md`.** Only fill cells that are `TBD`, blank, or placeholders. If a cell I already filled conflicts with the evidence, do **not** overwrite it silently: keep my text, and record the conflict in `REVIEW-NOTES.md` (Section 9).
5. **Do not rewrite the hypotheses.** In Section 2b, the column "My hypothesis (written before the scan)" was written by me before scanning. Leave it exactly as is. You fill only "What actually happened" and "Did it hold? Why / why not?".
6. **Keep the document's structure.** Do not rename, renumber, reorder, or delete sections, tables, or columns. Keep every Markdown table valid (same number of cells in every row). You may add rows where a table has room for them (for example, notable CVEs). No emoji.
7. **Be a skeptic about the data.** Cross-check totals, flag anomalies, and say so when a result contradicts a hypothesis. A finding that surprises us is more valuable in the panel than a tidy story.

---

## 2. Background you need (you have no memory of the earlier conversation)

### The challenge
Take-home for a Senior Solutions Engineer / Sales Engineer role at Chainguard, followed by a 30-45 minute presentation. The brief (repo `README.md`): containerize a Go web server with a single-stage and a multi-stage Dockerfile, scan with CVE scanners, document findings, patch the app and its dependencies, update/optimize base images, rescan, document the improvement, and deploy and validate a container. Optional bonuses: SBOMs, image signing, a local registry, Kubernetes. Deliverables: all Dockerfiles, before/after scan reports, and documentation of findings and methodology (this file).

**Evaluation criteria** (write with these in mind): problem-solving approach and technical reasoning; security awareness and analysis depth; quality of work over quantity; code quality and documentation; communication; ability to articulate challenges and tradeoffs. The audience is engineers and sales leaders judging a *solutions engineer*, so connect technical findings to business impact (Gap Selling / Value Selling) wherever it is natural, but never overstate.

### The application (`go/`)
Module `hello-server`: `go 1.18` in `go.mod`, one direct dependency `github.com/gin-gonic/gin v1.8.1` plus 17 indirect dependencies (several from 2021-2022: `golang.org/x/net`, `x/crypto`, `x/sys`, `x/text`, protobuf, yaml, go-toml, validator, go-json). `main.go` is 12 lines: `gin.Default()`, one route `GET /` returning `Hello World!` (HTTP 200), `r.Run()` listening on `0.0.0.0:8080`. There are **no tests**. It is built with `CGO_ENABLED=0` (a static binary). `gin.Default()` runs in debug mode unless `GIN_MODE=release`.

### My environment (already recorded by me in Section 1; verify against evidence, do not overwrite)
Mac with Apple Silicon (aarch64). VM: Multipass, Ubuntu Server 24.04 LTS, 4 CPUs, 8 GB RAM, 40 GB disk, kernel 6.8.0-147-generic, guest arch arm64. Docker Engine inside the VM. Tools: Grype 0.121.0, Trivy 0.76.1, govulncheck v1.9.0, Syft 1.55.0, cosign v3.1.4. Go installed in the VM (used for `go get` and govulncheck *source* mode): 1.27.3. Images were built for **arm64**, not amd64.

### The improvement ladder (one change per step; each step builds on the previous)
Image tags are `hello:<lowercase-id>-<label>`; evidence files are `evidence/<ID>.*`.

| ID | Image tag | The ONE change | Dockerfile + build args |
|---|---|---|---|
| **A** | `hello:a-baseline` | Baseline: single-stage on `golang:1.18` (Debian 11 bullseye, Go 1.18.10), runs as root | `docker/Dockerfile.single`, `GO_VERSION=1.18` |
| **B** | `hello:b-multistage` | Multi-stage build; runtime becomes `alpine:3` | `docker/Dockerfile.multi`, `GO_VERSION=1.18`, `RUNTIME_IMAGE=alpine:3` |
| **C** | `hello:c-go-updated` | Go toolchain updated in the builder | `Dockerfile.multi`, `GO_VERSION=<newer>`, `RUNTIME_IMAGE=alpine:3` |
| **D** | `hello:d-mods-bumped` | Go modules bumped (Gin and transitive); source changed (on branch `remediation`) | same build args as C |
| **E** | `hello:e-chainguard` | Runtime base becomes Chainguard `static` (a minimal "distroless-style" image on Chainguard OS). **Also non-root by default (UID 65532), so E changes two things: the base and the default user** | `Dockerfile.multi`, `RUNTIME_IMAGE=cgr.dev/<org>/static:latest` |
| **F** | `hello:f-hardened` | **No image change.** Same image as E, run with hardening flags: `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=100 --memory=128m --cpus=0.5 -e GIN_MODE=release` | `docker run` flags |

Optional side-by-sides that may or may not exist: `Ealt` (Google `distroless/static`), `Ebuild` (Chainguard `go` builder too), `Eapko` (melange + apko build). Git tags `step-A` through `step-F` (and `ladder-complete`) mark each step; step D's source changes live on branch `remediation`.

**Interpretation guardrails (state these where relevant; they are the honest framing):**
- Each step's delta is measured *given the steps before it*. A different order would attribute individual deltas differently; the cumulative total would be the same.
- Expected pattern, to be **tested against the data, not assumed**: B moves the OS-package bucket; C moves the Go stdlib bucket; D moves the Go-module bucket; E is a *small* change for this static Go binary; F changes **no** CVE counts (same image as E) but changes privileges. Report what the data actually shows.
- For this specific app (static binary, one route), any good minimal base is a best case, so the Alpine vs. Chainguard count difference may be small. Do not oversell. The stronger Chainguard argument is what a count cannot show (continuous rebuilds, remediation commitment, signatures/SBOM/provenance, coverage across every language and image), and that must be stated as an argument, not as a measured result.
- Scan counts are **findings, not risk**. Say so, and use reachability (govulncheck) to separate "present" from "called".
- Scanner databases change daily. Note each scan's DB date and flag any comparison between scans taken on different days.

---

## 3. Evidence inventory and file formats

First list `./evidence/` and build an inventory (Section 4, Step 1). Expected files (a step letter `<ID>` is A, B, C, D, E, F, or an optional ID):

| File | Contents |
|---|---|
| `<ID>.grype.json` | Grype JSON. Findings = `.matches[]`. Fields: `.vulnerability.{id,severity,fix.state}`, `.artifact.{name,version,type}`, `.relatedVulnerabilities[].id` |
| `<ID>.trivy.json` | Trivy JSON. `.Results[]` each with `.Class` (`os-pkgs` or `lang-pkgs`), `.Target`, `.Type`, and `.Vulnerabilities[]` with `{VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Status}` |
| `<ID>.syft.json` | Syft JSON. Packages = `.artifacts[]` with `.name`, `.version`, `.type` (`deb`, `apk`, `rpm`, `go-module`, `binary`, ...) |
| `<ID>.props.txt` | `key: value` lines: `image`, `image_id`, `size_bytes`, `layers`, `user` (empty = root), `entrypoint`/`cmd`, `shell_present`, `syft_total_packages`, `syft_os_packages`, `libc_packages` |
| `<ID>.build.txt` | `cold_build_s`, `warm_build_s`, and the exact `docker build` command |
| `<ID>.scan-meta.txt` | Scan date; Grype version block and `grype db status` block (`Built:`, `Status:`); Trivy version block (including vulnerability-DB lines); the exact scan commands |
| `<ID>.buildinfo.txt` | Output of `go version -m` on the extracted binary: embedded Go version and the module list |
| `<ID>.govulncheck-binary.txt` | govulncheck in binary mode on that step's binary |
| `A.govulncheck-source.txt`, `D.govulncheck-source.txt` | govulncheck in source mode (uses the VM's Go 1.27.3 for stdlib, so it does **not** reflect the Go 1.18 in image A) |
| `<ID>.runtime.txt` | From `scripts/runtime-profile.sh`, for A, E, F: endpoint HTTP code and body, configured user, Docker host config, the kernel's `/proc/<pid>/status` fields (`Uid`, `CapEff`, `CapBnd`, `NoNewPrivs`, `Seccomp`, ...), shell-exec attempt, time to stop |
| `ladder.csv` | Columns `step,scanner,critical,high,medium,low,other,total,fixable,os_pkgs,go_modules,go_stdlib`. Note: this script's `go_modules` = total - os - stdlib, so it lumps any "other" findings into modules |
| `diff-<X>-<Y>.{gone,still,new}.tsv` | CVE+package rows gone/still present/new between two steps (Grype, tab-separated: id, package, severity) |
| `go-modules-before.txt`, `go-modules-after.txt` | `go list -m all` before and after step D |
| `sbom/*.spdx.json`, cosign/registry/Kubernetes outputs | Only if the bonus tasks were done |
| `*.log` | Scanner/syft logs (check for errors and warnings) |
| `bin/` | Extracted binaries (ignored by git; do not read them) |

**Stale or odd files:** an earlier version of the scripts used numeric IDs (`S1.*`, `S2.*`, ...). If any exist, treat them as stale duplicates: do not use them, and list them in `REVIEW-NOTES.md`. Also note the repo's own `.gitignore` files ignore `scanner_results/`, `sbom_scanner_results/`, `syft-sboms/`, `melange.rsa*`, `packages/`, `output.tar`, and `sbom-*`; confirm with `git check-ignore -v` that no needed evidence is being silently ignored.

---

## 4. Procedure

### Step 1: Inventory and quality gates (do this first, print the results)
1. Run `git status`, `git log --oneline --decorate --all`, and `git tag`. Copy `FINDINGS.md` to `FINDINGS.pre-populate.md` (a backup; do not commit it).
2. List `./evidence/` and build a table: for each step ID, which of the expected files exist, with sizes. Identify which steps have complete evidence, partial evidence, or none.
3. **Quality gates** (record every failure for `REVIEW-NOTES.md`):
   - Any `.json` scan file that is empty or invalid JSON.
   - Any `<ID>.scan-meta.txt` showing `Status: invalid`, `database does not exist`, or `Built: 0001-01-01` (that scan's DB date is unusable).
   - Scans for different steps taken on different days (compare `date_utc` across `scan-meta.txt` files): comparisons are then confounded by database drift. Recommend I run `scripts/rescan-all.sh` and re-run you.
   - Any `*.log` with errors.
   - For F: whether `F.grype.json`/`F.trivy.json` exist; if they do, they must match E's counts exactly (same image). If they do not, F's image/scan columns are "= E (same image)", which you must flag as "not independently verified; verify with `docker image inspect -f '{{.Id}}' hello:e-chainguard hello:f-hardened`".
   - Arithmetic: severities must sum to the total for each scanner and step.
4. Check which tools exist (`jq`, `python3`). **Prefer writing a throwaway Python script (standard library only) in `/tmp`, not in the repo,** that computes every metric below from the raw JSON and prints a single JSON summary; then work from that summary. If `jq` exists, use it to spot-check at least three numbers independently.

### Step 2: Compute the metrics (definitions; use exactly these, state them in the document)

**Finding** = one entry. Grype: each element of `.matches[]`. Trivy: each element of `.Results[].Vulnerabilities[]`. Also compute **unique CVE/advisory IDs** per scanner when helpful, and say which unit a table uses.

**Severity:** Grype `.vulnerability.severity` (lower-case: critical, high, medium, low, negligible, unknown). Trivy `.Severity` (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN). "Negligible / Unknown" row (Grype) and "Unknown" row (Trivy) hold those values.

**Fixable:** Grype `.vulnerability.fix.state == "fixed"`. Trivy `.FixedVersion` non-empty. **Not fixable** = total - fixable.

**Source bucket (Section 6), computed precisely and separately from `ladder.csv`:**
- OS packages: Grype `.artifact.type` in {apk, deb, rpm}; Trivy Result `.Class == "os-pkgs"`.
- Go stdlib: `.artifact.name == "stdlib"` (Grype) / `.PkgName == "stdlib"` (Trivy).
- Go modules: Go-module findings that are not stdlib (Grype `.artifact.type == "go-module"`; Trivy `lang-pkgs` that are not stdlib).
- Other: everything else.
If your numbers differ from `ladder.csv` (which folds "other" into modules), say so in a note under the table.

**Primary scanner:** use **Grype** as the primary scanner for Sections 6 and 5d unless the data gives a clear reason otherwise; state your choice in the document.

**Image properties:** `size_bytes` / 1,000,000 = MB (state decimal MB); layer count and `shell_present` from `props.txt`; OS package count = `syft_os_packages`; total packages = `syft_total_packages`; libc = `libc_packages` (if empty, write "none reported by Syft" and note the binary is static); Go version = first line of `<ID>.buildinfo.txt`; build times from `build.txt`; **Pull time: write "Not measured"**. "Package manager present?", "Compiler present?", "Source present?" are not directly in `props.txt`: infer from the Syft package list (for example `apt`/`dpkg`/`apk-tools`, `golang`/`gcc`) and from what you know of each Dockerfile, label the cell "(inferred from Syft + Dockerfile)", and list it as something I can confirm with `docker run --rm --entrypoint sh <image> -c 'command -v apt-get apk go gcc; ls /app'`.

**Scan metadata (Section 4):** Grype version and **DB build date** from the `Built:` line of `grype db status`; Trivy version and DB date from the vulnerability-DB lines in the Trivy version block; the exact commands from the `cmd:` lines. Use the image identifier from `props.txt` (`image_id`); note that it is the *local* image ID (with the containerd image store this is the manifest digest), not a registry digest, and that builds used `--provenance=false` so IDs are stable.

**Runtime profile (Section 10b):** parse `A.runtime.txt`, `E.runtime.txt`, `F.runtime.txt`. Key expectations to verify against the data: A runs as root (`Uid` 0); E runs as UID 65532 already (non-root process has `CapEff = 0`); F additionally shows `CapBnd = 0000000000000000` and `NoNewPrivs: 1`; `Seccomp: 2` throughout; the shell-exec attempt fails on E and F; endpoint returns HTTP 200 and `Hello World!`. Report what the files say, and flag any deviation.

**Reachability (Section 7):** read the govulncheck text files. Extract: number of vulnerabilities your code **calls** (reachable), and the "present but not called" counts for imported packages / required modules, using the summary sentences ("Your code is affected by N vulnerabilities...", "This scan also found P vulnerabilities in packages you import and Q in modules you require, but your code doesn't appear to call...") or the "Vulnerability #" blocks. The format varies by govulncheck version (v1.9.0 here), so read the actual text and quote the counts exactly; do not guess. If a file reports a binary-mode limitation (for example missing symbols), say so. Remember: **source mode uses the VM's Go 1.27.3 for the standard library**, so stdlib findings appear only in binary mode for the Go 1.18 images.

### Step 3: Fill the document, section by section

| Section | What to do |
|---|---|
| **0 Executive summary** | Write last, 3-4 sentences: the starting point (A), the changes in order, the headline numbers (A total vs. final; Critical+High; which buckets moved at which step), and the single most important lesson. Evidence-based; no overclaiming. |
| **1 Environment** | Keep my filled cells. Fill versions you can source: patched Gin version and patched `go` line from `go/go.mod` and `git show step-D:go/go.mod` (and before from `git show step-C:go/go.mod`); Go toolchain per step from `buildinfo.txt`. Docker and Multipass versions are not in evidence: leave `TBD` and add them to the needs-input list, and suggest I capture them into `evidence/environment.txt` (`multipass version`, `docker version`, `uname -a`, `go version`). |
| **2a Ladder definition** | Fill the TBD cells (Go versions from `buildinfo.txt`; Gin version; the "patched" description; exact build args from `build.txt` `cmd:` lines). Builder-image digests are not captured unless a file contains them; if not, state "not captured" and list the one-line command that would capture it. Keep my existing digest for `golang:1.18`. |
| **2b Hypotheses vs. outcomes** | Fill "What actually happened" with concrete numbers (before/after, by bucket) and "Did it hold? Why / why not?" with a candid assessment. Leave hypotheses untouched. |
| **3 Image properties** | Fill A-F (F = E where it is a property of the image). Add a note on the measurement caveats above. |
| **4 Scan metadata** | Fill one row per scan from `scan-meta.txt`; flag any unusable DB date. |
| **5a / 5b Counts** | Fill from your computed metrics (Grype and Trivy). F = E. |
| **5c Scanner discrepancy** | Fill totals and delta. For "likely cause", **analyze the data**: unique IDs per scanner; intersection and only-in-one lists; compare by CVE where possible (Grype may use GHSA IDs for Go modules; use `.relatedVulnerabilities[].id` to map to CVEs; fall back to (package, version) pairs); counts by bucket per scanner; how each scanner treats unfixed findings (Grype `fix.state`; Trivy `Status`). Label explanations you cannot prove as hypotheses. |
| **5d Waterfall** | For each transition (A to B, B to C, C to D, D to E, E to F, cumulative A to F): total delta, Critical+High delta, fixable delta, which bucket moved, one-sentence takeaway. Use the primary scanner. Cross-check with `diff-*.tsv` where present (gone/still/new). E to F must show 0 if the image is identical. |
| **6 Findings by source** | Fill the bucket table from your precise computation. |
| **7 Reachability** | Fill from the govulncheck files. Complete the prediction line ("did it hold?") honestly. |
| **8a Remediation log** | One row per change with the exact command (from `build.txt` `cmd:` lines and `git log`/`git diff`), bucket addressed, whether it broke anything (look in git history and any logs), and verification. "Time spent": estimate only from commit-timestamp gaps and label it "estimate from git timestamps", otherwise `N/A` (ask me). Record the `go` line before/after step D and whether the module bump forced a toolchain update. |
| **8b CVE diff per transition** | Fill from `diff-*.tsv` (or compute the same sets yourself): gone/still/new counts, top "gone" packages, and why. |
| **8c Notable CVEs** | Choose up to ~10 informative ones: highest severity, reachable ones, and any that appear or persist unexpectedly. Give ID, package, severity, step in, step gone, and the reason (for example "stdlib; fixed by the newer Go in step C"). |
| **9 Remaining findings** | At the final image (E): union of remaining findings across scanners, each with fix-available? and reachable? (from govulncheck). Propose a disposition (Fix / Accept / False positive / Awaiting upstream) with a rationale, and mark every disposition **"proposed, for the user's review"** in `REVIEW-NOTES.md`; these are judgments, not facts. If there are very many, group by package and list the highest-severity individually. |
| **10a Functional checks** | Fill from `F.runtime.txt` with Pass/Fail and the observed values. Pass criteria: HTTP 200 and body `Hello World!`; non-root Uid; `ReadonlyRootfs=true`; caps dropped (`CapBnd` zero); `NoNewPrivs 1`; clean stop time; shell absent. |
| **10b Runtime profile** | Fill the A / E / F table from the `/proc` fields and the shell/stop-time lines. Keep the reading tip. |
| **11 / 12 / 12b Bonuses** | Fill only if evidence exists (`sbom/`, cosign signing/verification output, registry digest, Kubernetes outputs, apko/melange outputs). Otherwise write "Not attempted" in the first Result cell and carry it to Section 15. Do not fabricate. |
| **13 Friction log** | Pre-fill with the events below (I experienced all of them), plus anything you find in logs and git history. Leave "Time lost" as `TBD (user)` unless evidence gives it. |
| **14 Business impact** | Fill the A / D / E-F columns with the measured numbers and compute the A-to-F gap. The right-hand "Business impact" column is customer-specific: keep it as hypotheses and write which discovery question would confirm each one. Do not invent customer figures; keep the illustrative value-model formula and show a worked example **clearly labeled as illustrative** only if I ask. Include the "honest reading of the ladder" paragraph: where the big drops were, how small E was for a static Go binary, what a scan count cannot show. |
| **15 What I did not do** | Derive from missing evidence (bonus tasks, optional side-by-sides, Pull time, anything not captured) with a reason and a next step for each. Ask me when the reason is not inferable. |

**Friction events to pre-fill in Section 13 (all real):**
1. Docker apt repo file `/etc/apt/sources.list.d/docker.list` was emptied (running `sudo tee` alone, then Ctrl+C), so `apt` reported "no installation candidate" for `docker-ce`. Root cause: a pipeline run in two parts. Customer question: "How do you verify that a package repository is configured and signed correctly before an install runs in your build pipeline?"
2. `git clone` over SSH from the VM failed with `Permission denied (publickey)`: SSH agent was not forwarded into the VM. Question: "How do your build agents authenticate to source control, and where do their keys live?"
3. `docker build` failed with "the Dockerfile cannot be empty" because the editor buffer was unsaved. Question: "How do you ensure what's in Git is exactly what the build reads?"
4. The first version of `scripts/step.sh` stopped silently after printing `==> [A] scans` because `grype db status` returns non-zero before the vulnerability database exists, and strict shell mode aborted with no message. Root cause: a scanner/tooling step failing silently looks exactly like a clean scan. Question: "How do you know your scan pipeline actually ran, and what alerts you when a scanner returns nothing?"
5. BuildKit attached a provenance attestation by default, so the image digest changed on every rebuild even for identical images; fixed with `--provenance=false`. Question: "Which digest do you pin, and how do you keep it stable across rebuilds?"
6. `curl` appeared to return no body: the app sends no trailing newline, so `Hello World!` ran into the shell prompt. (Minor; include only as a one-line "observability" note.)

Also add rows for anything the evidence reveals, for example: a newer Go failing to build old dependencies at step C, the Gin bump raising the `go` line at step D, scanners disagreeing, scan DB drift across days, base-image tag movement, and absence of tests.

### Step 4: Self-audit before you finish
1. Search `FINDINGS.md` for every remaining `TBD`, empty cell, and `N/A`. Each must be intentional and explained. Print a grouped list.
2. Validate every table: consistent column counts per row; severities sum to totals; F equals E where required; B's module and stdlib counts compare sensibly to A's (if not, explain why); cumulative deltas equal the sum of step deltas.
3. Re-derive three numbers independently (a different method or tool) and confirm they match what you wrote.
4. Confirm every number in the document is traceable: add a short "Source:" line under each major table naming the evidence file(s) and the metric definition used.
5. Re-read Sections 0, 2b, 7, 9, and 14 for overclaiming. Make sure limitations are stated: arm64 not amd64; one run per step; DB dates; a static Go binary being the best case for minimal images; E changing two things; order-dependent attribution; findings are not risk.

---

## 5. Writing style for the narrative cells

- Concrete and short. Numbers first, then the one-sentence "why". Name tradeoffs without being asked.
- Say what surprised us and what we did not do.
- Never claim "zero CVEs" or "drop-in replacement". Use "near-zero baseline" only if the data shows it, and say for which scanner.
- Don't disparage alternatives (Alpine, Google distroless, Docker Hardened Images). State what each does well and where it is limited, as evidenced here.
- Attribute vendor claims to the vendor. Anything about Chainguard's SLA, pricing tiers, or product packaging is **not** in the evidence: do not state it as fact; if it is relevant, mark it "[verify at edu.chainguard.dev]".

---

## 6. Things that are easy to get wrong (check these)

- Source-mode govulncheck uses the VM's Go (1.27.3), not the image's Go; stdlib findings in image A come from **binary** mode.
- `ladder.csv`'s `go_modules` includes "other"; your Section 6 does not.
- Grype and Trivy count differently by design (data sources, unfixed handling, matching method). A single CVE can appear on several packages and be counted several times; say which unit each table uses.
- The image identifier is the local image ID, not a registry digest, unless a registry push happened (Bonus A).
- E's non-root default means non-root arrives at E, not F. In the runtime profile, a non-root process already has `CapEff = 0`, so F's additions show up in `CapBnd` and `NoNewPrivs`.
- Do not treat F's CVE counts as separate evidence: it is the same image as E.

---

## 7. Questions to ask me (after you've done everything possible; do not block on these)

Collect these and ask at the end, not up front: tool versions not in evidence (Multipass, Docker); time spent per step; confirmation of "package manager / compiler / source present" inferences; whether to mark specific remaining findings as Accept vs. Fix; whether any optional side-by-sides or bonus tasks were done outside `evidence/`.

---

## 8. Definition of done

- `FINDINGS.md` has every section populated or explicitly marked `N/A` / `Not attempted` with a reason, no stray `TBD`s except those listed as awaiting my input, valid Markdown tables, and a "Source:" line under each major table.
- Section 0 (executive summary) is written last and reflects the final numbers.
- `REVIEW-NOTES.md` exists (Section 9).
- Your final chat message follows the format in Section 9.

---

## 9. Outputs

1. **`FINDINGS.md`** (edited in place; backup at `FINDINGS.pre-populate.md`).
2. **`REVIEW-NOTES.md`** at the repo root, for my eyes only (I may delete it before sharing the repo), containing: the evidence inventory; every quality-gate failure; every conflict between my pre-filled cells and the evidence; every assumption you made; stale files found; the proposed dispositions awaiting my review; and the "needs input from the user" list with the exact command that would capture each missing item.
3. **Your final chat message**, brief and structured: (a) what you populated; (b) the headline findings in 5-8 bullets (the waterfall); (c) anything surprising or contradicting the hypotheses; (d) data-quality problems; (e) the top items I must review or supply. Do not paste the whole document.

Begin with Step 1 (inventory and quality gates) and print the results before filling anything in.
