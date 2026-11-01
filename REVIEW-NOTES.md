# REVIEW-NOTES.md (for the author's eyes only; delete before sharing)

Generated while populating `FINDINGS.md`. Backup of the pre-populate file: `FINDINGS.pre-populate.md` (not committed).

## 1. Evidence inventory (branch `remediation`, HEAD `aef4ea7`)

| Step | grype | trivy | syft | props | build | scan-meta | buildinfo | govulncheck | runtime | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | 54.3 MB | 76.5 MB | 10.2 MB | yes | yes | yes | yes | binary + source | yes | complete |
| B | 0.43 MB | 0.9 MB | yes | yes | yes | yes | yes | binary | no | complete (runtime not required) |
| C | yes | yes | yes | yes | yes | yes | yes | binary | no | complete |
| D | yes | yes | yes | yes | yes | yes | yes | binary + source | no | complete |
| E | yes | yes | yes | yes | yes | yes | yes | binary | yes | complete |
| F | none | none | none | none | none | none | none | none | yes | runtime only (F = E assumed) |

Also present: `ladder.csv` (A to E), `diff-{A-B,B-C,C-D,A-D,D-E}.*.tsv`, `go-modules-before/after.txt`. Not present: `sbom/`, cosign, registry, Kubernetes, apko/melange, Ealt/Ebuild/Eapko.

## 2. Quality-gate results

- All `.json` scan files parse and are non-empty. All `*.log` files are empty (no scanner errors). `*.db-update.log` only record DB refreshes.
- Grype DB is identical for all five scans (Built 2026-11-01T06:20:12Z, Status valid). Trivy DB identical for B to E (UpdatedAt 2026-11-01 13:02:34 UTC). **`A.scan-meta.txt` has no Trivy DB lines**: A's Trivy DB date is unknown (flagged in Section 4 and the friction log).
- All scans were taken the same day (2026-11-01, 17:35Z to 18:34Z): no cross-day drift. `scripts/rescan-all.sh` is therefore not required for Grype; it would fix the A Trivy DB gap.
- **F has no scans and no props/image ID.** F = E is an assumption. Verify with `docker image inspect -f '{{.Id}}' hello:e-chainguard hello:f-hardened`.
- Arithmetic: severities sum to totals for every scanner and step (checked in script). A to F cumulative equals the sum of step deltas (total, Critical+High, fixable).
- **`scripts/diff-steps.sh` bug**: `diff-D-E.{gone,still,new}.tsv` are all empty, but 3 findings (CVE-2025-60876 on busybox, busybox-binsh, ssl_client) are gone at E. Cause: awk `NR==FNR` idiom fails when the second input is empty. Also the script keys on CVE id only, so its counts differ by one from the unique (id, package) sets I computed at A to B. I used my own computed sets and said so in FINDINGS.md.
- **`ladder.csv` folds "other" into modules** at A (`go_modules` 135 = 17 modules + 118 `go` binary findings). Section 6 uses the precise split.
- **No git tags** (`step-A` to `step-F`, `ladder-complete`) exist in this clone; I cited commits instead.
- `.gitignore` check: `git check-ignore -v evidence/*` returned nothing, so no needed evidence is ignored (`evidence/bin/` is intentionally ignored and was not read).
- Stale numeric-ID files (`S1.*` etc.): none found.

## 3. Conflicts between your pre-filled cells and the evidence

None found. Your hypotheses, environment cells and Section 2a comments were left untouched (hypothesis column verified unchanged with a diff). Observations that touch your wording are recorded in "What actually happened" / "Did it hold" instead:
- 2a C-row comment says "Expect stdlib findings to drop sharply; nothing else should move": Grype also lost one x/text finding at C (unexplained).
- 2a B-row comment "module and stdlib findings unchanged": module count unchanged; the stdlib bucket fell 383 to 59 because toolchain binaries are no longer shipped (the application's own 59 are unchanged).
- Step E runtime base cell says `cgr.dev/<org>/static`; the build used `cgr.dev/checkmarx.com/static:latest`.

## 4. Assumptions I made

- Primary scanner = Grype (default in CLAUDE.md); Trivy used as cross-check.
- "Present but not called" = govulncheck's P + Q (imported packages + required modules); "found" = N + P + Q is my sum, not a govulncheck figure. The A binary split (about 48 stdlib / 12 x/net / 1 x/text) is derived by subtraction from the `Module:` lines.
- Package-manager / compiler / source-present cells are inferred from Syft + Dockerfiles (E: no `apk-tools` in Syft, `shell_present: no`).
- Time per step = gaps between commit timestamps (they include scanning); A not estimable (scan precedes its commit).
- "Docker's default capability set" for `CapBnd a80425fb` is my inference, not in the evidence.
- The single remaining govulncheck "1 vulnerability in a required module" at D/E may be GO-2026-5932; unconfirmed.
- The Grype x/text GHSA-ppp9-7jff-5vj2 disappearance at C and Grype's lack of x/crypto matches (while Trivy has 25) are reported as unexplained / hypotheses.

## 5. Proposed dispositions (judgment, for your review)

| Finding | Proposed | Note |
|---|---|---|
| GO-2026-5932 `golang.org/x/crypto` openpgp unmaintained (Trivy only, UNKNOWN, no fix) | Accept | Confirm that nothing imports `openpgp` (`go list -deps ./... \| grep openpgp`). |
| CVE-2025-60876 busybox (Grype only, D and earlier) | n/a at E | Gone at E; no disposition needed at the final image. |

## 6. Needs input from you (with the command to capture it)

| Item | Command / action |
|---|---|
| Multipass, Docker versions; host `uname` | `multipass version; docker version; uname -a; go version` into `evidence/environment.txt` |
| Section 1 "Why / Tradeoff" cells still `TBD` (your rationale) | Write them yourself (guest OS, arch, Docker, Grype, Trivy, Syft, cosign) |
| Time lost per friction item | Fill `TBD (user)` in Section 13 |
| F image ID equals E | `docker image inspect -f '{{.Id}}' hello:e-chainguard hello:f-hardened` |
| Gin release-mode log check | `docker logs <name>` from an F run |
| Base-image digests | `docker buildx imagetools inspect golang:1.27.3`, `alpine:3`, `cgr.dev/checkmarx.com/static:latest` |
| Confirm inferred cells (shell / package manager / compiler / source) | `docker run --rm --entrypoint sh <image> -c 'command -v apt-get apk go gcc; ls /app'` |
| Pull time | `time docker pull <image>` from a clean cache |
| Trivy DB date for A | `scripts/rescan-all.sh` |
| Per-step `curl` output; B write test | re-run and save under `evidence/` |
| Git tags | `git tag step-A 0be2e2e; git tag step-B 75d491c; git tag step-C a6ff36e; git tag step-D 64db612; git tag step-E 85fee63; git tag step-F aef4ea7` (confirm the commit mapping) |
| Bonuses / side-by-sides done outside `evidence/`? | Tell me if any exist |
| `diff-D-E.*.tsv` | Fix `scripts/diff-steps.sh` and re-run `scripts/diff-steps.sh D E` |
