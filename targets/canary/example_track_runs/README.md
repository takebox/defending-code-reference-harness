# targets/canary/example_track_runs

A captured run of the four Day-1 tracks (`/threat-model` → `/vuln-scan`
→ `/triage` → `/patch`) chained over `targets/canary`. Use it to see what
each artifact looks like without burning tokens on a fresh scan, and as a
fixture: the files here are valid input for `/triage` and `/patch` directly.

## Artifacts

| File | Produced by | What to look at |
|---|---|---|
| `THREAT_MODEL.md` | `/threat-model bootstrap targets/canary` | §4 Threats table — T1 is the cluster all three planted bugs map to; §8 has class-level mitigations. |
| `VULN-FINDINGS.md` | `/vuln-scan targets/canary` | Five findings: three HIGH, one per planted parser bug, plus a LOW info-leak and a MEDIUM double-free at lower confidence — the spread `/triage` exists to sort out. |
| `VULN-FINDINGS.json` | `/vuln-scan targets/canary` | Machine-readable canonical findings, sorted by confidence; what `/triage` ingests. |
| `TRIAGE.md` | `/triage targets/canary/VULN-FINDINGS.json --repo targets/canary --auto --votes 3` | "Act on these" section: 4/5 confirmed by 3-vote adversarial verification, the double-free absorbed as a duplicate of the UAF, derived severity. |
| `TRIAGE.json` | `/triage …` | Per-finding `vote_breakdown`, `first_links` (reachability evidence), `rationale`. The canonical input for `/patch`. |
| `PATCHES.md` | `/patch TRIAGE.json --repo targets/canary --top 3` | One section per bug: rationale, variants checked, bypass considered, independent-reviewer verdict + style score. |
| `PATCHES.json` | `/patch TRIAGE.json --repo targets/canary --top 3` | Summary counts + per-finding review status. |
| `PATCHES/bug_NN/patch.diff` | `/patch …` (static mode) | Inert unified diffs — never auto-applied. Read these the way you'd read any incoming PR. |
| `PATCHES/bug_NN/patch_result.json` | `/patch …` (static mode) | `verified: static_review_only`, reviewer reason, out-of-scope-hunk list. |

## Use as a fixture

This directory is laid out like a run dir, so you can point downstream tracks
at it directly:

```bash
/triage targets/canary/example_track_runs/ --repo targets/canary
/patch targets/canary/example_track_runs/TRIAGE.json --repo targets/canary
```

(Both tracks write their outputs — `TRIAGE.*`, `PATCHES*` — to the directory
you invoke them from, and resume from any `.triage-state/` / `.patch-state/`
checkpoint left there by an interrupted run; `--fresh` starts over instead.
Run from a scratch directory to keep the checked-in copies pristine, or from
inside this one to regenerate them.)

## Exclusion-rule note

`targets/canary` self-documents as a deliberately vulnerable test fixture
(the file header literally says so). A *strict* run of `/triage` correctly
applies exclusion rule 2 (test-only / intended-design code) and drops the
findings as false positives — that's the right call when this code shows up
inside a real repo. For this captured example the rule was waived by operator
instruction, recorded in `TRIAGE.json:triage_context.environment`, so the
chain has work to pass to `/patch`. On a real target the same findings would
survive verification without the waiver.

## Execution-verified patching

These patches are `static_review_only` — authored and reviewed by reading
source, never compiled or run. For an example of the **execution-verified**
ladder (`vuln-pipeline patch`: build → reproduce → regress → re-attack), see
`targets/canary/fixtures/results_sample/` instead.
