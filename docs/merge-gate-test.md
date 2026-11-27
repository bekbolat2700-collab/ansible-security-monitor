# Does the merge gate really block merges?

A green or red CI job is not the same thing as a blocked merge. This page records
both outcomes separately, for four cases.

The test ran in a disposable public repository (deleted afterwards) with the same
kind of rule as a normal branch gate: a repository ruleset that requires a pull
request and two status checks, `lint` and `docs-check`, with **no bypass actors**.

- `lint` runs on every pull request (`ansible-lint --profile production`).
- `docs-check` only runs when `docs/**` changes (a path filter, like a paths-filtered Molecule job).

## Results

| # | Case | Check jobs | Merge | Verdict |
|---|------|------------|-------|---------|
| 0 | Control: a good change | `lint` passed, `docs-check` passed | allowed (`CLEAN`) | PASS |
| 1 | Deliberately failing lint (FQCN broken on purpose), `docs-check` also runs and passes (case 1b) | `lint` failed, `docs-check` passed | blocked (`BLOCKED`), merge refused | PASS |
| 2 | Required check that never reports | `lint` passed, `docs-check` never ran | blocked (`BLOCKED`), merge refused | PASS |
| 3 | New commit after an earlier green run | commit `d930640` was green and `CLEAN`; new commit `af31aea`: `lint` queued | `BLOCKED` right after the push, merge refused; `CLEAN` again once the new commit's checks passed | PASS |

Run date: 2026-11-16 (UTC).

## Findings

- A failing required check blocks the merge, not only the job.
- Evidence is per commit: a green run on an earlier commit does not carry over to a new one.
- **A required check with a path filter blocks every pull request that does not trigger it** (case 2). This is why the Molecule workflow in this repository was not a required check at first: it ran only when `ansible/**` changes, so making it required would have left other pull requests waiting forever. See [Molecule gate](#molecule-gate-always-run-workflow-and-a-final-gate-job) below for the fix.
  A way around it is an always-running job that decides internally what to skip. That is not implemented here.

## Limits

- The owner of the repository was tested. With no bypass actors the owner is bound by the rule, but a second account without admin rights was not used.
- The "branch must be up to date" option was not enabled.
- The first run of case 1 did not trigger `docs-check`, so two things blocked that merge. It was repeated as case 1b with `docs-check` passing, so only the red lint could block it.
- The four cases ran in a lab repository. The ruleset of this repository (`protect-master`: pull request required, required checks `lint`, `kics` and `correlation-engine-tests`, no bypass actors) was checked separately on 2026-11-17 with a test pull request that broke FQCN on purpose: `lint` failed, the other required checks passed, and the Merge button was disabled. That pull request was closed without merging.

## Repeat it

The scripts are in `tools/merge-gate-lab/`. They need the GitHub CLI (`gh`) logged in with the `repo` and `workflow` scopes.

1. `bash merge_gate_setup.sh` creates the disposable repository and the ruleset.
2. `bash merge_gate_run.sh` runs the four cases (about 10 minutes) and writes `~/merge-gate-results.md`. `merge_gate_case1b.sh` is an optional extra run of case 1 on its own.
3. Save the results, then `bash merge_gate_cleanup.sh` deletes the repository (it needs the `delete_repo` scope and asks you to type `DELETE`).

The test design follows a suggestion from a public discussion: test a deliberately failing change, a required check that never reports, and a new commit after a green run; record "job red" and "merge blocked" separately.

## Molecule gate: always-run workflow and a final gate job

Follow-up to the path-filter finding, using an idea from John Duggin. `molecule.yml` now runs on every pull request:

1. `changes` always runs and checks with `git diff` whether `ansible/**` or the workflow file itself changed.
2. `molecule` (Ubuntu 22.04 and 24.04) runs only if it did.
3. `molecule-gate` always runs (`if: always()`) and is the only Molecule check required by the ruleset. It fails if change detection failed, or if Molecule was needed and did not succeed; it passes when nothing in `ansible/` changed.

Observed (repository owner, one run per case):

| Case | `changes` | `molecule` | `molecule-gate` | Merge |
|---|---|---|---|---|
| Docs-only change | success | skipped | success | allowed |
| Deliberate Molecule failure (a wrong `maxauthtries` expectation in `verify.yml`), gate not yet required | success | failure (both distros) | failure | **allowed** |
| Same failure, `molecule-gate` added to the ruleset | success | failure (both distros) | failure (Required) | **blocked** |

The middle row is the point: a red gate that is not a required status check blocks nothing. The gate only protects the branch once it is required in the ruleset.

Limits: tested as the repository owner only, one run per case. The docs-only case ran before `molecule-gate` was added to the ruleset. The test pull requests were closed without merging.
