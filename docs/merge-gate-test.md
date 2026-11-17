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
- **A required check with a path filter blocks every pull request that does not trigger it** (case 2). This is why the Molecule workflow in this repository is not a required check: it runs only when `ansible/**` changes, so making it required would leave other pull requests waiting forever.
  A way around it is an always-running job that decides internally what to skip. That is not implemented here.

## Limits

- The owner of the repository was tested. With no bypass actors the owner is bound by the rule, but a second account without admin rights was not used.
- The "branch must be up to date" option was not enabled.
- The first run of case 1 did not trigger `docs-check`, so two things blocked that merge. It was repeated as case 1b with `docs-check` passing, so only the red lint could block it.
- The test ran in a lab repository. The ruleset of this repository is configured separately and was not part of this run.

## Repeat it

The scripts are in `tools/merge-gate-lab/`. They need the GitHub CLI (`gh`) logged in with the `repo` and `workflow` scopes.

1. `bash merge_gate_setup.sh` creates the disposable repository and the ruleset.
2. `bash merge_gate_run.sh` runs the four cases (about 10 minutes) and writes `~/merge-gate-results.md`. `merge_gate_case1b.sh` is an optional extra run of case 1 on its own.
3. Save the results, then `bash merge_gate_cleanup.sh` deletes the repository (it needs the `delete_repo` scope and asks you to type `DELETE`).

The test design follows a suggestion from a public discussion: test a deliberately failing change, a required check that never reports, and a new commit after a green run; record "job red" and "merge blocked" separately.
