#!/usr/bin/env bash
# merge_gate_run.sh
# Runs four cases in the disposable repo and records TWO separate outcomes for each:
#   (a) what the check job did, (b) whether the merge was actually blocked.
#   case0  control: a good change            -> merge allowed (CLEAN)
#   case1  deliberately failing lint         -> job red, merge blocked
#   case2  required check that never reports -> merge blocked
#   case3  new commit after an earlier green -> merge blocked until the new commit has evidence
# Takes about 10 minutes. Results are saved to ~/merge-gate-results.md
set -uo pipefail   # no -e on purpose: refused merges are the expected outcome

REPO_NAME="merge-gate-lab"
RESULTS="$HOME/merge-gate-results.md"
cd "$HOME/$REPO_NAME" || { echo "Run merge_gate_setup.sh first."; exit 1; }
OWNER=$(gh api user --jq .login)
SLUG="$OWNER/$REPO_NAME"

# ---------- helpers ----------
new_branch() {  # $1 = branch name, starts from fresh main
  git checkout -q main && git pull -q
  git checkout -q -b "$1"
}
commit_push() {  # $1 = branch, $2 = message
  git add -A && git commit -q -m "$2" && git push -q -u origin "$1"
}
open_pr() {  # $1 = branch, $2 = title -> prints PR number
  local url
  url=$(gh pr create --repo "$SLUG" --head "$1" --base main --title "$2" --body "Merge-gate test case ($1)" | tail -1)
  basename "$url"
}
check_state() {  # $1 = PR, $2 = check name -> "STATUS/CONCLUSION" or "absent"
  gh pr view "$1" --repo "$SLUG" --json statusCheckRollup --jq \
    "[.statusCheckRollup[]? | select(.name==\"$2\")] | if length==0 then \"absent\" else (.[0].status + \"/\" + (.[0].conclusion // \"\")) end"
}
wait_check() {  # $1 = PR, $2 = check name; waits up to ~9 min for COMPLETED
  local s
  for _ in $(seq 1 54); do
    s=$(check_state "$1" "$2")
    case "$s" in COMPLETED/*) echo "$s"; return;; esac
    sleep 10
  done
  echo "TIMEOUT($s)"
}
merge_state() {  # $1 = PR
  local s
  for _ in 1 2 3 4 5; do
    s=$(gh pr view "$1" --repo "$SLUG" --json mergeStateStatus --jq .mergeStateStatus)
    [ "$s" != "UNKNOWN" ] && break
    sleep 3
  done
  echo "$s"
}
head_sha() { gh pr view "$1" --repo "$SLUG" --json headRefOid --jq '.headRefOid[0:7]'; }
try_merge() {  # $1 = PR -> sets MERGE_RC and MERGE_MSG (first line)
  local out
  out=$(gh pr merge "$1" --repo "$SLUG" --merge 2>&1)
  MERGE_RC=$?
  MERGE_MSG=$(printf '%s' "$out" | head -1 | tr '|' '/')
}

declare -A R   # results, keyed by case

# ---------- case0: control ----------
echo "== case0: good change (control) =="
new_branch case0-good
echo "case0 $(date -u +%H:%M:%S)" >> docs/README.md
commit_push case0-good "case0: good docs change"
PR=$(open_pr case0-good "case0: good change (control)")
L=$(wait_check "$PR" lint); D=$(wait_check "$PR" docs-check)
MS=$(merge_state "$PR")
if [ "$L" = "COMPLETED/SUCCESS" ] && [ "$D" = "COMPLETED/SUCCESS" ] && [ "$MS" = "CLEAN" ]; then V=PASS; else V=FAIL; fi
R[0]="| 0 control: good change | lint=$L, docs-check=$D | $MS | not attempted (should be allowed) | $V |"
echo "${R[0]}"

# ---------- case1: failing lint ----------
echo "== case1: deliberately failing lint =="
new_branch case1-bad-lint
sed -i 's/ansible.builtin.debug:/debug:/' ansible/site.yml
echo "case1 $(date -u +%H:%M:%S)" >> docs/README.md
commit_push case1-bad-lint "case1: break FQCN on purpose"
PR=$(open_pr case1-bad-lint "case1: failing lint")
L=$(wait_check "$PR" lint)
MS=$(merge_state "$PR")
try_merge "$PR"
if [ "$L" = "COMPLETED/FAILURE" ] && [ "$MS" = "BLOCKED" ] && [ "$MERGE_RC" -ne 0 ]; then V=PASS; else V=FAIL; fi
R[1]="| 1 failing lint | lint=$L | $MS | rc=$MERGE_RC: $MERGE_MSG | $V |"
echo "${R[1]}"

# ---------- case2: required check never reports ----------
echo "== case2: required check that never reports =="
new_branch case2-never-reports
echo "# touched" >> ansible/site.yml          # lint passes; docs/** untouched, so docs-check never runs
commit_push case2-never-reports "case2: change that does not trigger docs-check"
PR=$(open_pr case2-never-reports "case2: required check never reports")
L=$(wait_check "$PR" lint)
sleep 20                                      # give GitHub time to start docs-check if it were going to
D=$(check_state "$PR" docs-check)
MS=$(merge_state "$PR")
try_merge "$PR"
if [ "$L" = "COMPLETED/SUCCESS" ] && [ "$D" = "absent" ] && [ "$MS" = "BLOCKED" ] && [ "$MERGE_RC" -ne 0 ]; then V=PASS; else V=FAIL; fi
R[2]="| 2 required check never reports | lint=$L, docs-check=$D | $MS | rc=$MERGE_RC: $MERGE_MSG | $V |"
echo "${R[2]}"

# ---------- case3: new commit after an earlier green run ----------
echo "== case3: new commit after a green run =="
new_branch case3-new-commit
echo "first $(date -u +%H:%M:%S)" >> docs/README.md
commit_push case3-new-commit "case3: first commit"
PR=$(open_pr case3-new-commit "case3: new commit after green run")
L1=$(wait_check "$PR" lint); D1=$(wait_check "$PR" docs-check)
MS1=$(merge_state "$PR"); SHA1=$(head_sha "$PR")
echo "after first commit $SHA1: lint=$L1 docs-check=$D1 state=$MS1"
echo "second $(date -u +%H:%M:%S)" >> docs/README.md
commit_push case3-new-commit "case3: second commit"
MS2=$(merge_state "$PR"); SHA2=$(head_sha "$PR")
L2now=$(check_state "$PR" lint)
try_merge "$PR"                                # immediately, before the new run has reported
L2=$(wait_check "$PR" lint); D2=$(wait_check "$PR" docs-check)
MS3=$(merge_state "$PR")
if [ "$MS1" = "CLEAN" ] && [ "$SHA1" != "$SHA2" ] && [ "$MS2" != "CLEAN" ] && [ "$MERGE_RC" -ne 0 ]; then V=PASS; else V=FAIL; fi
R[3]="| 3 new commit after green run | $SHA1: lint=$L1, docs-check=$D1 -> $SHA2 right after push: lint=$L2now; later lint=$L2, docs-check=$D2 | $MS1 -> $MS2 -> $MS3 | rc=$MERGE_RC (immediately after push): $MERGE_MSG | $V |"
echo "${R[3]}"

# ---------- write results ----------
{
  echo "# Merge gate test results"
  echo
  echo "Repository: https://github.com/$SLUG (disposable). Ruleset: pull request + required checks \`lint\` and \`docs-check\`, no bypass actors."
  echo "Date (UTC): $(date -u +%Y-%m-%d)"
  echo
  echo "A red job and a blocked merge are separate outcomes, so both are recorded."
  echo
  echo "| Case | Check jobs | mergeStateStatus | Merge attempt | Verdict |"
  echo "|---|---|---|---|---|"
  for i in 0 1 2 3; do echo "${R[$i]}"; done
  echo
  echo "Notes: the repository owner was tested (no bypass actors, so admins are bound). A second non-admin account was not used."
} > "$RESULTS"

echo
echo "Saved: $RESULTS"
echo "Open PRs stay in the repo. Look at them in the browser if you want screenshots, then run merge_gate_cleanup.sh."
