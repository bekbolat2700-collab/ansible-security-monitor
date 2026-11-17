#!/usr/bin/env bash
# merge_gate_case1b.sh
# Re-run of case 1 that ISOLATES the failing lint:
# this time the change also touches docs/, so docs-check runs and passes,
# and the only thing that can block the merge is the red lint job.
# Run it while the disposable repo still exists (before merge_gate_cleanup.sh).
set -uo pipefail

REPO_NAME="merge-gate-lab"
RESULTS="$HOME/merge-gate-results.md"
cd "$HOME/$REPO_NAME" || { echo "Repo folder $HOME/$REPO_NAME not found."; exit 1; }
OWNER=$(gh api user --jq .login)
SLUG="$OWNER/$REPO_NAME"
BRANCH="case1b-lint-only"

check_state() {  # $1 = PR, $2 = check name -> "STATUS/CONCLUSION" or "absent"
  gh pr view "$1" --repo "$SLUG" --json statusCheckRollup --jq \
    "[.statusCheckRollup[]? | select(.name==\"$2\")] | if length==0 then \"absent\" else (.[0].status + \"/\" + (.[0].conclusion // \"\")) end"
}
wait_check() {  # waits up to ~9 min for COMPLETED
  local s
  for _ in $(seq 1 54); do
    s=$(check_state "$1" "$2")
    case "$s" in COMPLETED/*) echo "$s"; return;; esac
    sleep 10
  done
  echo "TIMEOUT($s)"
}
merge_state() {
  local s
  for _ in 1 2 3 4 5; do
    s=$(gh pr view "$1" --repo "$SLUG" --json mergeStateStatus --jq .mergeStateStatus)
    [ "$s" != "UNKNOWN" ] && break
    sleep 3
  done
  echo "$s"
}

git checkout -q main && git pull -q
git checkout -q -b "$BRANCH" || { echo "Branch $BRANCH already exists."; exit 1; }
echo "case1b $(date -u +%H:%M:%S)" >> docs/README.md                 # makes docs-check run (and pass)
sed -i 's/ansible.builtin.debug:/debug:/' ansible/site.yml          # breaks FQCN on purpose
git add -A && git commit -q -m "case1b: break FQCN on purpose, docs-check also runs" && git push -q -u origin "$BRANCH"
URL=$(gh pr create --repo "$SLUG" --head "$BRANCH" --base main \
  --title "case1b: failing lint, docs-check passes" --body "Merge-gate test case 1b ($BRANCH)" | tail -1)
PR=$(basename "$URL")

L=$(wait_check "$PR" lint)
D=$(wait_check "$PR" docs-check)
MS=$(merge_state "$PR")
OUT=$(gh pr merge "$PR" --repo "$SLUG" --merge 2>&1); RC=$?
MSG=$(printf '%s' "$OUT" | head -1 | tr '|' '/')

if [ "$L" = "COMPLETED/FAILURE" ] && [ "$D" = "COMPLETED/SUCCESS" ] && [ "$MS" = "BLOCKED" ] && [ "$RC" -ne 0 ]; then V=PASS; else V=FAIL; fi
ROW="| 1b failing lint, docs-check passes | lint=$L, docs-check=$D | $MS | rc=$RC: $MSG | $V |"
echo "$ROW"

{
  echo
  echo "## Case 1b: failing lint with docs-check passing (re-run that isolates lint)"
  echo
  echo "In the first run of case 1, docs-check never reported either, so two things blocked the merge."
  echo
  echo "| Case | Check jobs | mergeStateStatus | Merge attempt | Verdict |"
  echo "|---|---|---|---|---|"
  echo "$ROW"
} >> "$RESULTS"

echo
echo "PR page for the screenshot: $URL"
echo "Appended to $RESULTS"
