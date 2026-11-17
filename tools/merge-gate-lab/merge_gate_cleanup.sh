#!/usr/bin/env bash
# merge_gate_cleanup.sh
# Deletes the DISPOSABLE test repo and its local folder.
# Run it ONLY after merge_gate_run.sh finished and you saved ~/merge-gate-results.md
# (and took any screenshots you want from the PR pages).
set -euo pipefail

REPO_NAME="merge-gate-lab"
OWNER=$(gh api user --jq .login)
SLUG="$OWNER/$REPO_NAME"

if [ ! -s "$HOME/merge-gate-results.md" ]; then
  echo "~/merge-gate-results.md is missing or empty. Run merge_gate_run.sh first."
  exit 1
fi

echo "This will permanently delete: $SLUG (GitHub) and $HOME/$REPO_NAME (local)."
read -r -p "Type DELETE to continue: " ANSWER
[ "$ANSWER" = "DELETE" ] || { echo "Cancelled."; exit 1; }

if ! gh repo delete "$SLUG" --yes; then
  echo "Delete failed. If the error mentions the delete_repo scope, run:"
  echo "  gh auth refresh -h github.com -s delete_repo"
  echo "then run this script again."
  exit 1
fi
rm -rf "$HOME/$REPO_NAME"
echo "Deleted. Results are kept in $HOME/merge-gate-results.md"
