#!/usr/bin/env bash
# merge_gate_setup.sh
# Creates a DISPOSABLE public repo "merge-gate-lab" with a lint gate and a
# repository ruleset, so the merge gate can be tested without touching
# ansible-security-monitor. Nothing here changes your real repositories.
set -euo pipefail

REPO_NAME="merge-gate-lab"
WORKDIR="$HOME/$REPO_NAME"

command -v gh >/dev/null || {
  echo "gh is not installed. Run: sudo apt update && sudo apt install -y gh"
  exit 1
}
gh auth status >/dev/null 2>&1 || {
  echo "gh is not logged in. Run: gh auth login   (GitHub.com, HTTPS, login with browser)"
  echo "Do not paste tokens into any chat."
  exit 1
}

OWNER=$(gh api user --jq .login)
SLUG="$OWNER/$REPO_NAME"

[ -e "$WORKDIR" ] && { echo "$WORKDIR already exists. Run merge_gate_cleanup.sh first."; exit 1; }
if gh repo view "$SLUG" >/dev/null 2>&1; then
  echo "$SLUG already exists on GitHub. Run merge_gate_cleanup.sh first."
  exit 1
fi

mkdir -p "$WORKDIR/.github/workflows" "$WORKDIR/ansible" "$WORKDIR/docs"
cd "$WORKDIR"
git init -q -b main
if [ -z "$(git config user.email || true)" ]; then
  git config user.email "$OWNER@users.noreply.github.com"
  git config user.name "$OWNER"
fi

cat > ansible/site.yml <<'EOF'
---
- name: Merge gate lab
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Print a message
      ansible.builtin.debug:
        msg: hello
EOF

cat > docs/README.md <<'EOF'
# Docs

Changes under docs/ trigger the "docs-check" workflow.
EOF

cat > README.md <<'EOF'
# merge-gate-lab

Disposable repository that tests whether a merge gate really blocks merges.
EOF

# Required check #1: runs on EVERY pull request.
cat > .github/workflows/lint.yml <<'EOF'
name: Lint
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install ansible-lint
        run: pip install ansible-lint==26.11.0
      - name: Lint (production profile, no exceptions)
        run: ansible-lint --profile production ansible/
EOF

# Required check #2: only runs when docs/** changes (same shape as a paths-filtered Molecule job).
cat > .github/workflows/docs.yml <<'EOF'
name: Docs check
on:
  pull_request:
    paths:
      - "docs/**"
permissions:
  contents: read
jobs:
  docs-check:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "docs ok"
EOF

git add -A
git commit -q -m "Initial: lint gate lab"

gh repo create "$SLUG" --public --source=. --remote=origin --push \
  --description "Disposable lab: does the merge gate really block merges?"

# Ruleset: PR required, both checks required, NO bypass actors (the owner is bound too).
cat > /tmp/merge_gate_ruleset.json <<'EOF'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      } },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [ { "context": "lint" }, { "context": "docs-check" } ]
      } }
  ]
}
EOF
gh api "repos/$SLUG/rulesets" --method POST --input /tmp/merge_gate_ruleset.json >/dev/null
rm -f /tmp/merge_gate_ruleset.json

echo
echo "Ruleset state:"
gh api "repos/$SLUG/rulesets" --jq '.[] | "  " + .name + "  enforcement=" + .enforcement'
echo
echo "Done. Repo: https://github.com/$SLUG"
echo "Next: bash merge_gate_run.sh"
