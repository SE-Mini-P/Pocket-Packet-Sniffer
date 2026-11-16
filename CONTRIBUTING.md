# Contributing to Pocket Packet Sniffer

## Workflow

1. Pick a backlog item (GitHub issue) **assigned to you**; the issue carries its story points and sprint label.
2. Branch from `main`: `feature/<topic>`, `fix/<topic>` or `docs/<topic>`.
3. Commit with a conventional message (`feat(scope): ...`, `fix: ...`, `docs: ...`) and reference the issue.
4. Open a pull request **from your own branch**, link the issue (`Closes #N`), and say what changed and how you tested it.
5. CI (`.github/workflows/ci.yml`) must pass: flake8 error checks, all unit and system tests, and the >= 70% statement + branch coverage gate.
6. **Review and merge:** the pull request is reviewed and approved by the **repository owner or another team member who is not the author**, and merged after approval. Authors do not merge their own PRs.

## Local checks

```bash
python -m unittest discover -s tests
python -m coverage run --branch -m unittest discover -s tests
python -m coverage report --show-missing --fail-under=70
```

## Changes after the Sprint 2 freeze

Feature changes need a documented Engineering Change Request recorded in `docs/SPRINT2_FREEZE.md` (§6). Documentation and CI-only changes are allowed but must be described as such in the PR.

## Team contributions

Individual assignments and story points are in the README backlog tables (§6) and on the GitHub issues. Every contribution is traceable through the commit history and the PRs each member raised.
