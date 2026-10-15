# Changelog

## 0.4.0 - 2026-10-02

- `carabiner fix` pins every GitHub Action to its commit SHA.

## 0.3.1 - 2026-09-27

- Fixed three false results found by scanning well-known repositories.

## 0.3.0 - 2026-09-26

- Five new drills; repository rulesets count as protection.
- GitLab SAST output.
- Detects a Docker build context that ships `.git`.
- Every tag gets a Release, checked by CI011.

## 0.2.1 - 2026-08-23

- `--diff` scanned nothing on Windows.

## 0.2.0 - 2026-08-23

- `--diff` mode for pre-commit.
- Kubernetes, Jenkins, CircleCI and Azure Pipelines checks.
- Two more drills.

## 0.1.x - 2026-08-23

- Untrusted-trigger rule family, a native Dockerfile engine, severity calibration from a 60-repository sweep, and Windows fixes.

## 0.1.0 - 2026-08-22

- First release: scan, the ratchet baseline, expiring debt, SARIF, a GitHub Action, a pre-commit hook, the drill, and GitLab CI support.
