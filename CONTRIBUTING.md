# Contributing

Bug reports and pull requests are welcome.

## Setup

```bash
git clone https://github.com/MaXiMo000/carabiner
cd carabiner
python -m pip install -e . pytest ruff==0.16.8
```

## Before opening a pull request

```bash
ruff check .
python -m pytest
```

- Keep changes focused: one fix or feature per pull request.
- Add a test that fails without your change.
- A check that could not run must never report as passing. New checks follow the
  same pass / fail / unverified rule as the existing ones.
- Update `README.md` and `CHANGELOG.md` when behaviour changes.

## Reporting a security problem

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
