# Contributing to bab

Issues and pull requests are welcome. For anything beyond a small fix, open an issue first so we can agree on the approach; the design is in [docs/design.md](docs/design.md).

## Set up

Python 3.11 or newer (CI uses 3.12).

```
python3 -m venv venv && venv/bin/pip install -e ".[dev]"
```

## Run the checks

These are the same steps CI runs (`.github/workflows/ci.yml`):

```
venv/bin/ruff check bab tests
make fga                       # fetch the OpenFGA CLI
make model PY=venv/bin/python  # regenerate model/example.fga from the catalogue
git diff --exit-code model/example.fga   # the model is generated; do not hand-edit it
make test-model PY=venv/bin/python
venv/bin/pytest -q
```

If you change a catalogue in `catalogues/`, regenerate the model and commit the result.

## Open a PR

1. Fork the repo and branch from `main`.
2. Make your change and run the checks above.
3. Open a PR describing what changed and why.
