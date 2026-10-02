# Contributing

Thank you for improving `litestar-keycloak-admin`.

## Development setup

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required.

```bash
git clone https://github.com/alexkorolex/litestar_keycloak_admin.git
cd litestar_keycloak_admin
uv sync --group dev
```

The test suite uses an in-process HTTP server that emulates the Keycloak endpoints needed by
the package. A local Keycloak installation is not required.

## Quality checks

Run the same checks as CI before opening a pull request:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv build
uv run twine check --strict dist/*
```

Keep public behavior documented in `README.md` and record user-visible changes under the
`Unreleased` section of `CHANGELOG.md`. New behavior should include focused tests, including
failure cases where appropriate.

## Pull requests

- Keep changes focused and preserve backward compatibility unless the change is explicitly
  documented as breaking.
- Do not commit secrets, real access tokens, generated distributions, virtual environments, or
  Python bytecode.
- Use clear commit messages and explain why the change is needed in the pull request.
