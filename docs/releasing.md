# Releasing

Releases are built in GitHub Actions and uploaded to PyPI with OpenID Connect. No long-lived
PyPI token is stored in GitHub.

## One-time PyPI setup

Create a pending Trusted Publisher for the first release, or add a publisher to the existing
project, with these values:

| PyPI field | Value |
| --- | --- |
| PyPI project name | `litestar-keycloak-admin` |
| GitHub owner | `alexkorolex` |
| Repository name | `litestar_keycloak_admin` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Create a protected `pypi` environment in the GitHub repository. Requiring approval for that
environment adds a manual checkpoint before publication.

## Release checklist

1. Pull the latest `main` and confirm CI passes.
2. Choose a PEP 440 version and update `project.version` in `pyproject.toml`.
3. Move the entries from `Unreleased` in `CHANGELOG.md` into a section named for the version and
   release date, then add a fresh `Unreleased` section.
4. Refresh the lock file and run the local release checks:

   ```bash
   uv lock
   uv sync --locked --group dev
   uv run ruff check .
   uv run ruff format --check .
   uv run pytest
   uv build
   uv run twine check --strict dist/*
   ```

5. Commit and push the version and changelog changes.
6. Create a GitHub release with a tag matching the version, for example `v0.1.0`.
7. Approve the `pypi` environment deployment if protection rules require it.
8. Verify the new release on PyPI and install it in a clean environment.

PyPI does not allow replacing an uploaded distribution. If publication fails after any file was
accepted, increment the version before retrying.
