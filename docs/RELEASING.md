# Releasing

CI runs tests, zizmor workflow checks, and a container build for pull requests and changes on `main`. Dependabot checks NuGet, Docker, Compose, and GitHub Actions weekly, with a seven-day cooldown for version updates.

## Publish an image

1. Merge the release changes into `main` after CI passes.
2. Tag the merged commit with `vMAJOR.MINOR.PATCH` and push the tag.

```sh
git tag v1.2.3
git push origin v1.2.3
```

The tag workflow runs tests and zizmor before publishing. It rejects malformed tags and commits outside `main`. Images are published to `ghcr.io/f-bader/threatintelaggro` for `linux/amd64` and `linux/arm64`, with exact (`1.2.3`), minor (`1.2`), major (`1`), and `latest` tags.

For the first release, set the GHCR package visibility to Public if anonymous pulls are intended. To deploy a version, set `AGGRO_IMAGE_TAG=1.2.3` in `.env`, then run `docker compose pull` and `docker compose up -d`.

## Repository checks

Configure a branch ruleset for `main` in GitHub settings if pull requests and passing CI should be mandatory. Require the `test`, `zizmor`, and `container-build` checks. Workflow files alone do not enforce branch protection.

Enable Dependabot alerts and security updates in repository settings. The [CI workflow](../.github/workflows/ci.yml) and [Dependabot configuration](../.github/dependabot.yml) are the references for current automation.
