# Releases, container images, and repository rules

## Image location and tags

The published image is `ghcr.io/f-bader/threatintelaggro`. Release tags are Git tags in the form `vMAJOR.MINOR.PATCH`, for example `v1.2.3`. Each release publishes a multi-platform image for `linux/amd64` and `linux/arm64` with these container tags:

- `1.2.3` — exact release; pin this tag for predictable deployments.
- `1.2` — latest patch release in that minor line.
- `1` — latest minor/patch release in that major line.
- `latest` — latest stable release.

The `publish-image` job runs only after the CI `test` job passes. It rejects malformed version tags and tags that do not point to a commit reachable from `main`.

## Release procedure

1. Merge the release changes through a pull request to `main` after the required CI checks pass.
2. Create and push a version tag from the merged commit, for example `git tag v1.2.3 && git push origin v1.2.3`.
3. GitHub Actions reruns the tests for the tag and publishes the image to GHCR only when they pass.
4. For the first publish, open the package settings under the repository’s **Packages** section and set package visibility to **Public** if the image should be pullable without GitHub credentials. Otherwise, users must authenticate to GHCR before pulling.

To deploy a specific version, set `AGGRO_IMAGE_TAG=1.2.3` in the server’s Compose `.env` file, then run:

```sh
docker compose pull
docker compose up -d
```

Omitting `AGGRO_IMAGE_TAG` uses `latest`. The deployment Compose file keeps the app bound to host loopback; keep the reverse proxy in front of it.

## Dependency updates

`.github/dependabot.yml` checks the Docker base images and Compose references, GitHub Actions, and test-project NuGet packages weekly. Dependabot opens version-update pull requests; the same `test` and `container-build` checks run on those PRs. Keep Dependabot security updates enabled in the repository’s **Settings → Advanced Security** if you want security-alert fixes proposed outside the weekly schedule.

## Require pull requests and CI on `main`

The workflow runs `test` and `container-build` on every pull request targeting `main`. GitHub repository settings must make those checks required; a workflow file alone cannot prevent a direct push.

Create an active branch ruleset in the repository:

1. Open **Settings → Rules → Rulesets → New branch ruleset**.
2. Name it `Protect main`; target the default branch (`main`) and set enforcement to **Active**.
3. Enable **Require a pull request before merging**. For a single-owner repository, the required approval count can remain zero; the PR is still mandatory.
4. Enable **Require status checks to pass before merging**. Add the `test` and `container-build` checks from the `CI` workflow. Require the branch to be up to date before merging.
5. Do not add bypass actors. Keep force pushes and branch deletion blocked.

GitHub lists a status check after it has reported at least once. On the first PR that adds this workflow, wait for both checks to appear, create and activate the ruleset before merging that PR, and then require both checks for later PRs. Select the check runs produced by the `CI` workflow so unrelated checks with similar names do not satisfy the rule.

## Container workflow

`compose.yaml` deploys the published GHCR image. For local source builds, use the `compose.dev.yaml` override:

```sh
docker compose -f compose.yaml -f compose.dev.yaml up --build
```

The Docker build context excludes local databases, secrets, build output, and test files via `.dockerignore`.
