# Release Automation Proposal for imap-mcp

## Goals

1. **Automatic changelogs** — generated from commit history
2. **Semantic versioning** — version bumps derived from conventional commits
3. **Tagged Docker images** — `ghcr.io/factorial-io/imap-mcp:v1.2.3`
4. **Fully automated via GitHub Actions** — minimal manual intervention

---

## Recommended Approach: `release-please` + `git-cliff` + existing Docker workflow

### Why this combination?

| Concern | Tool | Rationale |
|---|---|---|
| Version bumps & release PRs | [release-please](https://github.com/googleapis/release-please) | Battle-tested, supports Rust/Cargo.toml, creates release PRs automatically |
| Changelog generation | [git-cliff](https://git-cliff.org/) | More flexible than release-please's built-in changelog; used by Scotty; supports grouped/categorized entries |
| Docker image tagging | Existing `docker-build-push.yml` | Already handles tag-triggered builds to ghcr.io; just needs to react to release tags |
| GitLab deployment trigger | Existing workflow step | Already in place, no changes needed |

### Why not the alternatives?

- **release-plz**: Great for crates published to crates.io, but imap-mcp is a server — we don't `cargo publish`. release-plz's main advantage (registry comparison) doesn't apply.
- **semantic-release (Node.js)**: Adds a Node.js dependency to a Rust project. Heavier than needed.
- **cargo-release** (Scotty's approach): Good for local/manual releases, but requires someone to run `cargo release` locally or via `workflow_dispatch`. Less automated than release-please's PR-based flow.

---

## How It Works (End-to-End Flow)

```
Developer merges PR with conventional commits
        │
        ▼
release-please detects changes on `main`
        │
        ▼
Creates/updates a "Release PR" with:
  - Bumped version in Cargo.toml
  - Updated CHANGELOG.md (via git-cliff)
        │
        ▼
Team reviews & merges the Release PR
        │
        ▼
release-please creates a GitHub Release + git tag (v1.2.3)
        │
        ▼
docker-build-push.yml triggers on the new tag
  - Builds image: ghcr.io/factorial-io/imap-mcp:v1.2.3
  - Also tags: ghcr.io/factorial-io/imap-mcp:latest (on main)
        │
        ▼
GitLab pipeline triggered for deployment
```

---

## Implementation Plan

### 1. Enforce Conventional Commits

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add STARTTLS support for IMAP connections
fix: handle expired OIDC tokens gracefully
feat!: redesign session storage (BREAKING CHANGE)
chore: update dependencies
docs: add deployment guide
```

Version bumps are derived automatically:
- `fix:` → patch (0.0.x)
- `feat:` → minor (0.x.0)
- `feat!:` or `BREAKING CHANGE:` → major (x.0.0)

**Action**: Add a CI check to validate PR titles follow conventional commit format.

### 2. Add `git-cliff` Configuration

Create `cliff.toml` at the repo root (inspired by Scotty's config):

```toml
[changelog]
header = """
# Changelog

All notable changes to this project will be documented in this file.\n
"""
body = """
{%- macro remote_url() -%}
  https://github.com/factorial-io/imap-mcp
{%- endmacro -%}

{% if version -%}
    ## [{{ version | trim_start_matches(pat="v") }}] - {{ timestamp | date(format="%Y-%m-%d") }}
{% else -%}
    ## [Unreleased]
{% endif -%}

{% for group, commits in commits | group_by(attribute="group") %}
    ### {{ group | striptags | trim | upper_first }}
    {% for commit in commits %}
        - {% if commit.scope %}*({{ commit.scope }})* {% endif %}{{ commit.message | upper_first }} \
            ([{{ commit.id | truncate(length=7, end="") }}]({{ self::remote_url() }}/commit/{{ commit.id }}))\
    {% endfor %}
{% endfor %}
"""
trim = true

[git]
conventional_commits = true
filter_unconventional = true
split_commits = false
commit_parsers = [
    { message = "^feat", group = "<!-- 0 -->Features" },
    { message = "^fix", group = "<!-- 1 -->Bug Fixes" },
    { message = "^doc", group = "<!-- 3 -->Documentation" },
    { message = "^perf", group = "<!-- 4 -->Performance" },
    { message = "^refactor", group = "<!-- 2 -->Refactor" },
    { message = "^style", group = "Styling" },
    { message = "^test", group = "Testing" },
    { message = "^chore\\(release\\)", skip = true },
    { message = "^chore\\(deps.*\\)", group = "<!-- 5 -->Dependencies" },
    { message = "^chore|^ci", group = "<!-- 6 -->Miscellaneous" },
    { body = ".*security", group = "<!-- 7 -->Security" },
]
protect_breaking_commits = false
filter_commits = false
tag_pattern = "v[0-9].*"
sort_commits = "newest"
```

### 3. Add release-please Configuration

**`.release-please-manifest.json`**:
```json
{
    ".": "0.1.0"
}
```

**`release-please-config.json`**:
```json
{
    "release-type": "rust",
    "packages": {
        ".": {
            "changelog-path": "CHANGELOG.md",
            "bump-minor-pre-major": true,
            "bump-patch-for-minor-pre-major": true
        }
    }
}
```

> `bump-minor-pre-major: true` means that while version is `0.x.y`, a `feat:` bumps patch instead of minor. This is standard for pre-1.0 projects.

### 4. Add Release Workflow

**`.github/workflows/release.yml`**:

```yaml
name: Release

on:
  push:
    branches:
      - main

permissions:
  contents: write
  pull-requests: write

jobs:
  release-please:
    runs-on: ubuntu-latest
    outputs:
      release_created: ${{ steps.release.outputs.release_created }}
      tag_name: ${{ steps.release.outputs.tag_name }}
    steps:
      - uses: googleapis/release-please-action@v4
        id: release
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  # Regenerate changelog with git-cliff for richer formatting
  update-changelog:
    needs: release-please
    if: needs.release-please.outputs.release_created
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Generate changelog with git-cliff
        uses: orhun/git-cliff-action@v4
        with:
          config: cliff.toml
          args: --verbose
        env:
          OUTPUT: CHANGELOG.md
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Commit updated changelog
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add CHANGELOG.md
          git diff --staged --quiet || git commit -m "chore(release): update changelog"
          git push
```

### 5. Add Conventional Commit Lint for PRs

**`.github/workflows/commitlint.yml`**:

```yaml
name: Lint PR Title

on:
  pull_request:
    types: [opened, edited, synchronize]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: amannn/action-semantic-pull-request@v5
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This ensures all squash-merged PRs produce valid conventional commit messages.

### 6. Update Docker Workflow (Minor Tweak)

The existing `docker-build-push.yml` already triggers on tags and produces correct tags via `docker/metadata-action`. **No changes needed** — when release-please creates a `v1.2.3` tag, the Docker workflow will automatically build and push `ghcr.io/factorial-io/imap-mcp:v1.2.3`.

The only optional improvement: add `type=semver,pattern={{version}}` and `type=semver,pattern={{major}}.{{minor}}` to the metadata action for additional semver tags:

```yaml
tags: |
  type=ref,event=branch
  type=semver,pattern={{version}}
  type=semver,pattern={{major}}.{{minor}}
  type=raw,value=latest,enable=${{ github.ref == 'refs/heads/main' }}
```

This gives you:
- `ghcr.io/factorial-io/imap-mcp:1.2.3`
- `ghcr.io/factorial-io/imap-mcp:1.2`
- `ghcr.io/factorial-io/imap-mcp:latest`

---

## Files to Add/Modify

| File | Action |
|---|---|
| `cliff.toml` | **Create** — git-cliff config |
| `.release-please-manifest.json` | **Create** — current version tracker |
| `release-please-config.json` | **Create** — release-please settings |
| `.github/workflows/release.yml` | **Create** — release-please + git-cliff workflow |
| `.github/workflows/commitlint.yml` | **Create** — PR title linting |
| `.github/workflows/docker-build-push.yml` | **Modify** — add semver tag patterns |
| `CHANGELOG.md` | **Auto-generated** on first release |

---

## Migration Path

1. Merge this configuration into `main`
2. Start using conventional commit prefixes in PR titles
3. After the next merge to `main`, release-please will open the first Release PR
4. Merge the Release PR → tag `v0.1.1` (or similar) is created → Docker image is built and pushed
5. Going forward, release PRs accumulate automatically

---

## Comparison with Scotty's Approach

| Aspect | Scotty | imap-mcp (proposed) |
|---|---|---|
| Version bumps | `cargo release` (manual CLI) | release-please (automated PR) |
| Changelog | git-cliff (during release) | git-cliff (in CI) |
| Docker tags | Branch/tag based | Semver + latest |
| Trigger | Developer runs command | Merge Release PR |
| Homebrew | Yes (binary distribution) | N/A (server, not CLI) |

The key difference: Scotty uses a manual `cargo release` workflow because it distributes binaries via Homebrew. imap-mcp is a server deployed via Docker, so a fully automated PR-based flow is more appropriate.

---

## References

- [release-please](https://github.com/googleapis/release-please)
- [git-cliff](https://git-cliff.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [action-semantic-pull-request](https://github.com/amannn/action-semantic-pull-request)
- [Scotty's workflows](https://github.com/factorial-io/scotty/tree/main/.github/workflows)
