# pam-passkey justfile
#
# The repository holds the design docs and the prerequisite PoCs; the module
# itself is not implemented yet, so there is no release flow (no VERSION, no
# bump). VCS-shaped gates delegate to `bump-semver vcs` as in the canonical
# justfile of kawaz/bump-semver.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# default behaviour: alias for `list`
default: list

# show the recipe list
list:
    @just --list --unsorted

# ---------- atomic (lint / poc) ----------

# just --fmt (justfile self-format check)
[private]
lint-just:
    just --unstable --fmt --check

# all lints
lint: lint-just

# build and test the PoCs (artifacts stay in each poc/*/target/)
poc:
    cd poc/pam && cargo build --release && cargo test
    cd poc/keychain && cargo build --release

# ---------- gates (used by `just push`; rarely invoked directly) ----------

# working copy is clean
[private]
ensure-clean:
    bump-semver vcs is clean

# fail if the current bookmark / branch is not the default
[private]
check-on-default-branch:
    bump-semver vcs is on-default-branch

# README-ja → README, DESIGN-ja → DESIGN translation pair freshness
[private]
check-outdated-translations: ensure-clean
    bump-semver vcs outdated 'glob:**/*-ja.md' '$1/$2.md'

# ---------- push ----------

# push the default branch to origin (clean + lint + translation freshness)
push: check-on-default-branch ensure-clean lint check-outdated-translations
    bump-semver vcs push --branch "$(bump-semver vcs get default-branch)" --jj-bookmark-auto-advance
