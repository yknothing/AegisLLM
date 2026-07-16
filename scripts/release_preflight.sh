#!/usr/bin/env sh
set -eu

GO_BIN=${GO:-go}
ACTIONLINT_VERSION=${ACTIONLINT_VERSION:-v1.7.12}
VERSION=${VERSION:-v0.2.1-rc-local}

if [ "${ALLOW_DIRTY:-}" != "1" ] && [ -n "$(git status --porcelain)" ]; then
  echo "release preflight requires a clean worktree; set ALLOW_DIRTY=1 to override" >&2
  git status --short >&2
  exit 1
fi

"$GO_BIN" test -count=1 ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race -count=1 ./...
make lint GO="$GO_BIN"
make security GO="$GO_BIN"
workflow_count=0
for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
  if [ ! -f "$workflow" ]; then
    continue
  fi
  "$GO_BIN" run "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}" "$workflow"
  workflow_count=$((workflow_count + 1))
done
if [ "$workflow_count" -eq 0 ]; then
  echo "no GitHub Actions workflows found" >&2
  exit 1
fi
git diff --check

default_tags=$(make -n docker VERSION="$VERSION")
printf '%s\n' "$default_tags" | grep -F -- "-t aegis:${VERSION}" >/dev/null
if printf '%s\n' "$default_tags" | grep -F -- "-t aegis:latest" >/dev/null; then
  echo "default docker target must not tag aegis:latest" >&2
  exit 1
fi

latest_tags=$(make -n docker VERSION="$VERSION" DOCKER_TAG_LATEST=true)
printf '%s\n' "$latest_tags" | grep -F -- "-t aegis:${VERSION}" >/dev/null
printf '%s\n' "$latest_tags" | grep -F -- "-t aegis:latest" >/dev/null

GO="$GO_BIN" VERSION="$VERSION" scripts/local_smoke.sh

echo "release preflight passed"
