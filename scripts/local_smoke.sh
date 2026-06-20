#!/usr/bin/env sh
set -eu

GO_BIN=${GO:-go}
VERSION=${VERSION:-v0.2.0-rc-local}
BUILD_DATE=${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}
PORT=${PORT:-18083}

HEAD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
COMMIT_PROVIDED=${COMMIT+x}
GIT_STATUS=$(git status --porcelain 2>/dev/null || true)
if [ "${ALLOW_DIRTY:-}" != "1" ] && [ -n "$GIT_STATUS" ]; then
  echo "local smoke requires a clean worktree; set ALLOW_DIRTY=1 to override" >&2
  git status --short >&2
  exit 1
fi
if [ -n "$GIT_STATUS" ]; then
  if [ -z "${COMMIT_PROVIDED:-}" ] || [ "${COMMIT:-}" = "$HEAD_COMMIT" ]; then
    COMMIT="workspace-${HEAD_COMMIT}"
  fi
  case "$COMMIT" in
    workspace-"${HEAD_COMMIT}"*) ;;
    *) echo "dirty local smoke COMMIT must start with workspace-${HEAD_COMMIT}" >&2; exit 1 ;;
  esac
else
  if [ -z "${COMMIT_PROVIDED:-}" ]; then
    COMMIT="$HEAD_COMMIT"
  fi
  if [ "$COMMIT" != "$HEAD_COMMIT" ]; then
    echo "clean local smoke COMMIT must equal current HEAD ${HEAD_COMMIT}" >&2
    exit 1
  fi
fi

case "$VERSION" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid VERSION: $VERSION" >&2; exit 1 ;;
esac
case "$COMMIT" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid COMMIT: $COMMIT" >&2; exit 1 ;;
esac
case "$BUILD_DATE" in
  *[!A-Za-z0-9._:+-]*|'') echo "invalid BUILD_DATE: $BUILD_DATE" >&2; exit 1 ;;
esac
case "$PORT" in
  *[!0-9]*|'') echo "invalid PORT: $PORT" >&2; exit 1 ;;
esac

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/aegis-local-smoke.XXXXXX")
bin_path="${tmp_dir}/aegis"
config_path="${tmp_dir}/aegis.json"
key_dir="${tmp_dir}/keys"
log_path="${tmp_dir}/aegis.log"
unauth_body="${tmp_dir}/unauth.json"
pid=''

cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$key_dir"
sed \
  -e "s#\"address\": \":8080\"#\"address\": \"127.0.0.1:${PORT}\"#" \
  -e "s#\"key_store_path\": \"aegis.keys\"#\"key_store_path\": \"${key_dir}\"#" \
  aegis.example.json >"$config_path"

"$GO_BIN" build -trimpath \
  -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o "$bin_path" \
  ./cmd/aegis

version_output=$("$bin_path" --version)
case "$version_output" in
  *"commit: ${COMMIT}"*) ;;
  *) echo "version output did not include expected commit ${COMMIT}: ${version_output}" >&2; exit 1 ;;
esac
printf 'version=%s\n' "$version_output"

AEGIS_MASTER_KEY=$(openssl rand -hex 32) \
AEGIS_JWT_KEY=$(openssl rand -hex 64) \
  "$bin_path" --config "$config_path" >"$log_path" 2>&1 &
pid=$!

health=''
for _ in $(seq 1 30); do
  if health=$(curl -fsS "http://127.0.0.1:${PORT}/health" 2>/dev/null); then
    break
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "aegis exited before health check succeeded" >&2
    cat "$log_path" >&2
    exit 1
  fi
  sleep 1
done
test "$health" = '{"status":"ok"}'
printf 'health=%s\n' "$health"

status=$(curl -sS -o "$unauth_body" -w '%{http_code}' "http://127.0.0.1:${PORT}/v1/chat/completions" || true)
test "$status" = "401"
printf 'unauth_status=%s\n' "$status"
