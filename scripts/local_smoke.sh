#!/usr/bin/env sh
set -eu

GO_BIN=${GO:-go}
VERSION=${VERSION:-v0.2.1-rc-local}
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
revocation_path="${tmp_dir}/revocations.json"
log_path="${tmp_dir}/aegis.log"
unauth_body="${tmp_dir}/unauth.json"
auth_body="${tmp_dir}/auth.json"
virtual_key_path="${tmp_dir}/smoke.jwt"
issue_status="${tmp_dir}/issue.status"
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
	-e "s#\"file_path\": \"aegis.revocations.json\"#\"file_path\": \"${revocation_path}\"#" \
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

"$bin_path" operator revocation init --config "$config_path" >&2

master_key=$(openssl rand -hex 32)
jwt_key=$(openssl rand -hex 64)
printf '%s' 'sk-smoke-provider-key' | \
  AEGIS_MASTER_KEY="$master_key" \
  "$bin_path" operator provider-key import \
    --config "$config_path" --provider openai-primary >&2
AEGIS_JWT_KEY="$jwt_key" \
  "$bin_path" operator virtual-key issue \
    --config "$config_path" \
    --subject smoke-client \
    --models gpt-4o-mini \
    --ttl 5m \
    --out "$virtual_key_path" 2>"$issue_status"
cat "$issue_status" >&2
virtual_key_id=$(sed -n 's/^virtual_key_issued kid=\([^ ]*\).*/\1/p' "$issue_status")
test -n "$virtual_key_id"
test "$(stat -f '%Lp' "$virtual_key_path" 2>/dev/null || stat -c '%a' "$virtual_key_path")" = "600"

AEGIS_MASTER_KEY="$master_key" \
AEGIS_JWT_KEY="$jwt_key" \
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

virtual_key=$(tr -d '\r\n' <"$virtual_key_path")
auth_status=$(curl -sS -o "$auth_body" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer ${virtual_key}" \
  -H 'Content-Type: application/json' \
  --data '{' \
  "http://127.0.0.1:${PORT}/v1/chat/completions" || true)
test "$auth_status" = "400"
printf 'valid_auth_pre_revoke_status=%s\n' "$auth_status"

"$bin_path" operator virtual-key revoke \
  --config "$config_path" --kid "$virtual_key_id" >&2
revoked_status=''
for _ in $(seq 1 30); do
  revoked_status=$(curl -sS -o "$auth_body" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer ${virtual_key}" \
    -H 'Content-Type: application/json' \
    --data '{' \
    "http://127.0.0.1:${PORT}/v1/chat/completions" || true)
  if [ "$revoked_status" = "401" ]; then
    break
  fi
  sleep 0.025
done
test "$revoked_status" = "401"
printf 'revoked_auth_status=%s\n' "$revoked_status"

status=$(curl -sS -o "$unauth_body" -w '%{http_code}' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data '{"model":"gpt-4o-mini","messages":[]}' \
  "http://127.0.0.1:${PORT}/v1/chat/completions" || true)
test "$status" = "401"
printf 'unauth_status=%s\n' "$status"
