#!/usr/bin/env sh
set -eu

REMOTE_HOST=${REMOTE_HOST:-ceo}
VERSION=${VERSION:-v0.2.0-docker-test}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo workspace)}
BUILD_DATE=${BUILD_DATE:-2026-06-20T00:00:00Z}
REMOTE_DOCKER_PATH='/Applications/Docker.app/Contents/Resources/bin:$PATH'

if [ "${ALLOW_DIRTY:-}" != "1" ] && [ -n "$(git status --porcelain)" ]; then
  echo "ceo docker smoke requires a clean worktree; set ALLOW_DIRTY=1 to override" >&2
  git status --short >&2
  exit 1
fi

case "$REMOTE_HOST" in
  *[!A-Za-z0-9._@-]*|'') echo "invalid REMOTE_HOST: $REMOTE_HOST" >&2; exit 1 ;;
esac
case "$VERSION" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid VERSION: $VERSION" >&2; exit 1 ;;
esac
case "$COMMIT" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid COMMIT: $COMMIT" >&2; exit 1 ;;
esac
case "$BUILD_DATE" in
  *[!A-Za-z0-9._:+-]*|'') echo "invalid BUILD_DATE: $BUILD_DATE" >&2; exit 1 ;;
esac

run_id=$(date -u +%Y%m%d%H%M%S)-$$
IMAGE=${IMAGE:-aegis:codex-docker-test-${run_id}}
CONTAINER=${CONTAINER:-aegis-codex-docker-test-${run_id}}
VOLUME=${VOLUME:-aegis-codex-docker-test-data-${run_id}}
PORT=${PORT:-18082}
for value in "$IMAGE" "$CONTAINER" "$VOLUME"; do
  case "$value" in
    *[!A-Za-z0-9._:-]*|'') echo "invalid docker identifier: $value" >&2; exit 1 ;;
  esac
done
case "$PORT" in
  *[!0-9]*|'') echo "invalid PORT: $PORT" >&2; exit 1 ;;
esac

remote_dir=$(ssh "$REMOTE_HOST" 'mktemp -d /tmp/aegis-docker-test.XXXXXX')
echo "remote_dir=${remote_dir}"

cleanup_remote() {
  ssh "$REMOTE_HOST" "rm -rf '${remote_dir}'" >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT

rsync -az --delete \
  --exclude '.git' \
  --exclude-from .dockerignore \
  ./ "${REMOTE_HOST}:${remote_dir}/"

ssh "$REMOTE_HOST" \
  "REMOTE_DIR='${remote_dir}' IMAGE='${IMAGE}' CONTAINER='${CONTAINER}' VOLUME='${VOLUME}' VERSION='${VERSION}' COMMIT='${COMMIT}' BUILD_DATE='${BUILD_DATE}' PORT='${PORT}' PATH=${REMOTE_DOCKER_PATH} sh -s" <<'REMOTE_SCRIPT'
set -eu
cd "$REMOTE_DIR"
bin_copy="/tmp/aegis-codex-docker-test-bin-${CONTAINER}"
unauth_body="/tmp/aegis-codex-unauth-body-${CONTAINER}"
cid=''

cleanup() {
  if [ -n "$cid" ]; then
    docker rm -f "$cid" >/dev/null 2>&1 || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -f "$bin_copy" "$unauth_body"
}
trap cleanup EXIT
cleanup

echo "== remote_preflight =="
printf 'host='; hostname
printf 'arch='; uname -m
printf 'docker_server='; docker version --format '{{.Server.Version}}'
printf 'docker_arch='; docker info --format '{{.Architecture}}'

echo "== docker_build =="
docker build --progress=plain --no-cache --pull \
  --build-arg VERSION="$VERSION" \
  --build-arg COMMIT="$COMMIT" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  -t "$IMAGE" .

echo "== image_inspect =="
docker image inspect "$IMAGE" --format 'image={{.Id}} os={{.Os}} arch={{.Architecture}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}} cmd={{json .Config.Cmd}}'
test "$(docker image inspect "$IMAGE" --format '{{.Os}}')" = "linux"
test "$(docker image inspect "$IMAGE" --format '{{.Architecture}}')" = "arm64"
test "$(docker image inspect "$IMAGE" --format '{{.Config.User}}')" = "nonroot:nonroot"
test "$(docker image inspect "$IMAGE" --format '{{json .Config.Entrypoint}}')" = '["/aegis"]'
test "$(docker image inspect "$IMAGE" --format '{{json .Config.Cmd}}')" = '["--config","/etc/aegis/aegis.json"]'

cid=$(docker create "$IMAGE" --version)
docker cp "$cid:/aegis" "$bin_copy"
docker rm "$cid" >/dev/null
cid=''
file "$bin_copy"
docker run --rm "$IMAGE" --version

echo "== readonly_runtime =="
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$CONTAINER" --read-only \
  -p "127.0.0.1:${PORT}:8080" \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  -e AEGIS_JWT_KEY="$(openssl rand -hex 32)" \
  -v "$VOLUME:/var/lib/aegis" \
  "$IMAGE" >/dev/null

health=''
for _ in $(seq 1 30); do
  if health=$(curl -fsS "http://127.0.0.1:${PORT}/health" 2>/dev/null); then
    break
  fi
  sleep 1
done
test "$health" = '{"status":"ok"}'
printf 'health=%s\n' "$health"

status=$(curl -sS -o "$unauth_body" -w '%{http_code}' "http://127.0.0.1:${PORT}/v1/chat/completions" || true)
test "$status" = "401"
printf 'unauth_status=%s\n' "$status"
docker inspect "$CONTAINER" --format 'readonly={{.HostConfig.ReadonlyRootfs}} user={{.Config.User}} mounts={{range .Mounts}}{{.Destination}}:{{.Type}} {{end}}'
test "$(docker inspect "$CONTAINER" --format '{{.HostConfig.ReadonlyRootfs}}')" = "true"
test "$(docker inspect "$CONTAINER" --format '{{.Config.User}}')" = "nonroot:nonroot"
REMOTE_SCRIPT
