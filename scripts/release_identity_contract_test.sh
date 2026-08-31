#!/usr/bin/env sh
set -eu
unset ALLOW_UNVERIFIED_ITERATION AEGIS_DISPOSABLE_CEO
unset BASH_ENV ENV
unset MAKEFILES MAKEFLAGS GNUMAKEFLAGS MAKEOVERRIDES MFLAGS

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
workspace_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
test_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/aegis-release-identity-test.XXXXXX")
test_root=$(CDPATH= cd "$test_root" && pwd -P)
trap '/bin/chmod -R u+w "$test_root" >/dev/null 2>&1 || :; /bin/rm -rf "$test_root"' EXIT INT TERM

release_preflight="$workspace_root/scripts/release_preflight.sh"
local_smoke="$workspace_root/scripts/local_smoke.sh"
ceo_docker_smoke="$workspace_root/scripts/ceo_docker_smoke.sh"
equals_pass='='P'ASS'

assert_file_contains() {
  path=$1
  expected=$2
  description=$3
  if ! /usr/bin/grep -F -- "$expected" "$path" >/dev/null; then
    echo "$description" >&2
    exit 1
  fi
}

assert_file_excludes() {
  path=$1
  forbidden=$2
  description=$3
  if /usr/bin/grep -F -- "$forbidden" "$path" >/dev/null; then
    echo "$description" >&2
    exit 1
  fi
}

for smoke_script in "$local_smoke" "$ceo_docker_smoke"; do
  for provider_id in openai-primary deepseek-primary; do
    assert_file_contains "$smoke_script" "--provider $provider_id" \
      "$smoke_script does not import enabled provider $provider_id"
  done
done

for identity_script in "$release_preflight" "$local_smoke" "$ceo_docker_smoke"; do
  for required in \
    'CANDIDATE_SOURCE_DIR' \
    'materialization_state' \
    'claimed_candidate_sha' \
    'claimed_candidate_tree' \
    'claimed_materialized_root_sha256' \
    'claimed_source_state' \
    'SCHEMA_VALIDATED_NOT_RELEASE_APPROVED' \
    'evidence_mode=ITERATION_ONLY' \
    'final_evidence=false' \
    'release_approved=false' \
    'materialized source must equal the canonical script workspace' \
    'identity_cleanup_stage_strict'
  do
    assert_file_contains "$identity_script" "$required" \
      "$identity_script is missing external materialized identity contract: $required"
  done
  for forbidden in \
    'CANDIDATE_SNAPSHOT' \
    'identity_extract_snapshot' \
    'snapshot_archive' \
    'snapshot_root' \
    'git archive' \
    'git status' \
    'git rev-parse' \
    'git write-tree' \
    'git update-index' \
    'git hash-object' \
    'git diff-files' \
    'rsync ' \
    'ssh "$REMOTE_HOST"' \
    "$equals_pass" \
    'source_evidence='
  do
    assert_file_excludes "$identity_script" "$forbidden" \
      "$identity_script retains forbidden candidate identity or evidence token: $forbidden"
  done
done

for identity_script in "$release_preflight" "$local_smoke" "$ceo_docker_smoke"; do
  for required in \
    'unset GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_SHALLOW_FILE GIT_EXTERNAL_DIFF' \
    'unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND' \
    'unset BASH_ENV ENV' \
    'unset MAKEFILES MAKEFLAGS GNUMAKEFLAGS MAKEOVERRIDES MFLAGS' \
    'GIT_CONFIG_NOSYSTEM=1' \
    'GIT_CONFIG_SYSTEM=/dev/null' \
    'GIT_CONFIG_GLOBAL=/dev/null' \
    'GIT_ATTR_NOSYSTEM=1' \
    'GIT_TERMINAL_PROMPT=0' \
    'GIT_NO_REPLACE_OBJECTS=1' \
    'GIT_NO_LAZY_FETCH=1' \
    'GOTOOLCHAIN=local' \
    'PATH=/usr/bin:/bin'
  do
    assert_file_contains "$identity_script" "$required" \
      "$identity_script does not sanitize ambient Git/tool execution: $required"
  done
done

for trusted_script in "$release_preflight" "$local_smoke"; do
  for required in \
    'GO command must be an absolute path' \
    'GOWORK=off GOFLAGS=-mod=readonly GOENV=off GOTOOLCHAIN=local' \
    'unset GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_SHALLOW_FILE GIT_EXTERNAL_DIFF' \
    'unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND' \
    'GIT_CONFIG_NOSYSTEM=1' \
    'GIT_CONFIG_SYSTEM=/dev/null' \
    'GIT_CONFIG_GLOBAL=/dev/null' \
    'GIT_ATTR_NOSYSTEM=1' \
    'GIT_TERMINAL_PROMPT=0' \
    'GIT_NO_REPLACE_OBJECTS=1' \
    'GIT_NO_LAZY_FETCH=1' \
    'PATH=/usr/bin:/bin'
  do
    assert_file_contains "$trusted_script" "$required" \
      "$trusted_script does not sanitize trusted Go/Git execution: $required"
  done
done
assert_file_contains "$local_smoke" \
  'BUILD_DATE=${BUILD_DATE:-$(/bin/date -u +"%Y-%m-%dT%H:%M:%SZ")}' \
  'local smoke does not use the fixed trusted date path before identity setup'
assert_file_contains "$release_preflight" \
  'unset MAKEFILES MAKEFLAGS GNUMAKEFLAGS MAKEOVERRIDES MFLAGS' \
  'release preflight does not clear inherited Make control variables'
release_make_call_count=$(/usr/bin/grep -c -F -- '/usr/bin/make' "$release_preflight")
if [ "$release_make_call_count" -ne 1 ]; then
  echo "release preflight must centralize all internal Make execution" >&2
  exit 1
fi
for required_make_boundary in \
  '/usr/bin/make -rR' \
  'SHELL=/bin/sh' \
  'GO="$TRUSTED_GO_BIN"' \
  'VERSION="$VERSION"' \
  'COMMIT="$technical_commit"' \
  'BUILD_DATE="$TRUSTED_BUILD_DATE"' \
  'GOLANGCI_VERSION="$TRUSTED_GOLANGCI_VERSION"' \
  'GOVULNCHECK_VERSION="$TRUSTED_GOVULNCHECK_VERSION"' \
  'GOSEC_VERSION="$TRUSTED_GOSEC_VERSION"' \
  'DOCKER_TAG_LATEST=false'
do
  assert_file_contains "$release_preflight" "$required_make_boundary" \
    "release preflight trusted Make boundary is incomplete: $required_make_boundary"
done
assert_file_contains "$ceo_docker_smoke" \
  'RUN_TOKEN=$(/usr/bin/openssl rand -hex 16)' \
  'ceo docker smoke does not use fixed trusted openssl for its ownership token'
assert_file_contains "$ceo_docker_smoke" \
  'REMOTE_HOST" != local' \
  'ceo docker smoke does not require execution on ssh ceo with REMOTE_HOST=local'

contract_sha256_file() {
  digest_path=$1
  if [ -x /usr/bin/shasum ]; then
    digest_output=$(/usr/bin/shasum -a 256 "$digest_path") || return 1
  elif [ -x /usr/bin/sha256sum ]; then
    digest_output=$(/usr/bin/sha256sum "$digest_path") || return 1
  else
    return 1
  fi
  digest_value=${digest_output%% *}
  case "$digest_value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  [ "${#digest_value}" -eq 64 ] || return 1
  printf '%s\n' "$digest_value"
}

contract_metadata() {
  metadata_path=$1
  if metadata_value=$(/usr/bin/stat -f '%u:%Lp:%d:%i' "$metadata_path" 2>/dev/null); then
    printf '%s\n' "$metadata_value"
    return 0
  fi
  /usr/bin/stat -c '%u:%a:%d:%i' "$metadata_path"
}

write_identity_lock() {
  lock_path=$1
  {
    printf '%s\n' \
      'schema=aegis-candidate-materialized-lock-v1' \
      'materialization_state=complete' \
      'claimed_candidate_sha=1111111111111111111111111111111111111111' \
      'claimed_candidate_tree=2222222222222222222222222222222222222222' \
      'claimed_worktree_clean=true' \
      'claimed_source_archive_sha256=3333333333333333333333333333333333333333333333333333333333333333' \
      'claimed_object_closure_sha256=4444444444444444444444444444444444444444444444444444444444444444' \
      'claimed_materialized_root_sha256=5555555555555555555555555555555555555555555555555555555555555555' \
      'claimed_verifier_sha256=6666666666666666666666666666666666666666666666666666666666666666' \
      'claimed_verifier_provenance_sha256=7777777777777777777777777777777777777777777777777777777777777777' \
      'claimed_materializer_sha256=8888888888888888888888888888888888888888888888888888888888888888' \
      'claimed_materializer_provenance_sha256=9999999999999999999999999999999999999999999999999999999999999999' \
      'claimed_materialized_format=aegis-readonly-source-git-dir-v1'
  } >"$lock_path"
  /bin/chmod 600 "$lock_path"
}

prepare_materialized_workspace() {
  prepared_root=$1
  prepared_readonly=$2
  /bin/mkdir -p \
    "$prepared_root/scripts" \
    "$prepared_root/.git/objects/pack" \
    "$prepared_root/.git/objects/info" \
    "$prepared_root/.git/info" \
    "$prepared_root/.git/refs/heads" \
    "$prepared_root/.github/workflows"
  /bin/cp "$release_preflight" "$prepared_root/scripts/release_preflight.sh"
  /bin/cp "$local_smoke" "$prepared_root/scripts/local_smoke.sh"
  /bin/cp "$ceo_docker_smoke" "$prepared_root/scripts/ceo_docker_smoke.sh"
  printf '%s\n' '#!/bin/sh' 'exit 0' \
    >"$prepared_root/scripts/release_identity_contract_test.sh"
  /bin/chmod 755 "$prepared_root/scripts/"*.sh
  printf '%s\n' 'ref: refs/heads/main' >"$prepared_root/.git/HEAD"
  printf '%s\n' '1111111111111111111111111111111111111111' \
    >"$prepared_root/.git/refs/heads/main"
  printf '%s\n' 'tracked filter=aegis-ambient-filter' >"$prepared_root/.gitattributes"
  printf '%s\n' 'raw fixture bytes' >"$prepared_root/tracked"
  {
    printf '%s\n' \
      '{' \
      '  "server": {"address": ":8080"},' \
      '  "kms": {"local": {"key_store_path": "aegis.keys"}},' \
      '  "revocation": {"file_path": "aegis.revocations.json"}' \
      '}'
  } >"$prepared_root/aegis.example.json"
  /bin/cp "$workspace_root/Makefile" "$prepared_root/Makefile"
  printf '%s\n' 'name: fixture' 'on: [push]' 'jobs: {}' \
    >"$prepared_root/.github/workflows/fixture.yml"
  printf '%s\n' 'FROM scratch' >"$prepared_root/Dockerfile"
  printf '%s\n' '.git' >"$prepared_root/.dockerignore"
  if [ "$prepared_readonly" = 1 ]; then
    /bin/chmod -R a-w "$prepared_root"
  fi
}

tooling_root="$test_root/tooling"
/bin/mkdir -p "$tooling_root"
fake_go="$tooling_root/fake-go"
fake_aegis_template="$tooling_root/fake-aegis-template"
ambient_filter_helper="$tooling_root/ambient-filter-helper"
ambient_filter_marker="$test_root/ambient-filter-executed"
env_sanitized_marker="$test_root/env-sanitized"
host_command_marker="$test_root/ambient-host-command-executed"
ambient_make_marker="$test_root/ambient-makefile-executed"
ambient_makefile="$tooling_root/ambient.mk"
ambient_shell_marker="$test_root/ambient-shell-env-executed"
ambient_shell_env="$tooling_root/ambient-shell-env"

printf '%s\n' "\$(shell /usr/bin/touch $ambient_make_marker)" >"$ambient_makefile"
printf '/usr/bin/touch "%s"\n' "$ambient_shell_marker" >"$ambient_shell_env"

{
  printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    ': >"$AMBIENT_FILTER_MARKER"'
} >"$ambient_filter_helper"
/bin/chmod 700 "$ambient_filter_helper"

cat >"$fake_go" <<'FAKE_GO'
#!/bin/sh
set -eu

ambient_failure() {
  printf 'fake Go observed unsafe ambient environment: %s\n' "$1" >&2
  "$AMBIENT_FILTER_HELPER"
  exit 96
}

[ "${GIT_CONFIG_PARAMETERS+x}" != x ] || ambient_failure GIT_CONFIG_PARAMETERS
[ "${GIT_EXEC_PATH+x}" != x ] || ambient_failure GIT_EXEC_PATH
[ "${GIT_SHALLOW_FILE+x}" != x ] || ambient_failure GIT_SHALLOW_FILE
[ "${GIT_EXTERNAL_DIFF+x}" != x ] || ambient_failure GIT_EXTERNAL_DIFF
[ "${GIT_DIR+x}" != x ] || ambient_failure GIT_DIR
[ "${GIT_WORK_TREE+x}" != x ] || ambient_failure GIT_WORK_TREE
[ "${GIT_COMMON_DIR+x}" != x ] || ambient_failure GIT_COMMON_DIR
[ "${GIT_INDEX_FILE+x}" != x ] || ambient_failure GIT_INDEX_FILE
[ "${GIT_OBJECT_DIRECTORY+x}" != x ] || ambient_failure GIT_OBJECT_DIRECTORY
[ "${GIT_ALTERNATE_OBJECT_DIRECTORIES+x}" != x ] || ambient_failure GIT_ALTERNATE_OBJECT_DIRECTORIES
[ "${GIT_REPLACE_REF_BASE+x}" != x ] || ambient_failure GIT_REPLACE_REF_BASE
[ "${GIT_ASKPASS+x}" != x ] || ambient_failure GIT_ASKPASS
[ "${SSH_ASKPASS+x}" != x ] || ambient_failure SSH_ASKPASS
[ "${GIT_SSH+x}" != x ] || ambient_failure GIT_SSH
[ "${GIT_SSH_COMMAND+x}" != x ] || ambient_failure GIT_SSH_COMMAND
[ "${GIT_PROXY_COMMAND+x}" != x ] || ambient_failure GIT_PROXY_COMMAND
[ "${GIT_CONFIG_KEY_37+x}" != x ] || ambient_failure GIT_CONFIG_KEY_37
[ "${BASH_ENV+x}" != x ] || ambient_failure BASH_ENV
[ "${ENV+x}" != x ] || ambient_failure ENV
[ "${MAKEFILES+x}" != x ] || ambient_failure MAKEFILES
[ "$PATH" = /usr/bin:/bin ] || ambient_failure PATH
[ "$GIT_CONFIG_NOSYSTEM" = 1 ] || ambient_failure GIT_CONFIG_NOSYSTEM
[ "$GIT_CONFIG_SYSTEM" = /dev/null ] || ambient_failure GIT_CONFIG_SYSTEM
[ "$GIT_CONFIG_GLOBAL" = /dev/null ] || ambient_failure GIT_CONFIG_GLOBAL
[ "$GIT_ATTR_NOSYSTEM" = 1 ] || ambient_failure GIT_ATTR_NOSYSTEM
[ "$GIT_TERMINAL_PROMPT" = 0 ] || ambient_failure GIT_TERMINAL_PROMPT
[ "$GIT_NO_REPLACE_OBJECTS" = 1 ] || ambient_failure GIT_NO_REPLACE_OBJECTS
[ "$GIT_NO_LAZY_FETCH" = 1 ] || ambient_failure GIT_NO_LAZY_FETCH
[ "$GOTOOLCHAIN" = local ] || ambient_failure GOTOOLCHAIN
[ "$GIT_CONFIG_COUNT" = 5 ] || ambient_failure GIT_CONFIG_COUNT
: >"$ENV_SANITIZED_MARKER"

if [ -n "${FAKE_GO_DRIFT_ROOT:-}" ] &&
   [ ! -e "${FAKE_GO_DRIFT_MARKER:-}" ]; then
  /bin/chmod u+w "$FAKE_GO_DRIFT_ROOT"
  : >"$FAKE_GO_DRIFT_MARKER"
fi

case "${1:-}" in
  build)
    output_path=''
    commit=unavailable
    previous=''
    for argument in "$@"; do
      if [ "$previous" = -o ]; then
        output_path=$argument
      fi
      case "$argument" in
        *main.commit=*)
          commit=${argument#*main.commit=}
          commit=${commit%% *}
          ;;
      esac
      previous=$argument
    done
    [ -n "$output_path" ] || exit 95
    /usr/bin/sed "s/__COMMIT__/$commit/g" "$FAKE_AEGIS_TEMPLATE" >"$output_path"
    /bin/chmod 700 "$output_path"
    ;;
  *)
    ;;
esac
FAKE_GO
/bin/chmod 700 "$fake_go"

cat >"$fake_aegis_template" <<'FAKE_AEGIS'
#!/bin/sh
set -eu
case "$*" in
  "--version")
    printf '%s\n' 'Aegis fixture (commit: __COMMIT__)'
    ;;
  "operator revocation init "*)
    ;;
  "operator provider-key import "*)
    /bin/cat >/dev/null
    ;;
  "operator virtual-key issue "*)
    output_path=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = --out ]; then output_path=$argument; fi
      previous=$argument
    done
    [ -n "$output_path" ] || exit 91
    umask 077
    printf '%s\n' fake-virtual-key >"$output_path"
    printf '%s\n' 'virtual_key_issued kid=fake-kid expires_at=2099-01-01T00:00:00Z' >&2
    ;;
  "operator virtual-key revoke "*)
    : >"$FAKE_AEGIS_STATE_DIR/revoked"
    ;;
  *)
    exec /usr/bin/python3 - <<'PYTHON_SERVER'
import http.server
import os
import socketserver

state = os.environ["FAKE_AEGIS_STATE_DIR"]
port = int(os.environ["FAKE_AEGIS_PORT"])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        status = 401 if os.path.exists(os.path.join(state, "revoked")) else 400
        body = b"{}"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

class Server(socketserver.TCPServer):
    allow_reuse_address = True

with Server(("127.0.0.1", port), Handler) as server:
    server.serve_forever()
PYTHON_SERVER
    ;;
esac
FAKE_AEGIS
/bin/chmod 700 "$fake_aegis_template"

fake_bin="$test_root/fake-bin"
/bin/mkdir -p "$fake_bin"

fake_docker="$fake_bin/docker"
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'ambient_failure() { "$AMBIENT_FILTER_HELPER"; exit 96; }' \
  '[ "${GIT_CONFIG_PARAMETERS+x}" != x ] || ambient_failure' \
  '[ "${GIT_CONFIG_KEY_37+x}" != x ] || ambient_failure' \
  '[ "${BASH_ENV+x}" != x ] || ambient_failure' \
  '[ "${ENV+x}" != x ] || ambient_failure' \
  '[ "${MAKEFILES+x}" != x ] || ambient_failure' \
  '[ "${MAKEFLAGS+x}" != x ] || ambient_failure' \
  '[ "${GNUMAKEFLAGS+x}" != x ] || ambient_failure' \
  '[ "${MAKEOVERRIDES+x}" != x ] || ambient_failure' \
  '[ "${MFLAGS+x}" != x ] || ambient_failure' \
  '[ "$GIT_CONFIG_COUNT" = 5 ] || ambient_failure' \
  '[ "$GIT_CONFIG_NOSYSTEM" = 1 ] || ambient_failure' \
  '[ "$GIT_CONFIG_SYSTEM" = /dev/null ] || ambient_failure' \
  '[ "$GIT_CONFIG_GLOBAL" = /dev/null ] || ambient_failure' \
  '[ "$GIT_ATTR_NOSYSTEM" = 1 ] || ambient_failure' \
  '[ "$GIT_TERMINAL_PROMPT" = 0 ] || ambient_failure' \
  '[ "$GIT_NO_REPLACE_OBJECTS" = 1 ] || ambient_failure' \
  '[ "$GIT_NO_LAZY_FETCH" = 1 ] || ambient_failure' \
  '[ "$GOTOOLCHAIN" = local ] || ambient_failure' \
  'state=$FAKE_DOCKER_STATE_DIR' \
  'image_digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  'transient_cid=1111111111111111111111111111111111111111111111111111111111111111' \
  'runtime_cid=2222222222222222222222222222222222222222222222222222222222222222' \
  'provider_cid=3333333333333333333333333333333333333333333333333333333333333333' \
  'issuer_cid=4444444444444444444444444444444444444444444444444444444444444444' \
  'provider_container="${CONTAINER}-provider-import"' \
  'issuer_container="${CONTAINER}-virtual-key-issue"' \
  'joined=$*' \
  'last=' \
  'for argument in "$@"; do last=$argument; done' \
  'record_delete_attempt() {' \
  '  printf "%s\n" "$1" >>"$state/delete-attempts"' \
  '}' \
  'case "${1:-}" in' \
  '  version)' \
  '    printf "%s\n" 27.0.0' \
  '    ;;' \
  '  info)' \
  '    printf "%s\n" arm64' \
  '    ;;' \
  '  build)' \
  '    : >"$state/image"' \
  '    printf "%s\n" "fake docker build"' \
  '    ;;' \
  '  image)' \
  '    case "${2:-}" in' \
  '      inspect)' \
  '        case "$joined" in' \
  '          *"index .Config.Labels"*) printf "%s\n" "$RUN_TOKEN" ;;' \
  '          *"image={{.Id}}"*) printf "%s\n" "image=$image_digest os=linux arch=arm64 user=nonroot:nonroot entrypoint=[\"/aegis\"] cmd=[\"--config\",\"/etc/aegis/aegis.json\"]" ;;' \
  '          *"{{.Id}}"*) printf "%s\n" "$image_digest" ;;' \
  '          *"{{.Os}}"*) printf "%s\n" linux ;;' \
  '          *"{{.Architecture}}"*) printf "%s\n" arm64 ;;' \
  '          *"{{.Config.User}}"*) printf "%s\n" nonroot:nonroot ;;' \
  '          *"{{json .Config.Entrypoint}}"*) printf "%s\n" "[\"/aegis\"]" ;;' \
  '          *"{{json .Config.Cmd}}"*) printf "%s\n" "[\"--config\",\"/etc/aegis/aegis.json\"]" ;;' \
  '          *) exit 81 ;;' \
  '        esac' \
  '        ;;' \
  '      ls)' \
  '        if [ -f "$state/image" ]; then' \
  '          case "$joined" in' \
  '            *"{{.ID}}"*) printf "%s\n" "$image_digest" ;;' \
  '            *) printf "%s\n" "$IMAGE" ;;' \
  '          esac' \
  '        fi' \
  '        ;;' \
  '      *) exit 82 ;;' \
  '    esac' \
  '    ;;' \
  '  create)' \
  '    case "$joined" in' \
  '      *"--name $provider_container"*)' \
  '        : >"$state/provider-container"' \
  '        printf "%s\n" "$RUN_TOKEN" >"$state/provider-container.owner"' \
  '        if [ "${FAKE_DOCKER_DISCONNECT_AFTER_CREATE:-}" = "provider-create" ]; then exit 96; fi' \
  '        printf "%s\n" "$provider_cid"' \
  '        ;;' \
  '      *"--name $issuer_container"*) : >"$state/issuer-container"; printf "%s\n" "$RUN_TOKEN" >"$state/issuer-container.owner"; printf "%s\n" "$issuer_cid" ;;' \
  '      *) : >"$state/transient-container"; printf "%s\n" "$RUN_TOKEN" >"$state/transient-container.owner"; printf "%s\n" "$transient_cid" ;;' \
  '    esac' \
  '    ;;' \
  '  cp)' \
  '    printf "%s\n" fake-aegis >"$last"' \
  '    ;;' \
  '  rm)' \
  '    record_delete_attempt "container:$last"' \
  '    case "$last" in' \
  '      "$transient_cid") rm -f "$state/transient-container" "$state/transient-container.owner" ;;' \
  '      "$runtime_cid"|"$CONTAINER") rm -f "$state/named-container" "$state/named-container.owner" ;;' \
  '      "$provider_cid"|"$provider_container") rm -f "$state/provider-container" "$state/provider-container.owner" ;;' \
  '      "$issuer_cid"|"$issuer_container") rm -f "$state/issuer-container" "$state/issuer-container.owner" ;;' \
  '      *) exit 83 ;;' \
  '    esac' \
  '    ;;' \
  '  ps)' \
  '    case "$joined" in' \
  '      *"{{.ID}}"*)' \
  '        if [ -f "$state/transient-container" ]; then printf "%s\n" "$transient_cid"; fi' \
  '        if [ -f "$state/named-container" ]; then printf "%s\n" "$runtime_cid"; fi' \
  '        if [ -f "$state/provider-container" ]; then printf "%s\n" "$provider_cid"; fi' \
  '        if [ -f "$state/issuer-container" ]; then printf "%s\n" "$issuer_cid"; fi' \
  '        ;;' \
  '      *"{{.Names}}"*)' \
  '        if [ -f "$state/named-container" ]; then printf "%s\n" "$CONTAINER"; fi' \
  '        if [ -f "$state/provider-container" ]; then printf "%s\n" "$provider_container"; fi' \
  '        if [ -f "$state/issuer-container" ]; then printf "%s\n" "$issuer_container"; fi' \
  '        ;;' \
  '      *) exit 84 ;;' \
  '    esac' \
  '    ;;' \
  '  volume)' \
  '    case "${2:-}" in' \
  '      create) : >"$state/volume"; printf "%s\n" "$VOLUME" ;;' \
  '      inspect)' \
  '        case "$joined" in' \
  '          *"index .Labels"*) printf "%s\n" "$RUN_TOKEN" ;;' \
  '          *"{{.Name}}"*) printf "%s\n" "$VOLUME" ;;' \
  '          *) exit 88 ;;' \
  '        esac' \
  '        ;;' \
  '      ls) if [ -f "$state/volume" ]; then printf "%s\n" "$VOLUME"; fi ;;' \
  '      rm)' \
  '        record_delete_attempt "volume:$last"' \
  '        if [ -f "$state/volume" ] && [ "${FAKE_DOCKER_FAIL_VOLUME_RM:-}" = "1" ]; then' \
  '          exit 89' \
  '        fi' \
  '        rm -f "$state/volume"' \
  '        ;;' \
  '      *) exit 85 ;;' \
  '    esac' \
  '    ;;' \
  '  rmi)' \
  '    record_delete_attempt "image:$last"' \
  '    case "$last" in' \
  '      "$image_digest"|"$IMAGE") rm -f "$state/image" ;;' \
  '      *) exit 92 ;;' \
  '    esac' \
  '    ;;' \
  '  run)' \
  '    case "$joined" in' \
  '      *" --version") printf "%s\n" "Aegis test (commit: $COMMIT)" ;;' \
  '      *"operator provider-key import"*) : >"$state/provider-container"; printf "%s\n" "$RUN_TOKEN" >"$state/provider-container.owner" ;;' \
  '      *"operator virtual-key issue"*)' \
  '        : >"$state/issuer-container"' \
  '        printf "%s\n" "$RUN_TOKEN" >"$state/issuer-container.owner"' \
  '        printf "%s\n" "virtual_key_issued kid=fake-kid expires_at=2099-01-01T00:00:00Z" >&2' \
  '        printf "%s\n" fake-virtual-key' \
  '        ;;' \
  '      *"operator virtual-key revoke"*) : >"$state/revoked" ;;' \
  '      *"-d --name $CONTAINER"*)' \
  '        : >"$state/named-container"' \
  '        printf "%s\n" "$RUN_TOKEN" >"$state/named-container.owner"' \
  '        if [ "${FAKE_DOCKER_DISCONNECT_AFTER_CREATE:-}" = "runtime-run" ]; then exit 97; fi' \
  '        printf "%s\n" "$runtime_cid"' \
  '        ;;' \
  '      *) : ;;' \
  '    esac' \
  '    ;;' \
  '  start)' \
  '    case "$last" in' \
  '      "$provider_cid") : ;;' \
  '      "$issuer_cid")' \
  '        printf "%s\n" "virtual_key_issued kid=fake-kid expires_at=2099-01-01T00:00:00Z" >&2' \
  '        printf "%s\n" fake-virtual-key' \
  '        ;;' \
  '      *) exit 93 ;;' \
  '    esac' \
  '    ;;' \
  '  inspect)' \
  '    inspect_target=${2:-}' \
  '    case "$inspect_target" in' \
  '      "$CONTAINER"|"$provider_container"|"$issuer_container") printf "%s\n" "$inspect_target" >>"$state/name-lookups" ;;' \
  '    esac' \
  '    case "$joined" in' \
  '      *"index .Config.Labels"*)' \
  '        if [ "${FAKE_DOCKER_DISCONNECT_UNOWNED:-}" = "1" ] &&' \
  '           { [ "$inspect_target" = "$provider_cid" ] || [ "$inspect_target" = "$provider_container" ]; }; then' \
  '          printf "%s\n" ffffffffffffffffffffffffffffffff' \
  '        else' \
  '          owner_file=' \
  '          case "$inspect_target" in' \
  '            "$transient_cid") owner_file="$state/transient-container.owner" ;;' \
  '            "$runtime_cid"|"$CONTAINER") owner_file="$state/named-container.owner" ;;' \
  '            "$provider_cid"|"$provider_container") owner_file="$state/provider-container.owner" ;;' \
  '            "$issuer_cid"|"$issuer_container") owner_file="$state/issuer-container.owner" ;;' \
  '          esac' \
  '          if [ -n "$owner_file" ] && [ -f "$owner_file" ]; then cat "$owner_file"; else printf "%s\n" ffffffffffffffffffffffffffffffff; fi' \
  '        fi' \
  '        ;;' \
  '      *"{{.Id}}"*)' \
  '        case "$inspect_target" in' \
  '          "$transient_cid") printf "%s\n" "$transient_cid" ;;' \
  '          "$runtime_cid"|"$CONTAINER") printf "%s\n" "$runtime_cid" ;;' \
  '          "$provider_cid"|"$provider_container") printf "%s\n" "$provider_cid" ;;' \
  '          "$issuer_cid"|"$issuer_container") printf "%s\n" "$issuer_cid" ;;' \
  '          *) exit 94 ;;' \
  '        esac' \
  '        ;;' \
  '      *"readonly={{.HostConfig.ReadonlyRootfs}}"*) printf "%s\n" "readonly=true user=nonroot:nonroot mounts=/var/lib/aegis:volume" ;;' \
  '      *"{{.HostConfig.ReadonlyRootfs}}"*) printf "%s\n" true ;;' \
  '      *"{{.Config.User}}"*) printf "%s\n" nonroot:nonroot ;;' \
  '      *) exit 86 ;;' \
  '    esac' \
  '    ;;' \
  '  *) exit 87 ;;' \
  'esac' >"$fake_docker"
chmod 700 "$fake_docker"

fake_curl="$fake_bin/curl"
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'joined=$*' \
  'output_path=' \
  'previous=' \
  'for argument in "$@"; do' \
  '  if [ "$previous" = "-o" ]; then output_path=$argument; fi' \
  '  previous=$argument' \
  'done' \
  'if [ -n "$output_path" ]; then printf "%s\n" "{}" >"$output_path"; fi' \
  'case "$joined" in' \
  '  *"/health"*) printf "%s\n" "{\"status\":\"ok\"}" ;;' \
  '  *)' \
  '    if [ -f "$FAKE_DOCKER_STATE_DIR/revoked" ]; then printf "%s" 401; else printf "%s" 400; fi' \
  '    ;;' \
  'esac' >"$fake_curl"
chmod 700 "$fake_curl"

fake_file="$fake_bin/file"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "fixture: ELF 64-bit LSB executable, ARM aarch64, statically linked"' \
  >"$fake_file"
chmod 700 "$fake_file"
for ambient_command in git tar ssh rsync openssl date sh; do
  {
    printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'printf "ambient host command invoked: %s\n" "${0##*/}" >&2' \
      ': >"$HOST_COMMAND_MARKER"' \
      'exit 94'
  } >"$fake_bin/$ambient_command"
  /bin/chmod 700 "$fake_bin/$ambient_command"
done

shell_exec_runner="$test_root/run-script-with-fixed-shell"
cat >"$shell_exec_runner" <<'SHELL_EXEC_RUNNER'
#!/bin/sh
set -eu
exec /bin/sh "$1"
SHELL_EXEC_RUNNER
/bin/chmod 700 "$shell_exec_runner"

direct_exec_runner="$test_root/run-script-directly"
cat >"$direct_exec_runner" <<'DIRECT_EXEC_RUNNER'
#!/bin/sh
set -eu
exec "$1"
DIRECT_EXEC_RUNNER
/bin/chmod 700 "$direct_exec_runner"

external_fixture="$test_root/external"
external_source="$external_fixture/materialized"
external_driver="$external_fixture/driver"
external_lock="$external_fixture/identity.lock"
/bin/mkdir -p "$external_fixture" "$external_driver"
prepare_materialized_workspace "$external_source" 1
write_identity_lock "$external_lock"
external_lock_sha256=$(contract_sha256_file "$external_lock")
external_source_metadata=$(contract_metadata "$external_source")

empty_tar="$test_root/unused-empty-tar"
: >"$empty_tar"
drift_git="$test_root/unused-drift-git"
fake_git="$test_root/unused-fake-git"
: >"$drift_git"
: >"$fake_git"

fake_rsync="$fake_bin/rsync"
cat >"$fake_rsync" <<'FAKE_RSYNC'
#!/bin/sh
set -eu
: >"$FAKE_TRANSPORT_STATE_DIR/rsync-invoked"
exit 95
FAKE_RSYNC
/bin/chmod 700 "$fake_rsync"

fake_ssh="$fake_bin/ssh"
cat >"$fake_ssh" <<'FAKE_SSH'
#!/bin/sh
set -eu
: >"$FAKE_TRANSPORT_STATE_DIR/ssh-invoked"
exit 95
FAKE_SSH
/bin/chmod 700 "$fake_ssh"

ceo_contract_runner="$test_root/run-ceo-contract"
cat >"$ceo_contract_runner" <<'CEO_RUNNER'
#!/bin/sh
set -eu
cd "$CONTRACT_DRIVER_DIR"
exec /usr/bin/env \
  -u COMMIT \
  -u CANDIDATE_IDENTITY_LOCK \
  -u CANDIDATE_IDENTITY_LOCK_SHA256 \
  -u CANDIDATE_SOURCE_DIR \
  REMOTE_HOST=local \
  CANDIDATE_IDENTITY_LOCK="$CONTRACT_IDENTITY_LOCK" \
  CANDIDATE_IDENTITY_LOCK_SHA256="$CONTRACT_IDENTITY_LOCK_SHA256" \
  CANDIDATE_SOURCE_DIR="$CONTRACT_SOURCE_DIR" \
  HOST_COMMAND_MARKER="$HOST_COMMAND_MARKER" \
  GIT_CONFIG_PARAMETERS="filter.aegis.clean=$AMBIENT_FILTER_HELPER" \
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_37=filter.aegis.clean \
  GIT_CONFIG_VALUE_37="$AMBIENT_FILTER_HELPER" \
  GIT_EXEC_PATH="$FAKE_REMOTE_BIN" \
  GIT_DIR=/ambient/git-dir \
  GIT_WORK_TREE=/ambient/work-tree \
  GIT_COMMON_DIR=/ambient/common-dir \
  GIT_INDEX_FILE=/ambient/index \
  GIT_OBJECT_DIRECTORY=/ambient/objects \
  GIT_ALTERNATE_OBJECT_DIRECTORIES=/ambient/alternates \
  GIT_REPLACE_REF_BASE=refs/ambient \
  GIT_SHALLOW_FILE=/ambient/shallow \
  GIT_EXTERNAL_DIFF="$AMBIENT_FILTER_HELPER" \
  GIT_ASKPASS="$AMBIENT_FILTER_HELPER" \
  SSH_ASKPASS="$AMBIENT_FILTER_HELPER" \
  GIT_SSH="$AMBIENT_FILTER_HELPER" \
  GIT_SSH_COMMAND="$AMBIENT_FILTER_HELPER" \
  GIT_PROXY_COMMAND="$AMBIENT_FILTER_HELPER" \
  PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin" \
  /bin/sh "$CONTRACT_SOURCE_DIR/scripts/ceo_docker_smoke.sh"
CEO_RUNNER
/bin/chmod 700 "$ceo_contract_runner"

CONTRACT_DRIVER_DIR=$external_driver
CONTRACT_IDENTITY_LOCK=$external_lock
CONTRACT_IDENTITY_LOCK_SHA256=$external_lock_sha256
CONTRACT_SOURCE_DIR=$external_source
AMBIENT_FILTER_HELPER=$ambient_filter_helper
HOST_COMMAND_MARKER=$host_command_marker
export CONTRACT_DRIVER_DIR CONTRACT_IDENTITY_LOCK CONTRACT_IDENTITY_LOCK_SHA256
export CONTRACT_SOURCE_DIR AMBIENT_FILTER_HELPER HOST_COMMAND_MARKER

terminal_for() {
  terminal_script=$1
  terminal_state=$2
  case "$terminal_script:$terminal_state" in
    release_preflight.sh:external)
      printf '%s\n' \
        'release_preflight=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED evidence_mode=ITERATION_ONLY claimed_source_state=unapproved_materialization claimed_candidate_sha=1111111111111111111111111111111111111111 claimed_candidate_tree=2222222222222222222222222222222222222222 claimed_materialized_root_sha256=5555555555555555555555555555555555555555555555555555555555555555 final_evidence=false release_approved=false'
      ;;
    local_smoke.sh:external)
      printf '%s\n' \
        'local_smoke=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED evidence_mode=ITERATION_ONLY claimed_source_state=unapproved_materialization claimed_candidate_sha=1111111111111111111111111111111111111111 claimed_candidate_tree=2222222222222222222222222222222222222222 claimed_materialized_root_sha256=5555555555555555555555555555555555555555555555555555555555555555 final_evidence=false release_approved=false'
      ;;
    ceo_docker_smoke.sh:external)
      printf '%s\n' \
        'ceo_docker_smoke=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED evidence_mode=ITERATION_ONLY claimed_source_state=unapproved_materialization claimed_candidate_sha=1111111111111111111111111111111111111111 claimed_candidate_tree=2222222222222222222222222222222222222222 claimed_materialized_root_sha256=5555555555555555555555555555555555555555555555555555555555555555 test_fixture_only=1 final_evidence=false release_approved=false'
      ;;
    release_preflight.sh:bootstrap)
      printf '%s\n' \
        'release_preflight=TECHNICAL_ITERATION_PASS evidence_mode=ITERATION_ONLY claimed_source_state=unverified_bootstrap claimed_candidate_sha=unavailable claimed_candidate_tree=unavailable claimed_materialized_root_sha256=unavailable final_evidence=false release_approved=false'
      ;;
    local_smoke.sh:bootstrap)
      printf '%s\n' \
        'local_smoke=TECHNICAL_ITERATION_PASS evidence_mode=ITERATION_ONLY claimed_source_state=unverified_bootstrap claimed_candidate_sha=unavailable claimed_candidate_tree=unavailable claimed_materialized_root_sha256=unavailable final_evidence=false release_approved=false'
      ;;
    ceo_docker_smoke.sh:bootstrap)
      printf '%s\n' \
        'ceo_docker_smoke=TECHNICAL_ITERATION_PASS evidence_mode=ITERATION_ONLY claimed_source_state=unverified_bootstrap claimed_candidate_sha=unavailable claimed_candidate_tree=unavailable claimed_materialized_root_sha256=unavailable test_fixture_only=1 final_evidence=false release_approved=false'
      ;;
    *)
      return 1
      ;;
  esac
}

run_external_success() {
  success_script=$1
  success_port=$2
  success_launch_mode=${3:-fixed-shell}
  success_environment_mode=${4:-hostile}
  case "$success_launch_mode" in
    fixed-shell) success_runner=$shell_exec_runner ;;
    direct) success_runner=$direct_exec_runner ;;
    *) echo "contract received an invalid script launch mode" >&2; exit 1 ;;
  esac
  case "$success_environment_mode" in
    hostile)
      success_bash_env=$ambient_shell_env
      success_env=$ambient_shell_env
      success_makefiles=$ambient_makefile
      success_makeflags=--no-builtin-rules
      success_gnumakeflags=''
      success_makeoverrides=ambient-contract-value
      success_mflags=-r
      success_path="$fake_bin:/usr/bin:/bin"
      ;;
    sterile)
      success_bash_env=''
      success_env=''
      success_makefiles=''
      success_makeflags=''
      success_gnumakeflags=''
      success_makeoverrides=''
      success_mflags=''
      success_path=/usr/bin:/bin
      ;;
    *) echo "contract received an invalid environment launch mode" >&2; exit 1 ;;
  esac
  success_output="$test_root/external-${success_script}.out"
  success_state="$test_root/external-${success_script}.state"
  success_transport="$test_root/external-${success_script}.transport"
  /bin/rm -rf "$success_state" "$success_transport"
  /bin/mkdir -p "$success_state" "$success_transport"
  : >"$success_state/delete-attempts"
  /bin/rm -f \
    "$ambient_filter_marker" "$env_sanitized_marker" "$host_command_marker" \
    "$ambient_make_marker" "$ambient_shell_marker"
  expected_terminal=$(terminal_for "$success_script" external)
  if ! (
    cd "$external_driver"
    /usr/bin/env \
      BASH_ENV="$ambient_shell_env" \
      ENV="$ambient_shell_env" \
      MAKEFILES="$ambient_makefile" \
      PATH="$fake_bin:/usr/bin:/bin" \
      "BASH_FUNC_contract%%=() { /usr/bin/touch $ambient_shell_marker; }" \
      /usr/bin/env -i \
      -u COMMIT \
      -u IMAGE \
      -u CONTAINER \
      -u VOLUME \
      -u MAKEFILES \
      -u MAKEFLAGS \
      -u GNUMAKEFLAGS \
      -u MAKEOVERRIDES \
      -u MFLAGS \
      GO="$fake_go" \
      FAKE_AEGIS_TEMPLATE="$fake_aegis_template" \
      FAKE_AEGIS_STATE_DIR="$success_state" \
      FAKE_AEGIS_PORT="$success_port" \
      PORT="$success_port" \
      AMBIENT_FILTER_HELPER="$ambient_filter_helper" \
      AMBIENT_FILTER_MARKER="$ambient_filter_marker" \
      ENV_SANITIZED_MARKER="$env_sanitized_marker" \
      HOST_COMMAND_MARKER="$host_command_marker" \
      CANDIDATE_IDENTITY_LOCK="$external_lock" \
      CANDIDATE_IDENTITY_LOCK_SHA256="$external_lock_sha256" \
      CANDIDATE_SOURCE_DIR="$external_source" \
      REMOTE_HOST=local \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_REMOTE_BIN="$fake_bin" \
      FAKE_DOCKER_STATE_DIR="$success_state" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      FAKE_TRANSPORT_STATE_DIR="$success_transport" \
      GIT_CONFIG_PARAMETERS="filter.aegis.clean=$ambient_filter_helper" \
      GIT_CONFIG_COUNT=1 \
      GIT_CONFIG_KEY_37=filter.aegis.clean \
      GIT_CONFIG_VALUE_37="$ambient_filter_helper" \
      GIT_EXEC_PATH="$fake_bin" \
      GIT_DIR=/ambient/git-dir \
      GIT_WORK_TREE=/ambient/work-tree \
      GIT_COMMON_DIR=/ambient/common-dir \
      GIT_INDEX_FILE=/ambient/index \
      GIT_OBJECT_DIRECTORY=/ambient/objects \
      GIT_ALTERNATE_OBJECT_DIRECTORIES=/ambient/alternates \
      GIT_REPLACE_REF_BASE=refs/ambient \
      GIT_SHALLOW_FILE=/ambient/shallow \
      GIT_EXTERNAL_DIFF="$ambient_filter_helper" \
      GIT_ASKPASS="$ambient_filter_helper" \
      SSH_ASKPASS="$ambient_filter_helper" \
      GIT_SSH="$ambient_filter_helper" \
      GIT_SSH_COMMAND="$ambient_filter_helper" \
      GIT_PROXY_COMMAND="$ambient_filter_helper" \
      BASH_ENV="$success_bash_env" \
      ENV="$success_env" \
      MAKEFILES="$success_makefiles" \
      MAKEFLAGS="$success_makeflags" \
      GNUMAKEFLAGS="$success_gnumakeflags" \
      MAKEOVERRIDES="$success_makeoverrides" \
      MFLAGS="$success_mflags" \
      PATH="$success_path" \
      /bin/sh "$success_runner" "$external_source/scripts/$success_script"
  ) >"$success_output" 2>&1; then
    echo "$success_script external technical fixture failed" >&2
    /bin/cat "$success_output" >&2
    exit 1
  fi
  actual_terminal=$(/usr/bin/tail -n 1 "$success_output")
  if [ "$actual_terminal" != "$expected_terminal" ]; then
    echo "$success_script emitted an unexpected external terminal" >&2
    printf 'expected=%s\nactual=%s\n' "$expected_terminal" "$actual_terminal" >&2
    exit 1
  fi
  if /usr/bin/grep -F -- "$equals_pass" "$success_output" >/dev/null; then
    echo "$success_script emitted a grep-ambiguous PASS token" >&2
    exit 1
  fi
  if [ -e "$ambient_make_marker" ]; then
    echo "$success_script executed ambient MAKEFILES content" >&2
    exit 1
  fi
  if [ -e "$ambient_shell_marker" ]; then
    echo "$success_script executed ambient BASH_ENV or ENV content" >&2
    exit 1
  fi
  if [ -e "$ambient_filter_marker" ] || [ -e "$host_command_marker" ]; then
    echo "$success_script executed ambient filter or host tooling" >&2
    exit 1
  fi
  case "$success_script" in
    release_preflight.sh|local_smoke.sh)
      [ -e "$env_sanitized_marker" ] || {
        echo "$success_script did not reach the sanitized Go gate" >&2
        exit 1
      }
      ;;
  esac
  current_external_source_metadata=$(contract_metadata "$external_source")
  if [ "$current_external_source_metadata" != "$external_source_metadata" ]; then
    echo "$success_script drifted the external source root metadata" >&2
    printf 'expected_metadata=%s\nactual_metadata=%s\n' \
      "$external_source_metadata" "$current_external_source_metadata" >&2
    exit 1
  fi
}

run_external_success release_preflight.sh 28181
run_external_success local_smoke.sh 28182
run_external_success ceo_docker_smoke.sh 28183
run_external_success release_preflight.sh 28191 direct
run_external_success local_smoke.sh 28192 direct
run_external_success ceo_docker_smoke.sh 28193 direct
run_external_success release_preflight.sh 28211 fixed-shell sterile
run_external_success local_smoke.sh 28212 fixed-shell sterile
run_external_success ceo_docker_smoke.sh 28213 fixed-shell sterile

assert_release_preflight_make_function_safe() {
  injection_name=$1
  injection_expectation=$2
  injection_port=$3
  injection_marker="$test_root/release-preflight-make-function-${injection_name}"
  injection_output="$test_root/release-preflight-make-function-${injection_name}.out"
  injection_state="$test_root/release-preflight-make-function-${injection_name}.state"
  injection_value=$(printf '\$(shell /usr/bin/touch %s)' "$injection_marker")
  /bin/rm -rf "$injection_state"
  /bin/mkdir -p "$injection_state"
  : >"$injection_state/delete-attempts"
  /bin/rm -f "$injection_marker" "$env_sanitized_marker"

  injection_rc=0
  (
    cd "$external_driver"
    /usr/bin/env -i \
      GO="$fake_go" \
      VERSION=v0.2.1-contract \
      FAKE_AEGIS_TEMPLATE="$fake_aegis_template" \
      FAKE_AEGIS_STATE_DIR="$injection_state" \
      FAKE_AEGIS_PORT="$injection_port" \
      PORT="$injection_port" \
      AMBIENT_FILTER_HELPER="$ambient_filter_helper" \
      AMBIENT_FILTER_MARKER="$ambient_filter_marker" \
      ENV_SANITIZED_MARKER="$env_sanitized_marker" \
      CANDIDATE_IDENTITY_LOCK="$external_lock" \
      CANDIDATE_IDENTITY_LOCK_SHA256="$external_lock_sha256" \
      CANDIDATE_SOURCE_DIR="$external_source" \
      REMOTE_HOST=local \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_REMOTE_BIN="$fake_bin" \
      FAKE_DOCKER_STATE_DIR="$injection_state" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      PATH=/usr/bin:/bin \
      "$injection_name=$injection_value" \
      /bin/sh "$external_source/scripts/release_preflight.sh"
  ) >"$injection_output" 2>&1 || injection_rc=$?

  if [ -e "$injection_marker" ]; then
    echo "release preflight executed a Make function from $injection_name" >&2
    /bin/cat "$injection_output" >&2
    exit 1
  fi
  case "$injection_expectation:$injection_rc" in
    reject:0)
      echo "release preflight accepted an invalid $injection_name" >&2
      /bin/cat "$injection_output" >&2
      exit 1
      ;;
    reject:*)
      if [ -e "$env_sanitized_marker" ]; then
        echo "release preflight validated $injection_name after a Go gate" >&2
        exit 1
      fi
      ;;
    neutralized:0)
      injection_terminal=$(/usr/bin/tail -n 1 "$injection_output")
      expected_injection_terminal=$(terminal_for release_preflight.sh external)
      if [ "$injection_terminal" != "$expected_injection_terminal" ]; then
        echo "release preflight emitted an unexpected $injection_name terminal" >&2
        /bin/cat "$injection_output" >&2
        exit 1
      fi
      ;;
    neutralized:*)
      echo "release preflight did not neutralize ambient $injection_name" >&2
      /bin/cat "$injection_output" >&2
      exit 1
      ;;
    *)
      echo "contract received an invalid Make-function expectation" >&2
      exit 1
      ;;
  esac
}

assert_release_preflight_make_function_safe VERSION reject 28221
assert_release_preflight_make_function_safe ACTIONLINT_VERSION reject 28222
assert_release_preflight_make_function_safe COMMIT neutralized 28223
assert_release_preflight_make_function_safe BUILD_DATE neutralized 28224
assert_release_preflight_make_function_safe GOLANGCI_VERSION neutralized 28225
assert_release_preflight_make_function_safe GOVULNCHECK_VERSION neutralized 28226
assert_release_preflight_make_function_safe GOSEC_VERSION neutralized 28227
assert_release_preflight_make_function_safe DOCKER_TAG_LATEST neutralized 28228

expect_ceo_rejection() {
  reject_script_path=$1
  reject_source=$2
  reject_lock=$3
  reject_digest=$4
  reject_remote_host=$5
  reject_description=$6
  reject_output="$test_root/reject-${reject_description}.out"
  reject_state="$test_root/reject-${reject_description}.state"
  /bin/mkdir -p "$reject_state"
  if (
    cd "$external_driver"
    /usr/bin/env -i \
      -u COMMIT \
      CANDIDATE_IDENTITY_LOCK="$reject_lock" \
      CANDIDATE_IDENTITY_LOCK_SHA256="$reject_digest" \
      CANDIDATE_SOURCE_DIR="$reject_source" \
      REMOTE_HOST="$reject_remote_host" \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_REMOTE_BIN="$fake_bin" \
      FAKE_DOCKER_STATE_DIR="$reject_state" \
      HOST_COMMAND_MARKER="$host_command_marker" \
      PATH="$fake_bin:/usr/bin:/bin" \
      /bin/sh "$reject_script_path"
  ) >"$reject_output" 2>&1; then
    echo "ceo docker smoke accepted invalid identity fixture: $reject_description" >&2
    exit 1
  fi
  if /usr/bin/grep -E '^ceo_docker_smoke=' "$reject_output" >/dev/null; then
    echo "ceo docker smoke emitted a terminal for rejected identity: $reject_description" >&2
    exit 1
  fi
}

extra_lock="$test_root/extra-line.lock"
/bin/cp "$external_lock" "$extra_lock"
printf '%s\n' 'extra_field=forbidden' >>"$extra_lock"
/bin/chmod 600 "$extra_lock"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$extra_lock" "$(contract_sha256_file "$extra_lock")" local extra-line

reordered_lock="$test_root/reordered.lock"
{
  /usr/bin/sed -n '2p' "$external_lock"
  /usr/bin/sed -n '1p' "$external_lock"
  /usr/bin/sed -n '3,$p' "$external_lock"
} >"$reordered_lock"
/bin/chmod 600 "$reordered_lock"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$reordered_lock" "$(contract_sha256_file "$reordered_lock")" local reordered

control_lock="$test_root/control.lock"
/bin/cp "$external_lock" "$control_lock"
printf '\r' >>"$control_lock"
/bin/chmod 600 "$control_lock"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$control_lock" "$(contract_sha256_file "$control_lock")" local control-byte

stale_lock="$test_root/stale.lock"
/bin/cp "$external_lock" "$stale_lock"
printf '%s\n' 'stale=true' >>"$stale_lock"
/bin/chmod 600 "$stale_lock"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$stale_lock" "$external_lock_sha256" local stale-digest

writable_lock="$test_root/writable.lock"
/bin/cp "$external_lock" "$writable_lock"
/bin/chmod 666 "$writable_lock"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$writable_lock" "$(contract_sha256_file "$writable_lock")" local writable-lock

symlink_lock="$test_root/symlink.lock"
/bin/ln -s "$external_lock" "$symlink_lock"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$symlink_lock" "$external_lock_sha256" local symlink-lock

source_symlink="$test_root/source-symlink"
/bin/ln -s "$external_source" "$source_symlink"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$source_symlink" "$external_lock" "$external_lock_sha256" local symlink-source

script_symlink="$test_root/ceo-script-symlink"
/bin/ln -s "$external_source/scripts/ceo_docker_smoke.sh" "$script_symlink"
expect_ceo_rejection "$script_symlink" \
  "$external_source" "$external_lock" "$external_lock_sha256" local symlink-script

expect_ceo_rejection "$ceo_docker_smoke" \
  "$external_source" "$external_lock" "$external_lock_sha256" local wrong-script-root
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$external_lock" "$external_lock_sha256" ceo nonlocal-transport

/bin/chmod u+w "$external_source"
expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
  "$external_source" "$external_lock" "$external_lock_sha256" local writable-source
/bin/chmod a-w "$external_source"

assert_git_metadata_path_rejected() {
  unsafe_relative_path=$1
  unsafe_path_kind=$2
  unsafe_description=$3
  unsafe_path="$external_source/.git/$unsafe_relative_path"
  unsafe_parent=${unsafe_path%/*}
  /bin/chmod u+w "$unsafe_parent"
  case "$unsafe_path_kind" in
    file)
      printf '%s\n' unsafe-materializer-fixture >"$unsafe_path"
      ;;
    directory)
      /bin/mkdir "$unsafe_path"
      ;;
    *)
      echo "contract received an invalid unsafe Git fixture kind" >&2
      exit 1
      ;;
  esac
  /bin/chmod -R a-w "$unsafe_path"
  /bin/chmod a-w "$unsafe_parent"
  expect_ceo_rejection "$external_source/scripts/ceo_docker_smoke.sh" \
    "$external_source" "$external_lock" "$external_lock_sha256" local "$unsafe_description"
  /bin/chmod u+w "$unsafe_parent"
  /bin/chmod -R u+w "$unsafe_path"
  /bin/rm -rf "$unsafe_path"
  /bin/chmod a-w "$unsafe_parent"
}

assert_git_metadata_path_rejected info/exclude file git-info-exclude
assert_git_metadata_path_rejected objects/info/grafts file git-object-grafts
assert_git_metadata_path_rejected worktrees directory git-worktrees
assert_git_metadata_path_rejected modules directory git-modules
assert_git_metadata_path_rejected commondir file git-commondir
assert_git_metadata_path_rejected refs/replace-shadow directory git-unknown-replace
assert_git_metadata_path_rejected objects/info/alternates-shadow file git-unknown-alternates

gitfile_fixture="$test_root/gitfile"
gitfile_source="$gitfile_fixture/materialized"
/bin/mkdir -p "$gitfile_fixture"
prepare_materialized_workspace "$gitfile_source" 0
/bin/rm -rf "$gitfile_source/.git"
printf '%s\n' 'gitdir: /untrusted/external-git-dir' >"$gitfile_source/.git"
/bin/chmod -R a-w "$gitfile_source"
expect_ceo_rejection "$gitfile_source/scripts/ceo_docker_smoke.sh" \
  "$gitfile_source" "$external_lock" "$external_lock_sha256" local gitfile-form

substituted_lock="$test_root/substituted-tcb.lock"
/usr/bin/sed \
  's/^claimed_verifier_sha256=[0-9a-f][0-9a-f]*$/claimed_verifier_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$external_lock" >"$substituted_lock"
/bin/chmod 600 "$substituted_lock"
substituted_digest=$(contract_sha256_file "$substituted_lock")
CONTRACT_IDENTITY_LOCK=$substituted_lock
CONTRACT_IDENTITY_LOCK_SHA256=$substituted_digest
export CONTRACT_IDENTITY_LOCK CONTRACT_IDENTITY_LOCK_SHA256
substitution_output="$test_root/substituted-tcb.out"
substitution_state="$test_root/substituted-tcb.state"
/bin/mkdir -p "$substitution_state"
if ! (
  cd "$external_driver"
  AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
    FAKE_REMOTE_BIN="$fake_bin" \
    FAKE_DOCKER_STATE_DIR="$substitution_state" \
    FAKE_DOCKER_FAIL_VOLUME_RM=0 \
    /bin/sh "$ceo_contract_runner"
) >"$substitution_output" 2>&1; then
  echo "schema-valid caller-selected TCB substitution did not reach technical terminal" >&2
  /bin/cat "$substitution_output" >&2
  exit 1
fi
if ! /usr/bin/grep -F -- \
  'ceo_docker_smoke=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED' \
  "$substitution_output" >/dev/null; then
  echo "caller-selected TCB substitution escaped the non-approved boundary" >&2
  exit 1
fi
CONTRACT_IDENTITY_LOCK=$external_lock
CONTRACT_IDENTITY_LOCK_SHA256=$external_lock_sha256
export CONTRACT_IDENTITY_LOCK CONTRACT_IDENTITY_LOCK_SHA256

drift_output="$test_root/source-root-drift.out"
drift_state="$test_root/source-root-drift.state"
drift_marker="$test_root/source-root-drift.marker"
/bin/mkdir -p "$drift_state"
/bin/rm -f "$drift_marker"
if (
  cd "$external_driver"
  /usr/bin/env \
    -u COMMIT \
    GO="$fake_go" \
    FAKE_AEGIS_TEMPLATE="$fake_aegis_template" \
    FAKE_AEGIS_STATE_DIR="$drift_state" \
    FAKE_AEGIS_PORT=28184 \
    FAKE_GO_DRIFT_ROOT="$external_source" \
    FAKE_GO_DRIFT_MARKER="$drift_marker" \
    AMBIENT_FILTER_HELPER="$ambient_filter_helper" \
    AMBIENT_FILTER_MARKER="$ambient_filter_marker" \
    ENV_SANITIZED_MARKER="$env_sanitized_marker" \
    CANDIDATE_IDENTITY_LOCK="$external_lock" \
    CANDIDATE_IDENTITY_LOCK_SHA256="$external_lock_sha256" \
    CANDIDATE_SOURCE_DIR="$external_source" \
    PATH="$fake_bin:/usr/bin:/bin" \
    /bin/sh "$external_source/scripts/local_smoke.sh"
) >"$drift_output" 2>&1; then
  echo "local smoke accepted source-root metadata drift" >&2
  exit 1
fi
/bin/chmod a-w "$external_source"
if ! /usr/bin/grep -F -- 'materialized source root must be read-only' \
  "$drift_output" >/dev/null; then
  echo "local smoke did not report source-root drift" >&2
  /bin/cat "$drift_output" >&2
  exit 1
fi

bootstrap_fixture="$test_root/bootstrap"
bootstrap_source="$bootstrap_fixture/source"
bootstrap_driver="$bootstrap_fixture/driver"
/bin/mkdir -p "$bootstrap_driver"
prepare_materialized_workspace "$bootstrap_source" 0

run_bootstrap_success() {
  bootstrap_script=$1
  bootstrap_port=$2
  bootstrap_output="$test_root/bootstrap-${bootstrap_script}.out"
  bootstrap_state="$test_root/bootstrap-${bootstrap_script}.state"
  /bin/rm -rf "$bootstrap_state"
  /bin/mkdir -p "$bootstrap_state"
  : >"$bootstrap_state/delete-attempts"
  expected_terminal=$(terminal_for "$bootstrap_script" bootstrap)
  if ! (
    cd "$bootstrap_driver"
    /usr/bin/env -i \
      -u COMMIT \
      -u CANDIDATE_IDENTITY_LOCK \
      -u CANDIDATE_IDENTITY_LOCK_SHA256 \
      -u CANDIDATE_SOURCE_DIR \
      GO="$fake_go" \
      FAKE_AEGIS_TEMPLATE="$fake_aegis_template" \
      FAKE_AEGIS_STATE_DIR="$bootstrap_state" \
      FAKE_AEGIS_PORT="$bootstrap_port" \
      PORT="$bootstrap_port" \
      AMBIENT_FILTER_HELPER="$ambient_filter_helper" \
      AMBIENT_FILTER_MARKER="$ambient_filter_marker" \
      ENV_SANITIZED_MARKER="$env_sanitized_marker" \
      ALLOW_UNVERIFIED_ITERATION=1 \
      AEGIS_DISPOSABLE_CEO=1 \
      REMOTE_HOST=local \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_REMOTE_BIN="$fake_bin" \
      FAKE_DOCKER_STATE_DIR="$bootstrap_state" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      PATH="$fake_bin:/usr/bin:/bin" \
      /bin/sh "$bootstrap_source/scripts/$bootstrap_script"
  ) >"$bootstrap_output" 2>&1; then
    echo "$bootstrap_script disposable bootstrap fixture failed" >&2
    /bin/cat "$bootstrap_output" >&2
    exit 1
  fi
  actual_terminal=$(/usr/bin/tail -n 1 "$bootstrap_output")
  if [ "$actual_terminal" != "$expected_terminal" ]; then
    echo "$bootstrap_script emitted an unexpected bootstrap terminal" >&2
    printf 'expected=%s\nactual=%s\n' "$expected_terminal" "$actual_terminal" >&2
    exit 1
  fi
  if /usr/bin/grep -F -- "$equals_pass" "$bootstrap_output" >/dev/null; then
    echo "$bootstrap_script emitted a grep-ambiguous PASS token in bootstrap mode" >&2
    exit 1
  fi
}

run_bootstrap_success release_preflight.sh 28185
run_bootstrap_success local_smoke.sh 28186
run_bootstrap_success ceo_docker_smoke.sh 28187

run_external_make_success() {
  make_target=$1
  make_port=$2
  case "$make_target" in
    local-smoke) make_script=local_smoke.sh ;;
    release-preflight) make_script=release_preflight.sh ;;
    ceo-docker-smoke) make_script=ceo_docker_smoke.sh ;;
    *) echo "contract received an unknown public Make target" >&2; exit 1 ;;
  esac
  make_output="$test_root/external-make-${make_target}.out"
  make_state="$test_root/external-make-${make_target}.state"
  make_transport="$test_root/external-make-${make_target}.transport"
  /bin/rm -rf "$make_state" "$make_transport"
  /bin/mkdir -p "$make_state" "$make_transport"
  : >"$make_state/delete-attempts"
  /bin/rm -f "$ambient_filter_marker" "$env_sanitized_marker" "$host_command_marker"
  make_expected_terminal=$(terminal_for "$make_script" external)
  if ! (
    cd "$external_driver"
    /usr/bin/env -i \
      -u COMMIT \
      -u IMAGE \
      -u CONTAINER \
      -u VOLUME \
      GO="$fake_go" \
      FAKE_AEGIS_TEMPLATE="$fake_aegis_template" \
      FAKE_AEGIS_STATE_DIR="$make_state" \
      FAKE_AEGIS_PORT="$make_port" \
      PORT="$make_port" \
      AMBIENT_FILTER_HELPER="$ambient_filter_helper" \
      AMBIENT_FILTER_MARKER="$ambient_filter_marker" \
      ENV_SANITIZED_MARKER="$env_sanitized_marker" \
      HOST_COMMAND_MARKER="$host_command_marker" \
      CANDIDATE_IDENTITY_LOCK="$external_lock" \
      CANDIDATE_IDENTITY_LOCK_SHA256="$external_lock_sha256" \
      CANDIDATE_SOURCE_DIR="$external_source" \
      REMOTE_HOST=local \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_REMOTE_BIN="$fake_bin" \
      FAKE_DOCKER_STATE_DIR="$make_state" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      FAKE_TRANSPORT_STATE_DIR="$make_transport" \
      GIT_CONFIG_PARAMETERS="filter.aegis.clean=$ambient_filter_helper" \
      GIT_CONFIG_COUNT=1 \
      GIT_CONFIG_KEY_37=filter.aegis.clean \
      GIT_CONFIG_VALUE_37="$ambient_filter_helper" \
      GIT_EXEC_PATH="$fake_bin" \
      GIT_DIR=/ambient/git-dir \
      GIT_WORK_TREE=/ambient/work-tree \
      GIT_COMMON_DIR=/ambient/common-dir \
      GIT_INDEX_FILE=/ambient/index \
      GIT_OBJECT_DIRECTORY=/ambient/objects \
      GIT_ALTERNATE_OBJECT_DIRECTORIES=/ambient/alternates \
      GIT_REPLACE_REF_BASE=refs/ambient \
      GIT_SHALLOW_FILE=/ambient/shallow \
      GIT_EXTERNAL_DIFF="$ambient_filter_helper" \
      GIT_ASKPASS="$ambient_filter_helper" \
      SSH_ASKPASS="$ambient_filter_helper" \
      GIT_SSH="$ambient_filter_helper" \
      GIT_SSH_COMMAND="$ambient_filter_helper" \
      GIT_PROXY_COMMAND="$ambient_filter_helper" \
      PATH="$fake_bin:/usr/bin:/bin" \
      /usr/bin/make -s --no-print-directory -C "$external_source" "$make_target" \
        GO="$fake_go" VERSION=v0.2.1-contract BUILD_DATE=2026-08-20T00:00:00Z
  ) >"$make_output" 2>&1; then
    echo "make $make_target external technical fixture failed" >&2
    /bin/cat "$make_output" >&2
    exit 1
  fi
  make_actual_terminal=$(/usr/bin/tail -n 1 "$make_output")
  if [ "$make_actual_terminal" != "$make_expected_terminal" ]; then
    echo "make $make_target emitted an unexpected external terminal" >&2
    printf 'expected=%s\nactual=%s\n' \
      "$make_expected_terminal" "$make_actual_terminal" >&2
    exit 1
  fi
  if /usr/bin/grep -F -- "$equals_pass" "$make_output" >/dev/null; then
    echo "make $make_target emitted a grep-ambiguous PASS token" >&2
    exit 1
  fi
  if [ -e "$ambient_filter_marker" ] || [ -e "$host_command_marker" ]; then
    echo "make $make_target executed ambient filter or host tooling" >&2
    exit 1
  fi
  if [ "$(contract_metadata "$external_source")" != "$external_source_metadata" ]; then
    echo "make $make_target drifted the external source root metadata" >&2
    exit 1
  fi
}

run_external_make_success local-smoke 28201
run_external_make_success release-preflight 28202
run_external_make_success ceo-docker-smoke 28203

assert_make_variable_injection_rejected() {
  injection_target=$1
  injection_output="$test_root/make-injection-${injection_target}.out"
  injection_go_marker="$test_root/make-injection-${injection_target}-go"
  injection_version_marker="$test_root/make-injection-${injection_target}-version"
  injection_date_marker="$test_root/make-injection-${injection_target}-date"
  injection_go=$(printf 'unsafe`/usr/bin/touch %s`' "$injection_go_marker")
  injection_version=$(printf 'unsafe`/usr/bin/touch %s`' "$injection_version_marker")
  injection_date=$(printf 'unsafe`/usr/bin/touch %s`' "$injection_date_marker")
  /bin/rm -f "$injection_go_marker" "$injection_version_marker" "$injection_date_marker"
  if (
    cd "$external_driver"
    /usr/bin/env -i \
      -u MAKEFILES \
      -u MAKEFLAGS \
      -u GNUMAKEFLAGS \
      -u MAKEOVERRIDES \
      -u MFLAGS \
      GO="$injection_go" \
      VERSION="$injection_version" \
      BUILD_DATE="$injection_date" \
      CANDIDATE_IDENTITY_LOCK="$external_lock" \
      CANDIDATE_IDENTITY_LOCK_SHA256="$external_lock_sha256" \
      CANDIDATE_SOURCE_DIR="$external_source" \
      REMOTE_HOST=local \
      /usr/bin/make -s --no-print-directory -C "$external_source" "$injection_target"
  ) >"$injection_output" 2>&1; then
    echo "make $injection_target accepted malicious exported build variables" >&2
    exit 1
  fi
  for injection_marker in \
    "$injection_go_marker" "$injection_version_marker" "$injection_date_marker"
  do
    if [ -e "$injection_marker" ]; then
      echo "make $injection_target executed a caller-controlled build variable" >&2
      /bin/cat "$injection_output" >&2
      exit 1
    fi
  done
}

assert_make_variable_injection_rejected local-smoke
assert_make_variable_injection_rejected release-preflight
assert_make_variable_injection_rejected ceo-docker-smoke

make_fake_path="$test_root/make-fake-path"
/bin/mkdir -p "$make_fake_path"
make_git_marker="$test_root/make-ambient-git-executed"
cat >"$make_fake_path/git" <<'MAKE_FAKE_GIT'
#!/bin/sh
set -eu
: >"$MAKE_GIT_MARKER"
printf '%s\n' caller-controlled-git-output
MAKE_FAKE_GIT
/bin/chmod 700 "$make_fake_path/git"
for make_target in local-smoke release-preflight ceo-docker-smoke; do
  make_output="$test_root/make-${make_target}.out"
  /bin/rm -f "$make_git_marker"
  if ! MAKE_GIT_MARKER="$make_git_marker" \
    PATH="$make_fake_path:/usr/bin:/bin" \
    /usr/bin/make -s -n -C "$workspace_root" "$make_target" >"$make_output" 2>&1; then
    echo "make -n $make_target failed" >&2
    /bin/cat "$make_output" >&2
    exit 1
  fi
  if [ -e "$make_git_marker" ]; then
    echo "make -n $make_target executed ambient Git during parse" >&2
    exit 1
  fi
  if /usr/bin/grep -E '(^|[[:space:]])COMMIT=' "$make_output" >/dev/null; then
    echo "make -n $make_target injects an untrusted COMMIT into the script" >&2
    /bin/cat "$make_output" >&2
    exit 1
  fi
done

assert_fake_remote_hook_is_contract_only() {
  state_dir="$test_root/docker-fake-hook-production-state"
  git_state_dir="$test_root/docker-fake-hook-production-git-state"
  transport_state_dir="$test_root/docker-fake-hook-production-transport"
  output="$test_root/docker-fake-hook-production.out"
  fake_remote_dir="/tmp/aegis-docker-test.fakehook$$"
  mkdir -p "$state_dir" "$git_state_dir" "$transport_state_dir"
  : >"$state_dir/delete-attempts"
  rm -rf "$fake_remote_dir"
  :

  if (
    unset IMAGE CONTAINER VOLUME AEGIS_INTERNAL_TEST_FIXTURE_MODE
    PATH="$fake_bin:/usr/bin:/bin" \
      ALLOW_DIRTY=1 \
      REMOTE_HOST=local \
      VERSION=v0.2.1-fake-hook-contract \
      COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
      BUILD_DATE=2026-06-20T00:00:00Z \
      PORT=18082 \
      FAKE_GIT_STATE_DIR="$git_state_dir" \
      FAKE_GIT_DRIFT_KIND=none \
      FAKE_EMPTY_TAR="$empty_tar" \
      FAKE_REMOTE_DIR="$fake_remote_dir" \
      FAKE_REMOTE_BIN="$fake_bin" \
      FAKE_DOCKER_STATE_DIR="$state_dir" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      FAKE_TRANSPORT_MUST_BE_LOCAL=1 \
      FAKE_TRANSPORT_STATE_DIR="$transport_state_dir" \
      /bin/sh "$ceo_contract_runner"
  ) >"$output" 2>&1; then
    echo "ceo docker smoke accepted FAKE_REMOTE_BIN outside internal contract mode" >&2
    exit 1
  fi
  if ! grep -F -- "FAKE_REMOTE_BIN is restricted to internal contract tests" "$output" >/dev/null; then
    echo "ceo docker smoke did not explicitly reject FAKE_REMOTE_BIN in production mode" >&2
    cat "$output" >&2
    exit 1
  fi
  if grep -F -- "ceo_docker_smoke=LEGACY_ACCEPTABLE_TOKEN" "$output" >/dev/null ||
     grep -F -- "ceo_docker_smoke=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED" "$output" >/dev/null; then
    echo "ceo docker smoke emitted a terminal after rejecting the fake remote hook" >&2
    exit 1
  fi
  if [ -e "$fake_remote_dir" ] || [ -L "$fake_remote_dir" ]; then
    echo "ceo docker smoke reached remote mutation before rejecting the fake remote hook" >&2
    exit 1
  fi
}

assert_fake_remote_hook_is_contract_only

assert_docker_cleanup_failure_is_fatal() {
  state_dir="$test_root/docker-cleanup-state"
  git_state_dir="$test_root/docker-cleanup-git-state"
  output="$test_root/docker-cleanup.out"
  fake_remote_dir="/tmp/aegis-docker-test.contract$$"
  mkdir -p "$state_dir" "$git_state_dir"
  rm -rf "$fake_remote_dir"
  :
  if (
    PATH="$fake_bin:/usr/bin:/bin" \
      ALLOW_DIRTY=1 \
      REMOTE_HOST=fake-ceo \
      VERSION=v0.2.1-cleanup-contract \
      COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
      BUILD_DATE=2026-06-20T00:00:00Z \
      PORT=18082 \
      FAKE_GIT_STATE_DIR="$git_state_dir" \
      FAKE_GIT_DRIFT_KIND=none \
      FAKE_EMPTY_TAR="$empty_tar" \
      FAKE_REMOTE_DIR="$fake_remote_dir" \
      FAKE_REMOTE_BIN="$fake_bin" \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_DOCKER_STATE_DIR="$state_dir" \
      FAKE_DOCKER_FAIL_VOLUME_RM=1 \
      /bin/sh "$ceo_contract_runner"
  ) >"$output" 2>&1; then
    echo "ceo docker smoke accepted a secret-bearing volume cleanup failure" >&2
    exit 1
  fi
  if ! grep -F -- "remote cleanup could not remove secret-bearing volume" "$output" >/dev/null; then
    echo "ceo docker smoke did not report the fake Docker cleanup failure" >&2
    cat "$output" >&2
    exit 1
  fi
  if ! grep -F -- "remote cleanup absence oracle found run-labeled volumes" "$output" >/dev/null; then
    echo "ceo docker smoke did not run the volume absence oracle" >&2
    cat "$output" >&2
    exit 1
  fi
  if grep -F -- "ceo_docker_smoke=LEGACY_ACCEPTABLE_TOKEN" "$output" >/dev/null; then
    echo "ceo docker smoke emitted PASS after cleanup failure" >&2
    exit 1
  fi
  if [ -e "$fake_remote_dir" ] || [ -L "$fake_remote_dir" ]; then
    echo "ceo docker smoke did not remove its remote directory after cleanup failure" >&2
    exit 1
  fi
}

assert_docker_cleanup_failure_is_fatal

assert_docker_resource_override_is_rejected() {
  override_name=$1
  state_dir="$test_root/docker-override-${override_name}-state"
  git_state_dir="$test_root/docker-override-${override_name}-git-state"
  output="$test_root/docker-override-${override_name}.out"
  fake_remote_dir="/tmp/aegis-docker-test.override${override_name}$$"
  mkdir -p "$state_dir" "$git_state_dir"
  : >"$state_dir/delete-attempts"
  case "$override_name" in
    IMAGE) override_assignment='IMAGE=aegis:forbidden-override' ;;
    CONTAINER) override_assignment='CONTAINER=aegis-forbidden-override' ;;
    VOLUME) override_assignment='VOLUME=aegis-forbidden-override-data' ;;
    *) echo "unsupported Docker override fixture: $override_name" >&2; exit 1 ;;
  esac
  rm -rf "$fake_remote_dir"
  :
  if /usr/bin/env -u IMAGE -u CONTAINER -u VOLUME \
    "$override_assignment" \
    PATH="$fake_bin:/usr/bin:/bin" \
    ALLOW_DIRTY=1 \
    REMOTE_HOST=fake-ceo \
    VERSION=v0.2.1-ownership-contract \
    COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
    BUILD_DATE=2026-06-20T00:00:00Z \
    PORT=18082 \
    FAKE_GIT_STATE_DIR="$git_state_dir" \
    FAKE_GIT_DRIFT_KIND=none \
    FAKE_EMPTY_TAR="$empty_tar" \
    FAKE_REMOTE_DIR="$fake_remote_dir" \
    FAKE_REMOTE_BIN="$fake_bin" \
    AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
    FAKE_DOCKER_STATE_DIR="$state_dir" \
    /bin/sh "$ceo_contract_runner" >"$output" 2>&1; then
    echo "ceo docker smoke accepted a caller-supplied ${override_name}" >&2
    exit 1
  fi
  if ! grep -F -- "ceo docker smoke does not allow ${override_name} overrides" "$output" >/dev/null; then
    echo "ceo docker smoke did not report the forbidden ${override_name} override" >&2
    cat "$output" >&2
    exit 1
  fi
  if [ -s "$state_dir/delete-attempts" ]; then
    echo "ceo docker smoke attempted Docker deletion while rejecting ${override_name}" >&2
    cat "$state_dir/delete-attempts" >&2
    exit 1
  fi
  if [ -e "$fake_remote_dir" ] || [ -L "$fake_remote_dir" ]; then
    echo "ceo docker smoke reached the remote host before rejecting ${override_name}" >&2
    exit 1
  fi
}

assert_preexisting_generated_docker_resource_is_preserved() {
  ownership_kind=$1
  state_dir="$test_root/docker-generated-${ownership_kind}-state"
  git_state_dir="$test_root/docker-generated-${ownership_kind}-git-state"
  output="$test_root/docker-generated-${ownership_kind}.out"
  fake_remote_dir="/tmp/aegis-docker-test.generated${ownership_kind}$$"
  mkdir -p "$state_dir" "$git_state_dir"
  : >"$state_dir/delete-attempts"
  case "$ownership_kind" in
    container) ownership_marker=named-container ;;
    volume) ownership_marker=volume ;;
    image) ownership_marker=image ;;
    *) echo "unsupported Docker ownership fixture: $ownership_kind" >&2; exit 1 ;;
  esac
  : >"$state_dir/$ownership_marker"
  rm -rf "$fake_remote_dir"
  :

  smoke_rc=0
  if (
    unset IMAGE CONTAINER VOLUME
    PATH="$fake_bin:/usr/bin:/bin" \
      ALLOW_DIRTY=1 \
      REMOTE_HOST=fake-ceo \
      VERSION=v0.2.1-ownership-contract \
      COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
      BUILD_DATE=2026-06-20T00:00:00Z \
      PORT=18082 \
      FAKE_GIT_STATE_DIR="$git_state_dir" \
      FAKE_GIT_DRIFT_KIND=none \
      FAKE_EMPTY_TAR="$empty_tar" \
      FAKE_REMOTE_DIR="$fake_remote_dir" \
      FAKE_REMOTE_BIN="$fake_bin" \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_DOCKER_STATE_DIR="$state_dir" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      /bin/sh "$ceo_contract_runner"
  ) >"$output" 2>&1; then
    smoke_rc=0
  else
    smoke_rc=$?
  fi

  ownership_contract_failed=0
  if [ "$smoke_rc" -eq 0 ]; then
    echo "ceo docker smoke accepted a pre-existing generated ${ownership_kind}" >&2
    ownership_contract_failed=1
  fi
  if ! grep -F -- "pre-existing ${ownership_kind}" "$output" >/dev/null; then
    echo "ceo docker smoke did not report the pre-existing generated ${ownership_kind}" >&2
    ownership_contract_failed=1
  fi
  if [ -s "$state_dir/delete-attempts" ]; then
    echo "ceo docker smoke attempted to delete an unowned generated ${ownership_kind}" >&2
    cat "$state_dir/delete-attempts" >&2
    ownership_contract_failed=1
  fi
  if [ ! -f "$state_dir/$ownership_marker" ]; then
    echo "ceo docker smoke deleted an unowned generated ${ownership_kind}" >&2
    ownership_contract_failed=1
  fi
  if [ "$ownership_contract_failed" -ne 0 ]; then
    cat "$output" >&2
    exit 1
  fi
}

for override_name in IMAGE CONTAINER VOLUME; do
  assert_docker_resource_override_is_rejected "$override_name"
done
for ownership_kind in container volume image; do
  assert_preexisting_generated_docker_resource_is_preserved "$ownership_kind"
done

assert_high_entropy_recovery_name() {
  recovered_name=$1
  recovery_kind=$2
  case "$recovery_kind" in
    provider-create)
      case "$recovered_name" in
        aegis-ceo-smoke-*-provider-import) ;;
        *) echo "provider recovery did not use the exact generated provider container name: $recovered_name" >&2; exit 1 ;;
      esac
      recovery_token=${recovered_name#aegis-ceo-smoke-}
      recovery_token=${recovery_token%-provider-import}
      ;;
    runtime-run)
      case "$recovered_name" in
        aegis-ceo-smoke-*) ;;
        *) echo "runtime recovery did not use the exact generated runtime container name: $recovered_name" >&2; exit 1 ;;
      esac
      recovery_token=${recovered_name#aegis-ceo-smoke-}
      ;;
    *) echo "unsupported disconnect recovery kind: $recovery_kind" >&2; exit 1 ;;
  esac
  case "$recovery_token" in
    *[!0-9a-f]*|'') echo "disconnect recovery name did not contain a hexadecimal ownership token" >&2; exit 1 ;;
  esac
  if [ "${#recovery_token}" -ne 32 ]; then
    echo "disconnect recovery name did not contain a 128-bit ownership token" >&2
    exit 1
  fi
}

assert_owned_disconnect_resource_is_recovered() {
  disconnect_kind=$1
  state_dir="$test_root/docker-disconnect-${disconnect_kind}-state"
  git_state_dir="$test_root/docker-disconnect-${disconnect_kind}-git-state"
  transport_state_dir="$test_root/docker-disconnect-${disconnect_kind}-transport"
  output="$test_root/docker-disconnect-${disconnect_kind}.out"
  fake_remote_dir="/tmp/aegis-docker-test.disconnect${disconnect_kind}$$"
  case "$disconnect_kind" in
    provider-create)
      resource_marker=provider-container
      expected_id=3333333333333333333333333333333333333333333333333333333333333333
      lookup_pattern='-provider-import$'
      ;;
    runtime-run)
      resource_marker=named-container
      expected_id=2222222222222222222222222222222222222222222222222222222222222222
      lookup_pattern='^aegis-ceo-smoke-[0-9a-f][0-9a-f]*$'
      ;;
    *) echo "unsupported Docker disconnect fixture: $disconnect_kind" >&2; exit 1 ;;
  esac
  mkdir -p "$state_dir" "$git_state_dir" "$transport_state_dir"
  : >"$state_dir/delete-attempts"
  : >"$state_dir/name-lookups"
  rm -rf "$fake_remote_dir"
  :

  if (
    unset IMAGE CONTAINER VOLUME
    PATH="$fake_bin:/usr/bin:/bin" \
      ALLOW_DIRTY=1 \
      REMOTE_HOST=local \
      VERSION=v0.2.1-disconnect-contract \
      COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
      BUILD_DATE=2026-06-20T00:00:00Z \
      PORT=18082 \
      FAKE_GIT_STATE_DIR="$git_state_dir" \
      FAKE_GIT_DRIFT_KIND=none \
      FAKE_EMPTY_TAR="$empty_tar" \
      FAKE_REMOTE_DIR="$fake_remote_dir" \
      FAKE_REMOTE_BIN="$fake_bin" \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_DOCKER_STATE_DIR="$state_dir" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      FAKE_DOCKER_DISCONNECT_AFTER_CREATE="$disconnect_kind" \
      FAKE_TRANSPORT_MUST_BE_LOCAL=1 \
      FAKE_TRANSPORT_STATE_DIR="$transport_state_dir" \
      /bin/sh "$ceo_contract_runner"
  ) >"$output" 2>&1; then
    echo "ceo docker smoke accepted a ${disconnect_kind} daemon disconnect" >&2
    exit 1
  fi
  if [ -e "$state_dir/$resource_marker" ]; then
    echo "ceo docker smoke left its run-owned secret container after ${disconnect_kind} disconnect" >&2
    cat "$output" >&2
    exit 1
  fi
  if ! grep -F -x -- "container:$expected_id" "$state_dir/delete-attempts" >/dev/null; then
    echo "ceo docker smoke did not delete the recovered ${disconnect_kind} container by exact id" >&2
    cat "$state_dir/delete-attempts" >&2
    exit 1
  fi
  if ! recovered_name=$(grep -E -- "$lookup_pattern" "$state_dir/name-lookups" | tail -n 1) ||
     [ -z "$recovered_name" ]; then
    echo "ceo docker smoke did not recover the disconnected ${disconnect_kind} container by exact name" >&2
    cat "$state_dir/name-lookups" >&2
    exit 1
  fi
  assert_high_entropy_recovery_name "$recovered_name" "$disconnect_kind"
  if grep -F -x -- "container:$recovered_name" "$state_dir/delete-attempts" >/dev/null; then
    echo "ceo docker smoke deleted the recovered ${disconnect_kind} container by mutable name instead of exact id" >&2
    exit 1
  fi
  if grep -F -- "ceo_docker_smoke=LEGACY_ACCEPTABLE_TOKEN" "$output" >/dev/null; then
    echo "ceo docker smoke emitted PASS after a ${disconnect_kind} daemon disconnect" >&2
    exit 1
  fi
  if [ -e "$fake_remote_dir" ] || [ -L "$fake_remote_dir" ]; then
    echo "ceo docker smoke did not remove its transport directory after ${disconnect_kind} disconnect" >&2
    exit 1
  fi
}

for disconnect_kind in provider-create runtime-run; do
  assert_owned_disconnect_resource_is_recovered "$disconnect_kind"
done

assert_unowned_disconnect_resource_is_preserved() {
  state_dir="$test_root/docker-disconnect-unowned-state"
  git_state_dir="$test_root/docker-disconnect-unowned-git-state"
  transport_state_dir="$test_root/docker-disconnect-unowned-transport"
  output="$test_root/docker-disconnect-unowned.out"
  fake_remote_dir="/tmp/aegis-docker-test.disconnectunowned$$"
  expected_id=3333333333333333333333333333333333333333333333333333333333333333
  mkdir -p "$state_dir" "$git_state_dir" "$transport_state_dir"
  : >"$state_dir/delete-attempts"
  : >"$state_dir/name-lookups"
  rm -rf "$fake_remote_dir"
  :

  if (
    unset IMAGE CONTAINER VOLUME
    PATH="$fake_bin:/usr/bin:/bin" \
      ALLOW_DIRTY=1 \
      REMOTE_HOST=local \
      VERSION=v0.2.1-disconnect-unowned-contract \
      COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
      BUILD_DATE=2026-06-20T00:00:00Z \
      PORT=18082 \
      FAKE_GIT_STATE_DIR="$git_state_dir" \
      FAKE_GIT_DRIFT_KIND=none \
      FAKE_EMPTY_TAR="$empty_tar" \
      FAKE_REMOTE_DIR="$fake_remote_dir" \
      FAKE_REMOTE_BIN="$fake_bin" \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_DOCKER_STATE_DIR="$state_dir" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      FAKE_DOCKER_DISCONNECT_AFTER_CREATE=provider-create \
      FAKE_DOCKER_DISCONNECT_UNOWNED=1 \
      FAKE_TRANSPORT_MUST_BE_LOCAL=1 \
      FAKE_TRANSPORT_STATE_DIR="$transport_state_dir" \
      /bin/sh "$ceo_contract_runner"
  ) >"$output" 2>&1; then
    echo "ceo docker smoke accepted an unowned disconnect fixture" >&2
    exit 1
  fi
  if [ ! -e "$state_dir/provider-container" ]; then
    echo "ceo docker smoke deleted a disconnected container whose ownership label did not match" >&2
    exit 1
  fi
  if grep -F -x -- "container:$expected_id" "$state_dir/delete-attempts" >/dev/null; then
    echo "ceo docker smoke deleted an unowned disconnected container by id" >&2
    exit 1
  fi
  if grep -E -- '^container:aegis-ceo-smoke-' "$state_dir/delete-attempts" >/dev/null; then
    echo "ceo docker smoke deleted an unowned disconnected container by name" >&2
    exit 1
  fi
  if ! grep -F -- "remote cleanup refused recovery of unowned container" "$output" >/dev/null; then
    echo "ceo docker smoke did not report refusing the unowned disconnect recovery" >&2
    cat "$output" >&2
    exit 1
  fi
  if grep -F -- "ceo_docker_smoke=LEGACY_ACCEPTABLE_TOKEN" "$output" >/dev/null; then
    echo "ceo docker smoke emitted PASS with an unowned disconnected container" >&2
    exit 1
  fi
}

assert_unowned_disconnect_resource_is_preserved

assert_local_transport_avoids_ssh_and_rsync() {
  state_dir="$test_root/docker-local-transport-state"
  git_state_dir="$test_root/docker-local-transport-git-state"
  transport_state_dir="$test_root/docker-local-transport-invocations"
  output="$test_root/docker-local-transport.out"
  fake_remote_dir="/tmp/aegis-docker-test.localcontract$$"
  mkdir -p "$state_dir" "$git_state_dir" "$transport_state_dir"
  : >"$state_dir/delete-attempts"
  rm -rf "$fake_remote_dir"
  :

  if ! (
    unset IMAGE CONTAINER VOLUME
    PATH="$fake_bin:/usr/bin:/bin" \
      ALLOW_DIRTY=1 \
      REMOTE_HOST=local \
      VERSION=v0.2.1-local-transport-contract \
      COMMIT=workspace-e4805e6f35d702a915288eeb348af5e25042972e \
      BUILD_DATE=2026-06-20T00:00:00Z \
      PORT=18082 \
      FAKE_GIT_STATE_DIR="$git_state_dir" \
      FAKE_GIT_DRIFT_KIND=none \
      FAKE_EMPTY_TAR="$empty_tar" \
      FAKE_REMOTE_DIR="$fake_remote_dir" \
      FAKE_REMOTE_BIN="$fake_bin" \
      AEGIS_INTERNAL_TEST_FIXTURE_MODE=1 \
      FAKE_DOCKER_STATE_DIR="$state_dir" \
      FAKE_DOCKER_FAIL_VOLUME_RM=0 \
      FAKE_TRANSPORT_MUST_BE_LOCAL=1 \
      FAKE_TRANSPORT_STATE_DIR="$transport_state_dir" \
      /bin/sh "$ceo_contract_runner"
  ) >"$output" 2>&1; then
    echo "ceo docker smoke local transport contract failed" >&2
    cat "$output" >&2
    exit 1
  fi
  for forbidden_marker in ssh-invoked rsync-invoked; do
    if [ -e "$transport_state_dir/$forbidden_marker" ]; then
      echo "ceo docker smoke local transport invoked ${forbidden_marker%-invoked}" >&2
      exit 1
    fi
  done
  if ! grep -F -- "transport=local" "$output" >/dev/null; then
    echo "ceo docker smoke local transport did not report its transport identity" >&2
    exit 1
  fi
  if ! grep -F -- "evidence_acceptance=TEST_FIXTURE_ONLY" "$output" >/dev/null; then
    echo "ceo docker smoke fake local transport did not mark its evidence as TEST_FIXTURE_ONLY" >&2
    exit 1
  fi
  if ! grep -F -- "ceo_docker_smoke=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED" "$output" >/dev/null; then
    echo "ceo docker smoke fake local transport did not emit its non-acceptable terminal" >&2
    exit 1
  fi
  if grep -F -- "ceo_docker_smoke=LEGACY_ACCEPTABLE_TOKEN" "$output" >/dev/null; then
    echo "ceo docker smoke fake local transport emitted an acceptable PASS" >&2
    exit 1
  fi
  for resource_marker in image volume transient-container named-container provider-container issuer-container; do
    if [ -e "$state_dir/$resource_marker" ]; then
      echo "ceo docker smoke local transport left fake Docker resource ${resource_marker}" >&2
      exit 1
    fi
  done
}

assert_local_transport_avoids_ssh_and_rsync



assert_rollback_make_contract() {
  output="$test_root/rollback-drill.make.out"
  digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  /usr/bin/make -s -n -C "$workspace_root" rollback-drill \
    CANDIDATE_BIN=/tmp/aegis-candidate \
    ROLLBACK_BIN=/tmp/aegis-rollback \
    INPUT_LOCK=/tmp/aegis-input.lock \
    INPUT_LOCK_SHA256="$digest" >"$output"
  assert_file_contains "$output" '--input-lock "/tmp/aegis-input.lock"' \
    "rollback-drill Make target did not pass the input lock path"
  assert_file_contains "$output" "--input-lock-sha256 \"$digest\"" \
    "rollback-drill Make target did not pass the input lock digest"
}

assert_rollback_make_contract

echo "release identity contract tests passed"
