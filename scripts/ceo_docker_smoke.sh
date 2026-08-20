#!/bin/sh
set -eu

REMOTE_HOST=${REMOTE_HOST:-}
VERSION=${VERSION:-v0.2.1-docker-test}
BUILD_DATE=${BUILD_DATE:-2026-06-20T00:00:00Z}
IDENTITY_SURFACE='ceo docker smoke'
IDENTITY_STAGE=''
identity_acceptance=''
claimed_source_state='unavailable'
claimed_candidate_sha='unavailable'
claimed_candidate_tree='unavailable'
claimed_worktree_clean='unavailable'
claimed_source_archive_sha256=''
claimed_object_closure_sha256=''
claimed_materialized_root_sha256=''
claimed_verifier_sha256=''
claimed_verifier_provenance_sha256=''
claimed_materializer_sha256=''
claimed_materializer_provenance_sha256=''
evidence_mode=ITERATION_ONLY
INVOCATION_CWD=$(pwd -P)

case "$0" in
  /*) invoked_script=$0 ;;
  *) invoked_script="${INVOCATION_CWD}/$0" ;;
esac
if [ -L "$invoked_script" ] || [ ! -f "$invoked_script" ]; then
  echo "$IDENTITY_SURFACE must run from a non-symlink script file" >&2
  exit 1
fi
script_leaf=${invoked_script##*/}
script_parent=${invoked_script%/*}
SCRIPT_DIR=$(CDPATH= cd "$script_parent" && pwd -P) || exit 1
SCRIPT_PATH="${SCRIPT_DIR}/${script_leaf}"
if [ -L "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
  echo "$IDENTITY_SURFACE could not canonicalize its script file" >&2
  exit 1
fi
SCRIPT_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P) || exit 1
if [ "$SCRIPT_DIR" != "$SCRIPT_ROOT/scripts" ] || [ "$SCRIPT_ROOT" = / ]; then
  echo "$IDENTITY_SURFACE script must be rooted in a canonical workspace" >&2
  exit 1
fi

is_lower_hex() {
  expected_length=$1
  value=$2
  [ "${#value}" -eq "$expected_length" ] || return 1
  case "$value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
}

identity_sha256_file() {
  digest_path=$1
  if [ -x /usr/bin/shasum ]; then
    digest_output=$(/usr/bin/shasum -a 256 "$digest_path") || return 1
  elif [ -x /usr/bin/sha256sum ]; then
    digest_output=$(/usr/bin/sha256sum "$digest_path") || return 1
  else
    return 1
  fi
  digest_value=${digest_output%% *}
  is_lower_hex 64 "$digest_value" || return 1
  printf '%s\n' "$digest_value"
}

identity_cleanup_stage() {
  if [ -n "$IDENTITY_STAGE" ]; then
    /bin/chmod -R u+w "$IDENTITY_STAGE" >/dev/null 2>&1 || :
    /bin/rm -rf "$IDENTITY_STAGE" >/dev/null 2>&1 || :
    IDENTITY_STAGE=''
  fi
}

identity_cleanup_stage_strict() {
  [ -n "$IDENTITY_STAGE" ] || return 0
  identity_stage_path=$IDENTITY_STAGE
  /bin/chmod -R u+w "$identity_stage_path" || return 1
  /bin/rm -rf "$identity_stage_path" || return 1
  if [ -e "$identity_stage_path" ] || [ -L "$identity_stage_path" ]; then
    return 1
  fi
  IDENTITY_STAGE=''
}

identity_init_stage() {
  IDENTITY_STAGE=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/aegis-release-identity.XXXXXX") || return 1
  /bin/chmod 700 "$IDENTITY_STAGE" || return 1
  trap identity_cleanup_stage EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

identity_check_lock_file() {
  identity_path=$1
  case "$identity_path" in
    /*) ;;
    *) echo "$IDENTITY_SURFACE identity lock path must be absolute" >&2; return 1 ;;
  esac
  if [ -L "$identity_path" ] || [ ! -f "$identity_path" ]; then
    echo "$IDENTITY_SURFACE identity lock must be a nofollow regular file" >&2
    return 1
  fi
  if identity_metadata=$(/usr/bin/stat -f '%u:%Lp:%z:%l:%d:%i' "$identity_path" 2>/dev/null); then
    :
  elif identity_metadata=$(/usr/bin/stat -c '%u:%a:%s:%h:%d:%i' "$identity_path" 2>/dev/null); then
    :
  else
    echo "$IDENTITY_SURFACE could not inspect identity lock metadata" >&2
    return 1
  fi
  old_ifs=$IFS
  IFS=:
  set -- $identity_metadata
  IFS=$old_ifs
  [ "$#" -eq 6 ] || return 1
  identity_owner=$1
  identity_mode=$2
  identity_size=$3
  identity_links=$4
  identity_device=$5
  identity_inode=$6
  identity_euid=$(/usr/bin/id -u) || return 1
  [ "$identity_owner" = "$identity_euid" ] || {
    echo "$IDENTITY_SURFACE identity lock owner mismatch" >&2
    return 1
  }
  case "$identity_mode:$identity_size:$identity_links:$identity_device:$identity_inode" in
    *[!0-9:]*|'') return 1 ;;
  esac
  identity_group_digit=$((identity_mode / 10 % 10))
  identity_other_digit=$((identity_mode % 10))
  if [ $((identity_group_digit & 2)) -ne 0 ] || [ $((identity_other_digit & 2)) -ne 0 ]; then
    echo "$IDENTITY_SURFACE identity lock is group/other writable" >&2
    return 1
  fi
  if [ "$identity_links" -ne 1 ] || [ "$identity_size" -le 0 ] || [ "$identity_size" -gt 16384 ]; then
    echo "$IDENTITY_SURFACE identity lock size or link count is unsafe" >&2
    return 1
  fi
  identity_lock_metadata=$identity_metadata
}

identity_check_source_dir() {
  identity_source_path=$1
  identity_require_readonly=$2
  case "$identity_source_path" in
    /) echo "$IDENTITY_SURFACE materialized source must not be the filesystem root" >&2; return 1 ;;
    /*) ;;
    *) echo "$IDENTITY_SURFACE materialized source path must be absolute" >&2; return 1 ;;
  esac
  if [ -L "$identity_source_path" ] || [ ! -d "$identity_source_path" ]; then
    echo "$IDENTITY_SURFACE materialized source must be a nofollow directory" >&2
    return 1
  fi
  identity_canonical_source=$(CDPATH= cd "$identity_source_path" && pwd -P) || return 1
  [ "$identity_canonical_source" = "$identity_source_path" ] || {
    echo "$IDENTITY_SURFACE materialized source path must be canonical" >&2
    return 1
  }
  if [ "$identity_require_readonly" = 1 ]; then
    case "$identity_canonical_source" in
      "$INVOCATION_CWD"|"$INVOCATION_CWD"/*) echo "$IDENTITY_SURFACE materialized source must be outside the invocation workspace" >&2; return 1 ;;
    esac
    case "$INVOCATION_CWD" in
      "$identity_canonical_source"/*) echo "$IDENTITY_SURFACE invocation workspace must not be nested in materialized source" >&2; return 1 ;;
    esac
  fi
  if identity_source_metadata=$(/usr/bin/stat -f '%u:%Lp:%d:%i' "$identity_canonical_source" 2>/dev/null); then
    :
  elif identity_source_metadata=$(/usr/bin/stat -c '%u:%a:%d:%i' "$identity_canonical_source" 2>/dev/null); then
    :
  else
    echo "$IDENTITY_SURFACE could not inspect materialized source metadata" >&2
    return 1
  fi
  old_ifs=$IFS
  IFS=:
  set -- $identity_source_metadata
  IFS=$old_ifs
  [ "$#" -eq 4 ] || return 1
  identity_source_owner=$1
  identity_source_mode=$2
  identity_source_device=$3
  identity_source_inode=$4
  identity_euid=$(/usr/bin/id -u) || return 1
  [ "$identity_source_owner" = "$identity_euid" ] || {
    echo "$IDENTITY_SURFACE materialized source owner mismatch" >&2
    return 1
  }
  case "$identity_source_mode:$identity_source_device:$identity_source_inode" in
    *[!0-9:]*|'') return 1 ;;
  esac
  if [ "$identity_require_readonly" = 1 ]; then
    identity_owner_digit=$((identity_source_mode / 100 % 10))
    identity_group_digit=$((identity_source_mode / 10 % 10))
    identity_other_digit=$((identity_source_mode % 10))
    if [ $((identity_owner_digit & 2)) -ne 0 ] ||
      [ $((identity_group_digit & 2)) -ne 0 ] ||
      [ $((identity_other_digit & 2)) -ne 0 ]; then
      echo "$IDENTITY_SURFACE materialized source root must be read-only" >&2
      return 1
    fi
    if [ ! -d "$identity_canonical_source/.git" ] || [ -L "$identity_canonical_source/.git" ]; then
      echo "$IDENTITY_SURFACE materialized source lacks external sanitized Git metadata" >&2
      return 1
    fi
    for unsafe_git_path in \
      "$identity_canonical_source/.git/config" \
      "$identity_canonical_source/.git/hooks" \
      "$identity_canonical_source/.git/info/attributes" \
      "$identity_canonical_source/.git/info/exclude" \
      "$identity_canonical_source/.git/objects/info/grafts" \
      "$identity_canonical_source/.git/worktrees" \
      "$identity_canonical_source/.git/modules" \
      "$identity_canonical_source/.git/commondir" \
      "$identity_canonical_source/.git/index.lock" \
      "$identity_canonical_source/.git/shallow"
    do
      if [ -e "$unsafe_git_path" ] || [ -L "$unsafe_git_path" ]; then
        echo "$IDENTITY_SURFACE materialized Git metadata is not sanitized" >&2
        return 1
      fi
    done
    for unsafe_git_path in \
      "$identity_canonical_source"/.git/refs/replace* \
      "$identity_canonical_source"/.git/objects/info/*alternates*
    do
      if [ -e "$unsafe_git_path" ] || [ -L "$unsafe_git_path" ]; then
        echo "$IDENTITY_SURFACE materialized Git metadata is not sanitized" >&2
        return 1
      fi
    done
    for promisor_path in "$identity_canonical_source"/.git/objects/pack/*.promisor; do
      if [ -e "$promisor_path" ] || [ -L "$promisor_path" ]; then
        echo "$IDENTITY_SURFACE materialized Git metadata permits lazy object access" >&2
        return 1
      fi
    done
  fi
  identity_source_canonical=$identity_canonical_source
}

identity_lock_line() {
  identity_line_number=$1
  identity_key=$2
  identity_line=$(/usr/bin/sed -n "${identity_line_number}p" "$BOUND_IDENTITY_LOCK") || return 1
  case "$identity_line" in
    "$identity_key="*) identity_value=${identity_line#*=} ;;
    *) echo "$IDENTITY_SURFACE identity lock schema mismatch at $identity_key" >&2; return 1 ;;
  esac
}

identity_parse_lock() {
  identity_line_count=$(/usr/bin/wc -l <"$BOUND_IDENTITY_LOCK") || return 1
  identity_line_count=${identity_line_count##* }
  [ "$identity_line_count" = 13 ] || {
    echo "$IDENTITY_SURFACE identity lock must contain exactly 13 lines" >&2
    return 1
  }
  identity_invalid_rc=0
  LC_ALL=C /usr/bin/grep '[^A-Za-z0-9_=-]' "$BOUND_IDENTITY_LOCK" >/dev/null 2>&1 || identity_invalid_rc=$?
  case "$identity_invalid_rc" in
    0) echo "$IDENTITY_SURFACE identity lock contains non-ASCII or unsupported bytes" >&2; return 1 ;;
    1) ;;
    *) echo "$IDENTITY_SURFACE could not validate identity lock bytes" >&2; return 1 ;;
  esac
  identity_last_byte=$(/usr/bin/tail -c 1 "$BOUND_IDENTITY_LOCK" | /usr/bin/od -An -tu1 | /usr/bin/tr -d ' ')
  [ "$identity_last_byte" = 10 ] || {
    echo "$IDENTITY_SURFACE identity lock must end with one newline" >&2
    return 1
  }

  identity_lock_line 1 schema || return 1
  [ "$identity_value" = aegis-candidate-materialized-lock-v1 ] || return 1
  identity_lock_line 2 materialization_state || return 1
  [ "$identity_value" = complete ] || return 1
  claimed_source_state=unapproved_materialization
  identity_lock_line 3 claimed_candidate_sha || return 1
  claimed_candidate_sha=$identity_value
  is_lower_hex 40 "$claimed_candidate_sha" || return 1
  identity_lock_line 4 claimed_candidate_tree || return 1
  claimed_candidate_tree=$identity_value
  is_lower_hex 40 "$claimed_candidate_tree" || return 1
  identity_lock_line 5 claimed_worktree_clean || return 1
  claimed_worktree_clean=$identity_value
  [ "$claimed_worktree_clean" = true ] || return 1
  identity_lock_line 6 claimed_source_archive_sha256 || return 1
  claimed_source_archive_sha256=$identity_value
  is_lower_hex 64 "$claimed_source_archive_sha256" || return 1
  identity_lock_line 7 claimed_object_closure_sha256 || return 1
  claimed_object_closure_sha256=$identity_value
  is_lower_hex 64 "$claimed_object_closure_sha256" || return 1
  identity_lock_line 8 claimed_materialized_root_sha256 || return 1
  claimed_materialized_root_sha256=$identity_value
  is_lower_hex 64 "$claimed_materialized_root_sha256" || return 1
  identity_lock_line 9 claimed_verifier_sha256 || return 1
  claimed_verifier_sha256=$identity_value
  is_lower_hex 64 "$claimed_verifier_sha256" || return 1
  identity_lock_line 10 claimed_verifier_provenance_sha256 || return 1
  claimed_verifier_provenance_sha256=$identity_value
  is_lower_hex 64 "$claimed_verifier_provenance_sha256" || return 1
  identity_lock_line 11 claimed_materializer_sha256 || return 1
  claimed_materializer_sha256=$identity_value
  is_lower_hex 64 "$claimed_materializer_sha256" || return 1
  identity_lock_line 12 claimed_materializer_provenance_sha256 || return 1
  claimed_materializer_provenance_sha256=$identity_value
  is_lower_hex 64 "$claimed_materializer_provenance_sha256" || return 1
  identity_lock_line 13 claimed_materialized_format || return 1
  [ "$identity_value" = aegis-readonly-source-git-dir-v1 ] || return 1
}

verify_candidate_identity() {
  identity_context=$1
  identity_check_source_dir "$BOUND_SOURCE_DIR" "$BOUND_SOURCE_REQUIRE_READONLY" || return 1
  [ "$identity_source_metadata" = "$BOUND_SOURCE_METADATA" ] || {
    echo "$IDENTITY_SURFACE materialized source root drifted during ${identity_context}" >&2
    return 1
  }
  if [ -n "${BOUND_IDENTITY_LOCK:-}" ]; then
    identity_check_lock_file "$BOUND_IDENTITY_LOCK" || return 1
    [ "$identity_lock_metadata" = "$BOUND_LOCK_METADATA" ] || {
      echo "$IDENTITY_SURFACE identity lock metadata drifted during ${identity_context}" >&2
      return 1
    }
    current_lock_sha256=$(identity_sha256_file "$BOUND_IDENTITY_LOCK") || return 1
    [ "$current_lock_sha256" = "$CANDIDATE_IDENTITY_LOCK_SHA256" ] || {
      echo "$IDENTITY_SURFACE identity lock digest drifted during ${identity_context}" >&2
      return 1
    }
  fi
}

identity_load_external_bundle() {
  is_lower_hex 64 "$CANDIDATE_IDENTITY_LOCK_SHA256" || {
    echo "$IDENTITY_SURFACE received an invalid identity lock digest" >&2
    return 1
  }
  identity_check_lock_file "$CANDIDATE_IDENTITY_LOCK" || return 1
  source_lock_metadata=$identity_lock_metadata
  source_lock_sha256=$(identity_sha256_file "$CANDIDATE_IDENTITY_LOCK") || return 1
  [ "$source_lock_sha256" = "$CANDIDATE_IDENTITY_LOCK_SHA256" ] || {
    echo "$IDENTITY_SURFACE identity lock digest mismatch" >&2
    return 1
  }
  identity_check_source_dir "$CANDIDATE_SOURCE_DIR" 1 || return 1
  source_dir_metadata=$identity_source_metadata
  source_dir_canonical=$identity_source_canonical
  [ "$source_dir_canonical" = "$SCRIPT_ROOT" ] || {
    echo "$IDENTITY_SURFACE materialized source must equal the canonical script workspace" >&2
    return 1
  }

  /bin/cp "$CANDIDATE_IDENTITY_LOCK" "$IDENTITY_STAGE/identity.lock" || return 1
  /bin/chmod 400 "$IDENTITY_STAGE/identity.lock" || return 1
  BOUND_IDENTITY_LOCK="$IDENTITY_STAGE/identity.lock"
  identity_check_lock_file "$BOUND_IDENTITY_LOCK" || return 1
  BOUND_LOCK_METADATA=$identity_lock_metadata
  bound_lock_sha256=$(identity_sha256_file "$BOUND_IDENTITY_LOCK") || return 1
  [ "$bound_lock_sha256" = "$source_lock_sha256" ] || return 1
  identity_check_lock_file "$CANDIDATE_IDENTITY_LOCK" || return 1
  [ "$identity_lock_metadata" = "$source_lock_metadata" ] || return 1
  [ "$(identity_sha256_file "$CANDIDATE_IDENTITY_LOCK")" = "$source_lock_sha256" ] || return 1
  identity_check_source_dir "$CANDIDATE_SOURCE_DIR" 1 || return 1
  [ "$identity_source_metadata" = "$source_dir_metadata" ] || return 1
  [ "$identity_source_canonical" = "$source_dir_canonical" ] || return 1

  identity_parse_lock || return 1
  BOUND_SOURCE_DIR=$source_dir_canonical
  BOUND_SOURCE_METADATA=$source_dir_metadata
  BOUND_SOURCE_REQUIRE_READONLY=1
  identity_acceptance=EXTERNAL_LOCK_SCHEMA_VALIDATED_NOT_RELEASE_APPROVED
}

identity_load_bootstrap_source() {
  [ "${AEGIS_DISPOSABLE_CEO:-}" = 1 ] || {
    echo "$IDENTITY_SURFACE unverified bootstrap requires AEGIS_DISPOSABLE_CEO=1" >&2
    return 1
  }
  BOUND_IDENTITY_LOCK=''
  identity_check_source_dir "$SCRIPT_ROOT" 0 || return 1
  BOUND_SOURCE_DIR=$identity_source_canonical
  BOUND_SOURCE_METADATA=$identity_source_metadata
  BOUND_SOURCE_REQUIRE_READONLY=0
  claimed_source_state=unverified_bootstrap
  claimed_candidate_sha=unavailable
  claimed_candidate_tree=unavailable
  identity_acceptance=UNVERIFIED_ITERATION_BOOTSTRAP
}

identity_init_stage || exit 1
external_bundle_count=0
for identity_variable in "${CANDIDATE_IDENTITY_LOCK+x}" "${CANDIDATE_IDENTITY_LOCK_SHA256+x}" "${CANDIDATE_SOURCE_DIR+x}"; do
  [ "$identity_variable" = x ] && external_bundle_count=$((external_bundle_count + 1))
done
case "$external_bundle_count" in
  3)
    [ "${ALLOW_UNVERIFIED_ITERATION:-}" != 1 ] || {
      echo "$IDENTITY_SURFACE cannot mix external identity with unverified bootstrap" >&2
      exit 1
    }
    identity_load_external_bundle || exit 1
    ;;
  0)
    [ "${ALLOW_UNVERIFIED_ITERATION:-}" = 1 ] || {
      echo "$IDENTITY_SURFACE requires an external materialized source or ALLOW_UNVERIFIED_ITERATION=1" >&2
      exit 1
    }
    identity_load_bootstrap_source || exit 1
    ;;
  *)
    echo "$IDENTITY_SURFACE requires all external materialized source inputs" >&2
    exit 1
    ;;
esac
verify_candidate_identity 'initial identity capture' || exit 1
printf 'identity_acceptance=%s evidence_mode=ITERATION_ONLY claimed_source_state=%s claimed_candidate_sha=%s claimed_candidate_tree=%s claimed_materialized_root_sha256=%s final_evidence=false release_approved=false\n' \
  "$identity_acceptance" "$claimed_source_state" "$claimed_candidate_sha" "$claimed_candidate_tree" \
  "${claimed_materialized_root_sha256:-unavailable}" >&2

unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_REPLACE_REF_BASE
unset GIT_CONFIG GIT_CONFIG_SYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT
unset GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_SHALLOW_FILE GIT_EXTERNAL_DIFF
unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND
unset BASH_ENV ENV
unset MAKEFILES MAKEFLAGS GNUMAKEFLAGS MAKEOVERRIDES MFLAGS
git_config_env_names=$(LC_ALL=C /usr/bin/env | \
  /usr/bin/sed -n \
    -e 's/^\(GIT_CONFIG_KEY_[0-9][0-9]*\)=.*/\1/p' \
    -e 's/^\(GIT_CONFIG_VALUE_[0-9][0-9]*\)=.*/\1/p')
for git_config_env_name in $git_config_env_names; do
  unset "$git_config_env_name"
done
PATH=/usr/bin:/bin
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_SYSTEM=/dev/null
GIT_CONFIG_GLOBAL=/dev/null
GIT_ATTR_NOSYSTEM=1
GIT_TERMINAL_PROMPT=0
GIT_NO_REPLACE_OBJECTS=1
GIT_NO_LAZY_FETCH=1
GIT_OPTIONAL_LOCKS=0
GIT_PROTOCOL_FROM_USER=0
GOTOOLCHAIN=local
GIT_CONFIG_COUNT=5
GIT_CONFIG_KEY_0=core.hooksPath
GIT_CONFIG_VALUE_0=/dev/null
GIT_CONFIG_KEY_1=core.fsmonitor
GIT_CONFIG_VALUE_1=false
GIT_CONFIG_KEY_2=core.untrackedCache
GIT_CONFIG_VALUE_2=false
GIT_CONFIG_KEY_3=maintenance.auto
GIT_CONFIG_VALUE_3=false
GIT_CONFIG_KEY_4=gc.auto
GIT_CONFIG_VALUE_4=0
export PATH GIT_CONFIG_NOSYSTEM GIT_CONFIG_SYSTEM GIT_CONFIG_GLOBAL GIT_ATTR_NOSYSTEM
export GIT_TERMINAL_PROMPT GIT_NO_REPLACE_OBJECTS GIT_NO_LAZY_FETCH
export GIT_OPTIONAL_LOCKS GIT_PROTOCOL_FROM_USER GOTOOLCHAIN GIT_CONFIG_COUNT
export GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1
export GIT_CONFIG_KEY_2 GIT_CONFIG_VALUE_2 GIT_CONFIG_KEY_3 GIT_CONFIG_VALUE_3
export GIT_CONFIG_KEY_4 GIT_CONFIG_VALUE_4

CLAIMED_CANDIDATE_SHA=$claimed_candidate_sha
CLAIMED_CANDIDATE_TREE=$claimed_candidate_tree
EVIDENCE_MODE=ITERATION_ONLY
COMMIT_PROVIDED=${COMMIT+x}
if [ "$identity_acceptance" = UNVERIFIED_ITERATION_BOOTSTRAP ]; then
  expected_commit=iteration-bootstrap-unverified
else
  expected_commit=$CLAIMED_CANDIDATE_SHA
fi
if [ -z "${COMMIT_PROVIDED:-}" ]; then
  COMMIT=$expected_commit
fi
if [ "$COMMIT" != "$expected_commit" ]; then
  echo "ceo docker smoke COMMIT must equal bound identity ${expected_commit}" >&2
  exit 1
fi

if [ "$REMOTE_HOST" != local ]; then
  echo "ceo docker smoke must run on ssh ceo with REMOTE_HOST=local" >&2
  exit 1
fi
printf 'transport=local remote_host=local\n'
case "$VERSION" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid VERSION: $VERSION" >&2; exit 1 ;;
esac
case "$COMMIT" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid COMMIT: $COMMIT" >&2; exit 1 ;;
esac
case "$BUILD_DATE" in
  *[!A-Za-z0-9._:+-]*|'') echo "invalid BUILD_DATE: $BUILD_DATE" >&2; exit 1 ;;
esac

if [ "${IMAGE+x}" = "x" ]; then
  echo "ceo docker smoke does not allow IMAGE overrides" >&2
  exit 1
fi
if [ "${CONTAINER+x}" = "x" ]; then
  echo "ceo docker smoke does not allow CONTAINER overrides" >&2
  exit 1
fi
if [ "${VOLUME+x}" = "x" ]; then
  echo "ceo docker smoke does not allow VOLUME overrides" >&2
  exit 1
fi
TEST_FIXTURE_ONLY=0
fake_remote_bin_provided=${FAKE_REMOTE_BIN+x}
case "${AEGIS_INTERNAL_TEST_FIXTURE_MODE:-}" in
  ''|1) ;;
  *) echo "ceo docker smoke received an invalid internal test fixture mode" >&2; exit 1 ;;
esac
if [ "${fake_remote_bin_provided:-}" = "x" ]; then
  if [ "${AEGIS_INTERNAL_TEST_FIXTURE_MODE:-}" != "1" ]; then
    echo "FAKE_REMOTE_BIN is restricted to internal contract tests" >&2
    exit 1
  fi
  case "$FAKE_REMOTE_BIN" in
    /*) ;;
    *) echo "internal contract FAKE_REMOTE_BIN must be an absolute path" >&2; exit 1 ;;
  esac
  if [ ! -d "$FAKE_REMOTE_BIN" ]; then
    echo "internal contract FAKE_REMOTE_BIN directory is unavailable" >&2
    exit 1
  fi
  TEST_FIXTURE_ONLY=1
  printf 'evidence_acceptance=TEST_FIXTURE_ONLY fake_remote_hook=enabled\n'
elif [ "${AEGIS_INTERNAL_TEST_FIXTURE_MODE:-}" = "1" ]; then
  echo "internal test fixture mode requires FAKE_REMOTE_BIN" >&2
  exit 1
fi
if ! RUN_TOKEN=$(/usr/bin/openssl rand -hex 16); then
  echo "ceo docker smoke could not generate its resource ownership token" >&2
  exit 1
fi
case "$RUN_TOKEN" in
  *[!0-9a-f]*|'') echo "ceo docker smoke generated an invalid resource ownership token" >&2; exit 1 ;;
esac
if [ "${#RUN_TOKEN}" -ne 32 ]; then
  echo "ceo docker smoke generated an invalid resource ownership token" >&2
  exit 1
fi
IMAGE="aegis:ceo-smoke-${RUN_TOKEN}"
CONTAINER="aegis-ceo-smoke-${RUN_TOKEN}"
VOLUME="aegis-ceo-smoke-data-${RUN_TOKEN}"
export IMAGE CONTAINER VOLUME RUN_TOKEN
PORT=${PORT:-18082}
case "$IMAGE" in
  *[!A-Za-z0-9._:-]*|'') echo "invalid docker image identifier: $IMAGE" >&2; exit 1 ;;
esac
for value in "$CONTAINER" "$VOLUME"; do
  case "$value" in
    *[!A-Za-z0-9_.-]*|'') echo "invalid docker resource identifier: $value" >&2; exit 1 ;;
  esac
done
case "$PORT" in
  *[!0-9]*|'') echo "invalid PORT: $PORT" >&2; exit 1 ;;
esac

run_docker_smoke() {
  docker_exec_path="/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin"
  if [ -n "${FAKE_REMOTE_BIN:-}" ]; then
    docker_exec_path="${FAKE_REMOTE_BIN}:/usr/bin:/bin"
  fi
  REMOTE_DIR="$BOUND_SOURCE_DIR" \
    IMAGE="$IMAGE" \
    CONTAINER="$CONTAINER" \
    VOLUME="$VOLUME" \
    RUN_TOKEN="$RUN_TOKEN" \
    VERSION="$VERSION" \
    COMMIT="$COMMIT" \
    BUILD_DATE="$BUILD_DATE" \
    PORT="$PORT" \
    FAKE_DOCKER_STATE_DIR="${FAKE_DOCKER_STATE_DIR:-}" \
    FAKE_DOCKER_FAIL_VOLUME_RM="${FAKE_DOCKER_FAIL_VOLUME_RM:-}" \
    FAKE_DOCKER_DISCONNECT_AFTER_CREATE="${FAKE_DOCKER_DISCONNECT_AFTER_CREATE:-}" \
    FAKE_DOCKER_DISCONNECT_UNOWNED="${FAKE_DOCKER_DISCONNECT_UNOWNED:-}" \
    PATH="$docker_exec_path" \
    /bin/sh -s
}

verify_candidate_identity "candidate source gate start" || exit 1

run_docker_smoke <<'REMOTE_SCRIPT'
set -eu
cd "$REMOTE_DIR"
bin_copy="/tmp/aegis-codex-docker-test-bin-${CONTAINER}"
unauth_body="/tmp/aegis-codex-unauth-body-${CONTAINER}"
auth_body="/tmp/aegis-codex-auth-body-${CONTAINER}"
revoked_body="/tmp/aegis-codex-revoked-body-${CONTAINER}"
issue_status="/tmp/aegis-codex-issue-status-${CONTAINER}"
cid=''
runtime_cid=''
provider_cid=''
issuer_cid=''
image_id=''
volume_owned=0
cleanup_complete=0
provider_container="${CONTAINER}-provider-import"
issuer_container="${CONTAINER}-virtual-key-issue"
OWNER_LABEL_KEY='io.aegis.ceo-docker-smoke.run'
OWNER_LABEL="${OWNER_LABEL_KEY}=${RUN_TOKEN}"
case "$RUN_TOKEN" in
  *[!0-9a-f]*|'') echo "invalid remote resource ownership token" >&2; exit 1 ;;
esac
if [ "${#RUN_TOKEN}" -ne 32 ]; then
  echo "invalid remote resource ownership token" >&2
  exit 1
fi
for tracked_container in "$CONTAINER" "$provider_container" "$issuer_container"; do
  case "$tracked_container" in
    *[!A-Za-z0-9_.-]*|'') echo "invalid tracked container identifier: $tracked_container" >&2; exit 1 ;;
  esac
done
if [ "$provider_container" = "$CONTAINER" ] || \
   [ "$issuer_container" = "$CONTAINER" ] || \
   [ "$provider_container" = "$issuer_container" ]; then
  echo "tracked container identifiers must be unique" >&2
  exit 1
fi

list_contains_exact() {
  list=$1
  expected=$2
  case "
${list}
" in
    *"
${expected}
"*) return 0 ;;
  esac
  return 1
}

is_sha256_digest() {
  [ "$#" -eq 1 ] || return 1
  [ "${#1}" -eq 71 ] || return 1
  case "$1" in
    sha256:*[!0-9a-f]*) return 1 ;;
    sha256:*) return 0 ;;
  esac
  return 1
}

is_container_id() {
  [ "$#" -eq 1 ] || return 1
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
  esac
}

mark_cleanup_failure() {
  echo "$1" >&2
  cleanup_failed=1
}

container_owner_label() {
  docker inspect "$1" --format "{{ index .Config.Labels \"${OWNER_LABEL_KEY}\" }}"
}

image_owner_label() {
  docker image inspect "$1" --format "{{ index .Config.Labels \"${OWNER_LABEL_KEY}\" }}"
}

volume_owner_label() {
  docker volume inspect "$1" --format "{{ index .Labels \"${OWNER_LABEL_KEY}\" }}"
}

remove_owned_container() {
  owned_container_id=$1
  if ! current_container_ids=$(docker ps -a --no-trunc --format '{{.ID}}' 2>/dev/null); then
    echo "remote cleanup could not enumerate containers before removing ${owned_container_id}" >&2
    return 1
  fi
  if ! list_contains_exact "$current_container_ids" "$owned_container_id"; then
    return 0
  fi
  if ! current_owner_label=$(container_owner_label "$owned_container_id" 2>/dev/null); then
    echo "remote cleanup could not inspect ownership for container ${owned_container_id}" >&2
    return 1
  fi
  if [ "$current_owner_label" != "$RUN_TOKEN" ]; then
    echo "remote cleanup refused unowned container ${owned_container_id}" >&2
    return 1
  fi
  if ! docker rm -f "$owned_container_id" >/dev/null 2>&1; then
    echo "remote cleanup could not remove owned container ${owned_container_id}" >&2
    return 1
  fi
}

recover_owned_container_by_name() {
  expected_container_name=$1
  if ! recovery_container_names=$(docker ps -a --format '{{.Names}}' 2>/dev/null); then
    echo "remote cleanup could not enumerate containers while recovering ${expected_container_name}" >&2
    return 1
  fi
  if ! list_contains_exact "$recovery_container_names" "$expected_container_name"; then
    return 0
  fi
  if ! recovered_container_id=$(docker inspect "$expected_container_name" --format '{{.Id}}' 2>/dev/null); then
    echo "remote cleanup could not resolve exact container name ${expected_container_name}" >&2
    return 1
  fi
  if ! is_container_id "$recovered_container_id"; then
    echo "remote cleanup resolved an invalid container id for ${expected_container_name}" >&2
    return 1
  fi
  if ! recovered_owner_label=$(container_owner_label "$recovered_container_id" 2>/dev/null); then
    echo "remote cleanup could not inspect ownership for recovered container ${expected_container_name}" >&2
    return 1
  fi
  if [ "$recovered_owner_label" != "$RUN_TOKEN" ]; then
    echo "remote cleanup refused recovery of unowned container ${expected_container_name}" >&2
    return 1
  fi
  if ! remove_owned_container "$recovered_container_id"; then
    return 1
  fi
}

import_provider_credential() {
  if [ "$#" -ne 4 ] || [ "$1" != "--provider" ] || [ "$3" != "--credential" ]; then
    echo "invalid remote smoke provider credential fixture" >&2
    return 1
  fi
  provider_id=$2
  provider_key=$4
  if ! created_provider_cid=$(docker create --name "$provider_container" --label "$OWNER_LABEL" -i \
    -e AEGIS_MASTER_KEY="$master_key" \
    -v "$VOLUME:/var/lib/aegis" \
    "$IMAGE" operator provider-key import \
      --config /etc/aegis/aegis.json --provider "$provider_id"); then
    echo "docker could not create the provider-import container for ${provider_id}" >&2
    provider_key=''
    return 1
  fi
  if ! is_container_id "$created_provider_cid"; then
    echo "docker returned an invalid provider-import container id for ${provider_id}: ${created_provider_cid}" >&2
    provider_key=''
    return 1
  fi
  provider_cid=$created_provider_cid
  if ! created_provider_owner=$(container_owner_label "$provider_cid" 2>/dev/null); then
    echo "docker could not inspect provider-import container ownership for ${provider_id}" >&2
    provider_key=''
    return 1
  fi
  if [ "$created_provider_owner" != "$RUN_TOKEN" ]; then
    echo "docker created a provider-import container without the expected ownership label for ${provider_id}" >&2
    provider_key=''
    return 1
  fi
  if ! printf '%s' "$provider_key" | docker start -a -i "$provider_cid"; then
    echo "provider credential import failed for ${provider_id}" >&2
    provider_key=''
    return 1
  fi
  provider_key=''
  if ! remove_owned_container "$provider_cid"; then
    return 1
  fi
  provider_cid=''
  provider_id=''
}

assert_resource_scope_unused() {
  if ! existing_container_names=$(docker ps -a --format '{{.Names}}' 2>/dev/null); then
    echo "remote preflight could not enumerate containers" >&2
    return 1
  fi
  for tracked_container in "$CONTAINER" "$provider_container" "$issuer_container"; do
    if list_contains_exact "$existing_container_names" "$tracked_container"; then
      echo "remote preflight found pre-existing container ${tracked_container}" >&2
      return 1
    fi
  done
  if ! existing_volume_names=$(docker volume ls --format '{{.Name}}' 2>/dev/null); then
    echo "remote preflight could not enumerate volumes" >&2
    return 1
  fi
  if list_contains_exact "$existing_volume_names" "$VOLUME"; then
    echo "remote preflight found pre-existing volume ${VOLUME}" >&2
    return 1
  fi
  if ! existing_image_refs=$(docker image ls -a --format '{{.Repository}}:{{.Tag}}' 2>/dev/null); then
    echo "remote preflight could not enumerate images" >&2
    return 1
  fi
  if list_contains_exact "$existing_image_refs" "$IMAGE"; then
    echo "remote preflight found pre-existing image ${IMAGE}" >&2
    return 1
  fi
}

cleanup_resources() {
  cleanup_failed=0
  master_key=''
  jwt_key=''
  virtual_key=''

  for expected_container_name in "$CONTAINER" "$provider_container" "$issuer_container"; do
    if recover_owned_container_by_name "$expected_container_name"; then
      :
    else
      cleanup_failed=1
    fi
  done

  for registered_container_id in "$cid" "$runtime_cid" "$provider_cid" "$issuer_cid"; do
    if [ -z "$registered_container_id" ]; then
      continue
    fi
    if remove_owned_container "$registered_container_id"; then
      :
    else
      cleanup_failed=1
    fi
  done

  if [ "$volume_owned" -eq 1 ]; then
    if ! current_volume_names=$(docker volume ls --format '{{.Name}}' 2>/dev/null); then
      mark_cleanup_failure "remote cleanup could not enumerate volumes"
    elif list_contains_exact "$current_volume_names" "$VOLUME"; then
      if ! current_volume_owner=$(volume_owner_label "$VOLUME" 2>/dev/null); then
        mark_cleanup_failure "remote cleanup could not inspect ownership for volume ${VOLUME}"
      elif [ "$current_volume_owner" != "$RUN_TOKEN" ]; then
        mark_cleanup_failure "remote cleanup refused unowned volume ${VOLUME}"
      elif docker volume rm "$VOLUME" >/dev/null 2>&1; then
        :
      else
        mark_cleanup_failure "remote cleanup could not remove secret-bearing volume ${VOLUME}"
      fi
    fi
  fi

  if [ -n "$image_id" ]; then
    if ! current_image_ids=$(docker image ls -a --no-trunc --format '{{.ID}}' 2>/dev/null); then
      mark_cleanup_failure "remote cleanup could not enumerate images"
    elif list_contains_exact "$current_image_ids" "$image_id"; then
      if ! current_image_owner=$(image_owner_label "$image_id" 2>/dev/null); then
        mark_cleanup_failure "remote cleanup could not inspect ownership for image ${image_id}"
      elif [ "$current_image_owner" != "$RUN_TOKEN" ]; then
        mark_cleanup_failure "remote cleanup refused unowned image ${image_id}"
      elif docker rmi "$image_id" >/dev/null 2>&1; then
        :
      else
        mark_cleanup_failure "remote cleanup could not remove image ${image_id}"
      fi
    fi
  fi

  if rm -f "$bin_copy" "$unauth_body" "$auth_body" "$revoked_body" "$issue_status"; then
    :
  else
    mark_cleanup_failure "remote cleanup could not remove smoke temporary files"
  fi

  if final_container_ids=$(docker ps -a --no-trunc --format '{{.ID}}' 2>/dev/null); then
    for registered_container_id in "$cid" "$runtime_cid" "$provider_cid" "$issuer_cid"; do
      if [ -n "$registered_container_id" ] && list_contains_exact "$final_container_ids" "$registered_container_id"; then
        mark_cleanup_failure "remote cleanup absence oracle found owned container ${registered_container_id}"
      fi
    done
  else
    mark_cleanup_failure "remote cleanup could not run the container-id absence oracle"
  fi
  if final_owned_container_ids=$(docker ps -a --no-trunc --filter "label=${OWNER_LABEL}" --format '{{.ID}}' 2>/dev/null); then
    if [ -n "$final_owned_container_ids" ]; then
      mark_cleanup_failure "remote cleanup absence oracle found run-labeled containers"
    fi
  else
    mark_cleanup_failure "remote cleanup could not run the container-label absence oracle"
  fi
  if final_owned_volume_names=$(docker volume ls --filter "label=${OWNER_LABEL}" --format '{{.Name}}' 2>/dev/null); then
    if [ -n "$final_owned_volume_names" ]; then
      mark_cleanup_failure "remote cleanup absence oracle found run-labeled volumes"
    fi
  else
    mark_cleanup_failure "remote cleanup could not run the volume-label absence oracle"
  fi
  if final_owned_image_ids=$(docker image ls -a --no-trunc --filter "label=${OWNER_LABEL}" --format '{{.ID}}' 2>/dev/null); then
    if [ -n "$final_owned_image_ids" ]; then
      mark_cleanup_failure "remote cleanup absence oracle found run-labeled images"
    fi
  else
    mark_cleanup_failure "remote cleanup could not run the image-label absence oracle"
  fi
  if [ -n "$image_id" ]; then
    if final_image_ids=$(docker image ls -a --no-trunc --format '{{.ID}}' 2>/dev/null); then
      if list_contains_exact "$final_image_ids" "$image_id"; then
        mark_cleanup_failure "remote cleanup absence oracle found image id ${image_id}"
      fi
    else
      mark_cleanup_failure "remote cleanup could not run the image-id absence oracle"
    fi
  fi
  for temporary_path in "$bin_copy" "$unauth_body" "$auth_body" "$revoked_body" "$issue_status"; do
    if [ -e "$temporary_path" ] || [ -L "$temporary_path" ]; then
      mark_cleanup_failure "remote cleanup absence oracle found temporary file ${temporary_path}"
    fi
  done

  if [ "$cleanup_failed" -eq 0 ]; then
    cid=''
    runtime_cid=''
    provider_cid=''
    issuer_cid=''
    image_id=''
    volume_owned=0
    cleanup_complete=1
    return 0
  fi
  cleanup_complete=0
  return 1
}

remote_exit_handler() {
  original_rc=$?
  trap - EXIT INT TERM
  cleanup_rc=0
  if [ "$cleanup_complete" -ne 1 ]; then
    if cleanup_resources; then
      :
    else
      cleanup_rc=$?
    fi
  fi
  if [ "$original_rc" -ne 0 ]; then
    exit "$original_rc"
  fi
  exit "$cleanup_rc"
}
trap remote_exit_handler EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! assert_resource_scope_unused; then
  exit 1
fi

echo "== remote_preflight =="
printf 'host='; hostname
printf 'arch='; uname -m
printf 'docker_server='; docker version --format '{{.Server.Version}}'
printf 'docker_arch='; docker info --format '{{.Architecture}}'

echo "== docker_build =="
docker build --no-cache --pull \
  --build-arg TARGETOS=linux \
  --build-arg TARGETARCH=arm64 \
  --build-arg VERSION="$VERSION" \
  --build-arg COMMIT="$COMMIT" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --label "$OWNER_LABEL" \
  -t "$IMAGE" .
image_id=$(docker image inspect "$IMAGE" --format '{{.Id}}')
if ! is_sha256_digest "$image_id"; then
  echo "docker returned an invalid image id: ${image_id}" >&2
  exit 1
fi
if ! built_image_owner=$(image_owner_label "$image_id" 2>/dev/null); then
  echo "docker could not inspect the built image ownership label" >&2
  exit 1
fi
if [ "$built_image_owner" != "$RUN_TOKEN" ]; then
  echo "docker built image without the expected ownership label" >&2
  exit 1
fi

echo "== image_inspect =="
docker image inspect "$IMAGE" --format 'image={{.Id}} os={{.Os}} arch={{.Architecture}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}} cmd={{json .Config.Cmd}}'
test "$(docker image inspect "$IMAGE" --format '{{.Os}}')" = "linux"
test "$(docker image inspect "$IMAGE" --format '{{.Architecture}}')" = "arm64"
test "$(docker image inspect "$IMAGE" --format '{{.Config.User}}')" = "nonroot:nonroot"
test "$(docker image inspect "$IMAGE" --format '{{json .Config.Entrypoint}}')" = '["/aegis"]'
test "$(docker image inspect "$IMAGE" --format '{{json .Config.Cmd}}')" = '["--config","/etc/aegis/aegis.json"]'

created_cid=$(docker create --label "$OWNER_LABEL" "$IMAGE" --version)
if ! is_container_id "$created_cid"; then
  echo "docker returned an invalid transient container id: ${created_cid}" >&2
  exit 1
fi
cid=$created_cid
if ! created_owner=$(container_owner_label "$cid" 2>/dev/null); then
  echo "docker could not inspect transient container ownership" >&2
  exit 1
fi
if [ "$created_owner" != "$RUN_TOKEN" ]; then
  echo "docker created a transient container without the expected ownership label" >&2
  exit 1
fi
docker cp "$cid:/aegis" "$bin_copy"
if ! remove_owned_container "$cid"; then
  exit 1
fi
cid=''
binary_file_output=$(file "$bin_copy")
printf '%s\n' "$binary_file_output"
case "$binary_file_output" in
  *"ELF 64-bit LSB executable, ARM aarch64"*) ;;
  *) echo "docker image contains a non-arm64 Aegis binary: ${binary_file_output}" >&2; exit 1 ;;
esac
version_output=$(docker run --rm --label "$OWNER_LABEL" "$IMAGE" --version)
case "$version_output" in
  *"commit: ${COMMIT}"*) ;;
  *) echo "docker version output did not include expected commit ${COMMIT}: ${version_output}" >&2; exit 1 ;;
esac
printf '%s\n' "$version_output"

echo "== readonly_runtime =="
created_volume=$(docker volume create --label "$OWNER_LABEL" "$VOLUME")
if [ "$created_volume" != "$VOLUME" ]; then
  echo "docker returned an unexpected volume name: ${created_volume}" >&2
  exit 1
fi
if ! created_volume_owner=$(volume_owner_label "$VOLUME" 2>/dev/null); then
  echo "docker could not inspect volume ownership" >&2
  exit 1
fi
if [ "$created_volume_owner" != "$RUN_TOKEN" ]; then
  echo "docker created or exposed a volume without the expected ownership label" >&2
  exit 1
fi
volume_owned=1
master_key=$(/usr/bin/openssl rand -hex 32)
jwt_key=$(/usr/bin/openssl rand -hex 32)
docker run --rm --label "$OWNER_LABEL" \
  -v "$VOLUME:/var/lib/aegis" \
  "$IMAGE" operator revocation init --config /etc/aegis/aegis.json
import_provider_credential \
  --provider openai-primary \
  --credential 'sk-smoke-openai-provider-key'
import_provider_credential \
  --provider deepseek-primary \
  --credential 'sk-smoke-deepseek-provider-key'
if ! created_issuer_cid=$(docker create --name "$issuer_container" --label "$OWNER_LABEL" \
  -e AEGIS_JWT_KEY="$jwt_key" \
  -v "$VOLUME:/var/lib/aegis" \
  "$IMAGE" operator virtual-key issue \
    --config /etc/aegis/aegis.json \
    --subject smoke-client \
    --models gpt-4o-mini \
    --ttl 5m \
    --stdout); then
  echo "docker could not create the virtual-key issuer container" >&2
  exit 1
fi
if ! is_container_id "$created_issuer_cid"; then
  echo "docker returned an invalid virtual-key issuer container id: ${created_issuer_cid}" >&2
  exit 1
fi
issuer_cid=$created_issuer_cid
if ! created_issuer_owner=$(container_owner_label "$issuer_cid" 2>/dev/null); then
  echo "docker could not inspect virtual-key issuer container ownership" >&2
  exit 1
fi
if [ "$created_issuer_owner" != "$RUN_TOKEN" ]; then
  echo "docker created a virtual-key issuer container without the expected ownership label" >&2
  exit 1
fi
virtual_key=$(docker start -a "$issuer_cid" 2>"$issue_status")
if ! remove_owned_container "$issuer_cid"; then
  exit 1
fi
issuer_cid=''
cat "$issue_status"
virtual_key_id=$(sed -n 's/^virtual_key_issued kid=\([^ ]*\) expires_at=.*/\1/p' "$issue_status")
test -n "$virtual_key"
test -n "$virtual_key_id"
if ! created_runtime_cid=$(docker run -d --name "$CONTAINER" --label "$OWNER_LABEL" --read-only \
  -p "127.0.0.1:${PORT}:8080" \
  -e AEGIS_MASTER_KEY="$master_key" \
  -e AEGIS_JWT_KEY="$jwt_key" \
  -v "$VOLUME:/var/lib/aegis" \
  "$IMAGE"); then
  echo "docker could not create the runtime container" >&2
  exit 1
fi
if ! is_container_id "$created_runtime_cid"; then
  echo "docker returned an invalid runtime container id: ${created_runtime_cid}" >&2
  exit 1
fi
runtime_cid=$created_runtime_cid
if ! created_runtime_owner=$(container_owner_label "$runtime_cid" 2>/dev/null); then
  echo "docker could not inspect runtime container ownership" >&2
  exit 1
fi
if [ "$created_runtime_owner" != "$RUN_TOKEN" ]; then
  echo "docker created a runtime container without the expected ownership label" >&2
  exit 1
fi

health=''
for _ in $(seq 1 30); do
  if health=$(curl -fsS "http://127.0.0.1:${PORT}/health" 2>/dev/null); then
    break
  fi
  sleep 1
done
test "$health" = '{"status":"ok"}'
printf 'health=%s\n' "$health"

if status=$(curl -sS -o "$auth_body" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $virtual_key" \
  -H 'Content-Type: application/json' \
  --data '{' \
  "http://127.0.0.1:${PORT}/v1/chat/completions"); then
  :
else
  status=''
fi
test "$status" = "400"
printf 'authenticated_pre_revoke_status=%s\n' "$status"

docker run --rm --label "$OWNER_LABEL" \
  -v "$VOLUME:/var/lib/aegis" \
  "$IMAGE" operator virtual-key revoke \
    --config /etc/aegis/aegis.json \
    --kid "$virtual_key_id"
status=''
for _ in $(seq 1 30); do
  if status=$(curl -sS -o "$revoked_body" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $virtual_key" \
    -H 'Content-Type: application/json' \
    --data '{' \
    "http://127.0.0.1:${PORT}/v1/chat/completions"); then
    :
  else
    status=''
  fi
  if [ "$status" = "401" ]; then
    break
  fi
  sleep 0.025
done
test "$status" = "401"
printf 'revoked_status=%s\n' "$status"

if status=$(curl -sS -o "$unauth_body" -w '%{http_code}' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data '{"model":"gpt-4o-mini","messages":[]}' \
  "http://127.0.0.1:${PORT}/v1/chat/completions"); then
  :
else
  status=''
fi
test "$status" = "401"
printf 'unauth_status=%s\n' "$status"
docker inspect "$runtime_cid" --format 'readonly={{.HostConfig.ReadonlyRootfs}} user={{.Config.User}} mounts={{range .Mounts}}{{.Destination}}:{{.Type}} {{end}}'
test "$(docker inspect "$runtime_cid" --format '{{.HostConfig.ReadonlyRootfs}}')" = "true"
test "$(docker inspect "$runtime_cid" --format '{{.Config.User}}')" = "nonroot:nonroot"

verified_image_id=$image_id
if ! cleanup_resources; then
  echo "remote smoke passed functional checks but strict cleanup failed" >&2
  exit 1
fi
printf 'remote_cleanup=TECHNICAL_ITERATION_COMPLETE container=%s volume=%s image=%s image_id=%s\n' \
  "$CONTAINER" "$VOLUME" "$IMAGE" "$verified_image_id"
REMOTE_SCRIPT

verify_candidate_identity "docker smoke execution"
verify_candidate_identity "terminal evidence emission"
if ! identity_cleanup_stage_strict; then
  echo "ceo docker smoke could not strictly remove its bound identity inputs" >&2
  exit 1
fi
if [ "$identity_acceptance" = UNVERIFIED_ITERATION_BOOTSTRAP ]; then
  ceo_docker_terminal=TECHNICAL_ITERATION_PASS
else
  ceo_docker_terminal=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED
fi
printf 'ceo_docker_smoke=%s evidence_mode=ITERATION_ONLY claimed_source_state=%s claimed_candidate_sha=%s claimed_candidate_tree=%s claimed_materialized_root_sha256=%s test_fixture_only=%s final_evidence=false release_approved=false\n' \
  "$ceo_docker_terminal" "$claimed_source_state" "$CLAIMED_CANDIDATE_SHA" \
  "$CLAIMED_CANDIDATE_TREE" "${claimed_materialized_root_sha256:-unavailable}" "$TEST_FIXTURE_ONLY"
