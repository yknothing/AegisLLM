#!/bin/sh
set -eu

GO_BIN=${GO:-go}
VERSION=${VERSION:-v0.2.1-rc-local}
BUILD_DATE=${BUILD_DATE:-$(/bin/date -u +"%Y-%m-%dT%H:%M:%SZ")}
PORT=${PORT:-18083}

case "$GO_BIN" in
  *[!A-Za-z0-9_./-]*|''|-*) echo "local smoke received an invalid GO command" >&2; exit 1 ;;
  /*) TRUSTED_GO_BIN=$GO_BIN ;;
  *) echo "local smoke GO command must be an absolute path" >&2; exit 1 ;;
esac
case "$TRUSTED_GO_BIN" in
  /*) ;;
  *) echo "local smoke GO command did not resolve to an absolute path" >&2; exit 1 ;;
esac
if [ ! -f "$TRUSTED_GO_BIN" ] || [ ! -x "$TRUSTED_GO_BIN" ]; then
  echo "local smoke resolved GO command is not a regular executable file" >&2
  exit 1
fi

run_trusted_go() {
  GOWORK=off GOFLAGS=-mod=readonly GOENV=off GOTOOLCHAIN=local \
    "$TRUSTED_GO_BIN" "$@"
}

IDENTITY_SURFACE='local smoke'
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
  echo "local smoke COMMIT must equal bound identity ${expected_commit}" >&2
  exit 1
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
source_dir=$BOUND_SOURCE_DIR
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
cleanup_complete=0

cleanup() {
  cleanup_failed=0
  master_key=''
  jwt_key=''
  virtual_key=''
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    if kill "$pid" >/dev/null 2>&1; then
      :
    else
      echo "local smoke could not stop process ${pid}" >&2
      cleanup_failed=1
    fi
  fi
  if [ -n "$pid" ]; then
    if wait "$pid" >/dev/null 2>&1; then
      :
    else
      wait_rc=$?
      case "$wait_rc" in
        127|143) ;;
        *)
          if kill -0 "$pid" >/dev/null 2>&1; then
            echo "local smoke process ${pid} survived cleanup" >&2
            cleanup_failed=1
          fi
          ;;
      esac
    fi
  fi
  if rm -rf "$tmp_dir"; then
    :
  else
    echo "local smoke could not remove temporary directory ${tmp_dir}" >&2
    cleanup_failed=1
  fi
  if [ -e "$tmp_dir" ] || [ -L "$tmp_dir" ]; then
    echo "local smoke could not prove temporary directory absence: ${tmp_dir}" >&2
    cleanup_failed=1
  fi
  if [ "$cleanup_failed" -eq 0 ]; then
    cleanup_complete=1
    return 0
  fi
  cleanup_complete=0
  return 1
}

exit_handler() {
  original_rc=$?
  trap - EXIT INT TERM
  cleanup_rc=0
  if [ "$cleanup_complete" -ne 1 ]; then
    if cleanup; then
      :
    else
      cleanup_rc=$?
    fi
  fi
  identity_cleanup_stage
  if [ "$original_rc" -ne 0 ]; then
    exit "$original_rc"
  fi
  exit "$cleanup_rc"
}
trap exit_handler EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

verify_candidate_identity "candidate source gate start" || exit 1

mkdir -p "$key_dir"
sed \
	-e "s#\"address\": \":8080\"#\"address\": \"127.0.0.1:${PORT}\"#" \
	-e "s#\"key_store_path\": \"aegis.keys\"#\"key_store_path\": \"${key_dir}\"#" \
	-e "s#\"file_path\": \"aegis.revocations.json\"#\"file_path\": \"${revocation_path}\"#" \
  "${source_dir}/aegis.example.json" >"$config_path"

(
  cd "$source_dir"
  run_trusted_go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o "$bin_path" \
    ./cmd/aegis
)
verify_candidate_identity "candidate build"

version_output=$("$bin_path" --version)
case "$version_output" in
  *"commit: ${COMMIT}"*) ;;
  *) echo "version output did not include expected commit ${COMMIT}: ${version_output}" >&2; exit 1 ;;
esac
printf 'version=%s\n' "$version_output"

"$bin_path" operator revocation init --config "$config_path" >&2

master_key=$(/usr/bin/openssl rand -hex 32)
jwt_key=$(/usr/bin/openssl rand -hex 64)

import_provider_credential() {
  if [ "$#" -ne 4 ] || [ "$1" != "--provider" ] || [ "$3" != "--credential" ]; then
    echo "invalid local smoke provider credential fixture" >&2
    return 1
  fi
  provider_id=$2
  provider_key=$4
  printf '%s' "$provider_key" | \
    AEGIS_MASTER_KEY="$master_key" \
    "$bin_path" operator provider-key import \
      --config "$config_path" --provider "$provider_id" >&2
  provider_key=''
  provider_id=''
}

import_provider_credential \
  --provider openai-primary \
  --credential 'sk-smoke-openai-provider-key'
import_provider_credential \
  --provider deepseek-primary \
  --credential 'sk-smoke-deepseek-provider-key'
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
test "$(stat -c '%a' "$virtual_key_path" 2>/dev/null || stat -f '%Lp' "$virtual_key_path")" = "600"

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
if [ "$health" != '{"status":"ok"}' ]; then
  echo "aegis health check did not become ready on 127.0.0.1:${PORT}" >&2
  cat "$log_path" >&2
  exit 1
fi
printf 'health=%s\n' "$health"

virtual_key=$(tr -d '\r\n' <"$virtual_key_path")
if auth_status=$(curl -sS -o "$auth_body" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer ${virtual_key}" \
  -H 'Content-Type: application/json' \
  --data '{' \
  "http://127.0.0.1:${PORT}/v1/chat/completions"); then
  :
else
  auth_status=''
fi
test "$auth_status" = "400"
printf 'valid_auth_pre_revoke_status=%s\n' "$auth_status"

"$bin_path" operator virtual-key revoke \
  --config "$config_path" --kid "$virtual_key_id" >&2
revoked_status=''
for _ in $(seq 1 30); do
  if revoked_status=$(curl -sS -o "$auth_body" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer ${virtual_key}" \
    -H 'Content-Type: application/json' \
    --data '{' \
    "http://127.0.0.1:${PORT}/v1/chat/completions"); then
    :
  else
    revoked_status=''
  fi
  if [ "$revoked_status" = "401" ]; then
    break
  fi
  sleep 0.025
done
test "$revoked_status" = "401"
printf 'revoked_auth_status=%s\n' "$revoked_status"

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

verify_candidate_identity "smoke execution"
if ! cleanup; then
  echo "local smoke passed functional checks but strict cleanup failed" >&2
  exit 1
fi
verify_candidate_identity "final evidence emission"
if ! identity_cleanup_stage_strict; then
  echo "local smoke could not strictly remove its bound identity inputs" >&2
  exit 1
fi
if [ "$identity_acceptance" = UNVERIFIED_ITERATION_BOOTSTRAP ]; then
  local_smoke_terminal=TECHNICAL_ITERATION_PASS
else
  local_smoke_terminal=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED
fi
printf 'local_smoke=%s evidence_mode=ITERATION_ONLY claimed_source_state=%s claimed_candidate_sha=%s claimed_candidate_tree=%s claimed_materialized_root_sha256=%s final_evidence=false release_approved=false\n' \
  "$local_smoke_terminal" "$claimed_source_state" "$CLAIMED_CANDIDATE_SHA" \
  "$CLAIMED_CANDIDATE_TREE" "${claimed_materialized_root_sha256:-unavailable}"
