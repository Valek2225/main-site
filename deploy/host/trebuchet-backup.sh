#!/usr/bin/env bash
# trebuchet-backup: encrypted off-site backups.
#
#   trebuchet-backup run        snapshot -> tar -> pad -> age (public key only) -> S3
#   trebuchet-backup self-test  check that the S3 key can write but can NOT delete or read
#
# Properties:
#   - encrypted with age to recipients whose PRIVATE keys are offline: this server can
#     write backups but can never decrypt them (unlike restic/borg, whose password must
#     live on the server);
#   - plaintext only ever exists in /run (tmpfs, RAM), never on disk;
#   - size padded to a whole MiB, file names are timestamps + random suffix;
#   - the bucket must have Object Lock default retention (compliance mode) and the key
#     must be write-only; `self-test` verifies the key part.
#
# Config: /etc/trebuchet/backup.env (see backup.env.example). Requires: tar, age, rclone.
set -euo pipefail
umask 077

CONFIG="${TREBUCHET_BACKUP_CONFIG:-/etc/trebuchet/backup.env}"
[ "$(stat -c '%u %a' "$CONFIG")" = "0 600" ] || { echo "trebuchet-backup: $CONFIG must be owned by root with mode 600" >&2; exit 1; }
# shellcheck source=/dev/null
. "$CONFIG"

: "${BACKUP_S3_ENDPOINT:?}" "${BACKUP_S3_BUCKET:?}" "${BACKUP_S3_REGION:?}"
: "${BACKUP_S3_ACCESS_KEY_ID:?}" "${BACKUP_S3_SECRET_ACCESS_KEY:?}"
: "${BACKUP_AGE_RECIPIENTS_FILE:=/etc/trebuchet/backup-recipients.txt}"
: "${BACKUP_SOURCE:=/srv/trebuchet/data/snapshots}"
: "${BACKUP_PREFIX:=trebuchet/}"

log() { echo "trebuchet-backup: $*"; }
die() { log "ERROR: $*"; exit 1; }

[ -s "$BACKUP_AGE_RECIPIENTS_FILE" ] || die "no age recipients in $BACKUP_AGE_RECIPIENTS_FILE"
if grep -q 'AGE-SECRET-KEY' "$BACKUP_AGE_RECIPIENTS_FILE"; then
  die "$BACKUP_AGE_RECIPIENTS_FILE contains a PRIVATE key; only public recipients belong on the server"
fi

# rclone is configured only through the environment: no config file with secrets on disk.
export RCLONE_CONFIG=/dev/null
export RCLONE_CONFIG_TREBUCHETBK_TYPE=s3
export RCLONE_CONFIG_TREBUCHETBK_PROVIDER=Other
export RCLONE_CONFIG_TREBUCHETBK_ENDPOINT="$BACKUP_S3_ENDPOINT"
export RCLONE_CONFIG_TREBUCHETBK_REGION="$BACKUP_S3_REGION"
export RCLONE_CONFIG_TREBUCHETBK_ACCESS_KEY_ID="$BACKUP_S3_ACCESS_KEY_ID"
export RCLONE_CONFIG_TREBUCHETBK_SECRET_ACCESS_KEY="$BACKUP_S3_SECRET_ACCESS_KEY"
export RCLONE_CONFIG_TREBUCHETBK_NO_CHECK_BUCKET=true
unset BACKUP_S3_SECRET_ACCESS_KEY
remote="trebuchetbk:${BACKUP_S3_BUCKET}/${BACKUP_PREFIX}"
RC=(rclone --s3-no-head --retries 3 --low-level-retries 5 --stats 0)

work="$(mktemp -d /run/trebuchet-backup.XXXXXX)"
trap 'rm -rf "$work"' EXIT

rand() { od -An -N8 -tx1 /dev/urandom | tr -d ' \n'; }

cmd_run() {
  [ -d "$BACKUP_SOURCE" ] || die "backup source $BACKUP_SOURCE does not exist"
  local tarf="$work/b.tar" encf="$work/b.tar.age" size mib=$((1024 * 1024)) name
  tar -C "$BACKUP_SOURCE" --numeric-owner -cf "$tarf" .
  size="$(stat -c %s "$tarf")"
  truncate -s $(( (size + mib - 1) / mib * mib )) "$tarf" # tar ignores trailing zero blocks
  age --encrypt -R "$BACKUP_AGE_RECIPIENTS_FILE" -o "$encf" "$tarf"
  rm -f "$tarf"
  name="$(date -u +%Y%m%dT%H%M%SZ)-$(rand).tar.age"
  "${RC[@]}" copyto "$encf" "${remote}${name}"
  log "uploaded ${name} ($(stat -c %s "$encf") bytes)"
}

cmd_self_test() {
  local name probe="$work/probe" ok=1
  name="selftest-$(date -u +%Y%m%dT%H%M%SZ)-$(rand)"
  head -c 1024 /dev/urandom > "$probe"
  "${RC[@]}" copyto "$probe" "${remote}${name}" || die "upload failed: check endpoint, bucket and key"
  log "write: OK"

  if "${RC[@]}" deletefile "${remote}${name}" 2>/dev/null; then
    log "FAIL: this key can DELETE objects. Restrict it to PutObject only."
    ok=0
  else
    log "delete refused: OK"
  fi

  if "${RC[@]}" cat "${remote}${name}" >/dev/null 2>&1; then
    log "WARN: this key can READ objects. Prefer a write-only key (backups are encrypted anyway)."
  else
    log "read refused: OK"
  fi

  log "Object Lock retention is configured in the provider console; verify it once by trying"
  log "to delete '${name}' (its version) there: the provider must refuse until retention ends."
  [ $ok = 1 ] || die "self-test failed"
}

case "${1:-}" in
  run) cmd_run ;;
  self-test) cmd_self_test ;;
  *) echo "usage: trebuchet-backup run|self-test" >&2; exit 2 ;;
esac
