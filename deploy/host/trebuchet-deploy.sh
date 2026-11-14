#!/usr/bin/env bash
# trebuchet-deploy: pull-based deployer.
#
# Runs on the server from a systemd timer. GitHub has NO access to the server:
# this script pulls, verifies and only then deploys. A new release is accepted only if
#   1. the tip of main is a commit signed by an allowed key (git verify-commit), and
#   2. every image for that commit carries a Sigstore signature whose certificate says
#      it was built by THIS repository's ci.yml, on refs/heads/main, from THAT commit.
# Only services whose image digest changed are restarted. A service that does not
# become healthy is rolled back to its previous digest.
#
# Config: /etc/trebuchet/deploy.env (see deploy.env.example). Requires: git, docker, cosign.
set -euo pipefail
umask 077

CONFIG="${TREBUCHET_DEPLOY_CONFIG:-/etc/trebuchet/deploy.env}"
# The config is sourced (executed), so it must be writable by root only.
[ "$(stat -c '%u %a' "$CONFIG")" = "0 600" ] || { echo "trebuchet-deploy: $CONFIG must be owned by root with mode 600" >&2; exit 1; }
# shellcheck source=/dev/null
. "$CONFIG"

: "${TREBUCHET_REPO:?owner/name of the GitHub repository}"
: "${TREBUCHET_CHECKOUT:?path to the git checkout on this server}"
: "${TREBUCHET_ALLOWED_SIGNERS:?path to git allowed_signers file}"
: "${TREBUCHET_SERVICES:=note caddy}"
: "${TREBUCHET_STATE_DIR:=/var/lib/trebuchet-deploy}"
: "${TREBUCHET_HEALTH_TIMEOUT:=60}"

OWNER="${TREBUCHET_REPO%%/*}"
OWNER="${OWNER,,}" # ghcr.io requires lowercase
IDENTITY="https://github.com/${TREBUCHET_REPO}/.github/workflows/ci.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"
COMPOSE_DIR="$TREBUCHET_CHECKOUT/deploy"
IMAGES_ENV="$TREBUCHET_STATE_DIR/images.env"

log() { echo "trebuchet-deploy: $*"; }
die() { log "ERROR: $*"; exit 1; }

mkdir -p "$TREBUCHET_STATE_DIR"
exec 9>"$TREBUCHET_STATE_DIR/lock"
flock -n 9 || { log "another run is in progress"; exit 0; }

compose() {
  docker compose --project-directory "$COMPOSE_DIR" \
    -f "$COMPOSE_DIR/docker-compose.yml" --env-file "$IMAGES_ENV" "$@"
}

# ---- 1. fetch and verify the commit -------------------------------------------------
git -C "$TREBUCHET_CHECKOUT" fetch --quiet --no-tags origin main
target="$(git -C "$TREBUCHET_CHECKOUT" rev-parse origin/main)"
current="$(cat "$TREBUCHET_STATE_DIR/commit" 2>/dev/null || true)"

if [ "$target" = "$current" ]; then
  exit 0 # nothing new
fi
[[ "$target" =~ ^[0-9a-f]{40}$ ]] || die "unexpected commit id"

git -C "$TREBUCHET_CHECKOUT" -c gpg.format=ssh \
  -c "gpg.ssh.allowedSignersFile=$TREBUCHET_ALLOWED_SIGNERS" \
  verify-commit "$target" 2>/dev/null \
  || die "commit $target is not signed by an allowed key; refusing to deploy"
log "commit $target: signature OK"

# ---- 2. verify images and resolve digests -------------------------------------------
declare -A new_digest
for svc in $TREBUCHET_SERVICES; do
  [[ "$svc" =~ ^[a-z0-9-]+$ ]] || die "bad service name"
  repo="ghcr.io/${OWNER}/trebuchet-${svc}"
  # Resolve the tag to an immutable digest first, then verify THAT digest:
  # what we verify is exactly what we run, even if the tag moves meanwhile.
  if ! digest="$(docker buildx imagetools inspect "${repo}:sha-${target}" --format '{{.Manifest.Digest}}' 2>/dev/null)"; then
    log "image ${repo}:sha-${target} is not published yet (CI still running?); will retry"
    exit 0
  fi
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image $svc: unexpected digest '$digest'"
  cosign verify "${repo}@${digest}" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-github-workflow-repository "$TREBUCHET_REPO" \
    --certificate-github-workflow-ref refs/heads/main \
    --certificate-github-workflow-sha "$target" >/dev/null 2>&1 \
    || die "image ${repo}@${digest}: signature verification FAILED; refusing to deploy"
  new_digest[$svc]="${repo}@${digest}"
  log "image $svc: signature OK ($digest)"
done

# ---- 3. switch the checkout (compose file, Caddyfile) to the verified commit --------
prev_commit="$current"
git -C "$TREBUCHET_CHECKOUT" -c advice.detachedHead=false checkout --quiet --detach "$target"

# ---- 4. deploy only what changed, with health check and rollback --------------------
touch "$IMAGES_ENV"
cp "$IMAGES_ENV" "$IMAGES_ENV.prev"

env_var() { echo "$(echo "$1" | tr 'a-z-' 'A-Z_')_IMAGE"; }
get_image() { grep "^$(env_var "$1")=" "$IMAGES_ENV" 2>/dev/null | cut -d= -f2- || true; }
set_image() {
  local var; var="$(env_var "$1")"
  grep -v "^${var}=" "$IMAGES_ENV" > "$IMAGES_ENV.tmp" || true
  echo "${var}=$2" >> "$IMAGES_ENV.tmp"
  mv "$IMAGES_ENV.tmp" "$IMAGES_ENV"
}

wait_healthy() {
  local svc="$1" cid status deadline=$((SECONDS + TREBUCHET_HEALTH_TIMEOUT))
  while [ $SECONDS -lt $deadline ]; do
    cid="$(compose ps -q "$svc")"
    if [ -n "$cid" ]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")"
      case "$status" in
        healthy|running) return 0 ;;
      esac
    fi
    sleep 2
  done
  return 1
}

config_changed=0
if [ -n "$prev_commit" ] && ! git -C "$TREBUCHET_CHECKOUT" diff --quiet "$prev_commit" "$target" -- deploy/; then
  config_changed=1
fi

failed=0
for svc in $TREBUCHET_SERVICES; do
  old="$(get_image "$svc")"
  new="${new_digest[$svc]}"
  # caddy also restarts when its config changed (admin API is off: no live reload)
  if [ "$old" = "$new" ] && ! { [ "$svc" = "caddy" ] && [ $config_changed = 1 ]; }; then
    continue
  fi
  log "deploying $svc: ${old:-none} -> $new"
  set_image "$svc" "$new"
  compose pull --quiet "$svc"
  compose up -d --no-build --no-deps "$svc"
  if wait_healthy "$svc"; then
    log "$svc is healthy"
  else
    log "$svc did NOT become healthy, rolling back"
    failed=1
    if [ -n "$old" ]; then
      set_image "$svc" "$old"
      compose up -d --no-build --no-deps "$svc" || true
    fi
  fi
done

if [ $failed = 1 ]; then
  [ -n "$prev_commit" ] && git -C "$TREBUCHET_CHECKOUT" checkout --quiet --detach "$prev_commit"
  die "deployment of $target failed; previous version restored where possible"
fi

echo "$target" > "$TREBUCHET_STATE_DIR/commit"
log "deployed $target"
