#!/usr/bin/env bash
# Security and quality checks. Run before every commit; CI runs it too.
# Tools are pinned to exact versions (at least 7 days old when pinned); bump them
# deliberately, never to @latest. In CI the tools are pre-installed by the workflow
# with the same versions; locally `go run pkg@version` is used.
#
# Env:
#   REQUIRE_RACE=1   fail if the race detector cannot run (CI sets this)
#   FUZZ_TIME=20s    duration of each fuzz target
set -euo pipefail

STATICCHECK_VERSION=v0.8.2
GOVULNCHECK_VERSION=v1.9.0
GOSEC_VERSION=v2.30.0
OSV_SCANNER_VERSION=v2.7.0
GITLEAKS_VERSION=v8.30.1
FUZZ_TIME="${FUZZ_TIME:-20s}"

root="$(cd "$(dirname "$0")/.." && pwd)"

# tool <binary> <module/cmd@version> [args...]: prefer an installed binary, else go run.
tool() {
  local bin="$1" pkg="$2"
  shift 2
  if command -v "$bin" >/dev/null 2>&1; then
    "$bin" "$@"
  else
    go run "$pkg" "$@"
  fi
}

skipped=()

for svc in "$root"/services/*/; do
  name="$(basename "$svc")"
  echo "######## service: $name"
  cd "$svc"

  echo "== gofmt";         test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
  echo "== go vet";        go vet ./...
  echo "== go mod verify"; go mod verify
  echo "== staticcheck";   tool staticcheck "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" ./...

  echo "== tests"
  if [ "$(go env CGO_ENABLED)" = "1" ] && command -v "$(go env CC)" >/dev/null 2>&1; then
    go test -count=1 -race ./...
  else
    if [ "${REQUIRE_RACE:-0}" = "1" ]; then
      echo "race detector required but cgo/C compiler is unavailable" >&2
      exit 1
    fi
    skipped+=("race detector ($name): no C compiler, ran tests without -race")
    go test -count=1 ./...
  fi

  echo "== govulncheck";   tool govulncheck "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
  echo "== gosec";         tool gosec "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}" -quiet ./...

  echo "== fuzz (${FUZZ_TIME} each)"
  # Every Fuzz* target in every package is fuzzed.
  while read -r pkg; do
    for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
      echo "   $pkg $target"
      go test -run='^$' -fuzz="^${target}\$" -fuzztime="$FUZZ_TIME" "$pkg"
    done
  done < <(go list ./...)
done

echo "######## caddy (built from source, deploy/caddy/src)"
cd "$root/deploy/caddy/src"
echo "== gofmt";         test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
echo "== go mod verify"; go mod verify
echo "== govulncheck";   tool govulncheck "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...

cd "$root"
echo "######## repository"
echo "== osv-scanner";     tool osv-scanner "github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}" scan source -r .
echo "== gitleaks";        tool gitleaks "github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}" git --no-banner --redact .

if [ ${#skipped[@]} -gt 0 ]; then
  echo
  echo "SKIPPED (not verified):"
  printf '  - %s\n' "${skipped[@]}"
fi
echo "All checks passed."
