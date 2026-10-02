#!/usr/bin/env bash
# PHP Auto-Updater — installs security patch releases for the PHP branch you
# already run (e.g. 8.3.x -> latest 8.3.x) using your OS package manager,
# restarts PHP-FPM / Apache, and warns when the branch is end-of-life.
#
# It never jumps to a new minor branch (8.3 -> 8.4) on its own: that can break
# applications and should be done deliberately.
#
# Usage:   sudo ./php-auto-update.sh [--dry-run]
# Cron:    17 3 * * * root /usr/local/sbin/php-auto-update.sh >> /var/log/php-auto-update.log 2>&1

set -euo pipefail

DATA_URL="${PHP_VERSIONS_URL:-https://aababababababbabaabababababba.github.io/PHP-Exposed-Verisons/data/versions.json}"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
run() { if (( DRY_RUN )); then log "dry-run: $*"; else log "+ $*"; "$@"; fi; }

if (( ! DRY_RUN )) && [[ $EUID -ne 0 ]]; then
  echo "Run as root (or with --dry-run)." >&2
  exit 1
fi

command -v php >/dev/null || { log "php not found in PATH"; exit 1; }
BEFORE=$(php -r 'echo PHP_VERSION;')
BRANCH=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
log "Installed PHP: $BEFORE (branch $BRANCH)"

# --- 1. apply patch updates for installed PHP packages only -----------------
if command -v apt-get >/dev/null; then
  PKGS=$(dpkg-query -W -f='${Package} ${Status}\n' 'php*' 2>/dev/null | awk '/install ok installed/ {print $1}' | tr '\n' ' ')
  run apt-get update -qq
  [[ -n "$PKGS" ]] && run env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade $PKGS
elif command -v dnf >/dev/null; then
  run dnf -y upgrade 'php*'
elif command -v yum >/dev/null; then
  run yum -y update 'php*'
elif command -v apk >/dev/null; then
  PKGS=$(apk info 2>/dev/null | grep -E '^php[0-9]*(-|$)' | tr '\n' ' ')
  run apk update
  [[ -n "$PKGS" ]] && run apk upgrade $PKGS
elif command -v brew >/dev/null; then
  FORMULA=$(brew list --formula | grep -E '^php(@[0-9.]+)?$' | head -1)
  [[ -n "$FORMULA" ]] && run brew upgrade "$FORMULA"
else
  log "No supported package manager (apt, dnf, yum, apk, brew) found."
  exit 1
fi

# --- 2. restart PHP services so the new binaries are used -------------------
if command -v systemctl >/dev/null; then
  for unit in $(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
                | awk '{print $1}' | grep -E '^(php[0-9.]*-fpm|php-fpm|apache2|httpd)\.service$' || true); do
    run systemctl restart "$unit"
  done
fi

AFTER=$(php -r 'echo PHP_VERSION;')
[[ "$AFTER" != "$BEFORE" ]] && log "Updated PHP $BEFORE -> $AFTER" || log "PHP unchanged at $AFTER"

# --- 3. compare against the published list ----------------------------------
if command -v curl >/dev/null && JSON=$(curl -fsS --max-time 15 "$DATA_URL"); then
  printf '%s' "$JSON" | php -r '
    $d = json_decode(stream_get_contents(STDIN), true);
    $v = PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION.".".PHP_RELEASE_VERSION;
    $br = PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;
    foreach ($d["branches"] ?? [] as $b) {
      if ($b["branch"] !== $br) continue;
      if ($b["securityUntil"] && $b["securityUntil"] < date("Y-m-d")) {
        echo "WARNING: PHP $br is END-OF-LIFE since {$b["securityUntil"]}. Upgrade to a supported branch.\n"; exit(2);
      }
      if (version_compare($v, $b["latest"], "<")) {
        echo "WARNING: $v is behind upstream {$b["latest"]}. Your OS repo may lag; consider a maintained repo (e.g. ppa:ondrej/php, Remi).\n"; exit(1);
      }
      echo "OK: $v is the latest $br release.\n"; exit(0);
    }
    echo "Branch $br not found in version list.\n";' | while read -r line; do log "$line"; done
else
  log "Could not fetch $DATA_URL to compare versions."
fi
