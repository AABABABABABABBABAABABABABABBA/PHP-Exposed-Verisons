# PHP Exposed Versions

I was bored and I had an idea to make a PHP exposure checker, so this entire project is vibe coded.

**Live site:** https://aababababababbabaabababababba.github.io/PHP-Exposed-Verisons/

## What's in it

- **Exposed versions list** — every PHP branch from 4.4 to 8.5, whether it's end-of-life, security-only or actively supported, and exactly which releases are exposed.
- **"Is my website exposed?" search** — type a PHP version, paste your `X-Powered-By` header, or enter your domain to get a verdict plus the CVEs that apply. You can also link straight to a result: `…/?q=7.4.33`.
- **Notable CVEs** — recent and mass-exploited PHP vulnerabilities (CVE-2024-4577, CVE-2019-11043, …) with the first fixed release per branch.
- **Tools** (in [`docs/tools/`](docs/tools)):
  - [`php-guard.php`](docs/tools/php-guard.php) — injection protection via `auto_prepend_file`. Blocks SQL injection, XSS, path traversal, remote file inclusion, command injection, PHP-CGI argument injection and PHP file uploads; hides `X-Powered-By`; sends security headers. Has a `log` mode for checking false positives first.
  - [`php-auto-update.sh`](docs/tools/php-auto-update.sh) — cron-friendly auto updater. Installs patch releases for your current PHP branch (apt/dnf/yum/apk/brew), restarts PHP-FPM/Apache, warns if the branch is end-of-life. Supports `--dry-run`.
  - [`php-version-check.php`](docs/tools/php-version-check.php) — self-check that reports your version, applicable CVEs and risky `php.ini` settings, with exit codes for cron/CI.

## Quick start

```ini
; php.ini or .user.ini
auto_prepend_file = "/var/www/php-guard.php"
```

```bash
sudo install -m 755 php-auto-update.sh /usr/local/sbin/
sudo php-auto-update.sh --dry-run
# daily:
echo '17 3 * * * root /usr/local/sbin/php-auto-update.sh >> /var/log/php-auto-update.log 2>&1' | sudo tee /etc/cron.d/php-auto-update
```

## How the data stays current

[`docs/data/versions.json`](docs/data/versions.json) holds the branch support dates and the CVE list. The GitHub Action in [`.github/workflows/pages.yml`](.github/workflows/pages.yml) runs daily, pulls the newest release of every branch from the php.net releases API ([`scripts/update-versions.mjs`](scripts/update-versions.mjs)), commits any changes, and redeploys the site. Branch status (active / security / end-of-life) is computed from today's date in the browser, so branches flip to end-of-life on schedule.

## Hosting on GitHub Pages

1. Repo **Settings → Pages → Build and deployment → Source: GitHub Actions**.
2. Push to the default branch (or run the workflow manually from the **Actions** tab).

## Caveats

- Browsers can't read another site's response headers, so for a domain the checker gives you a one-line `curl` command (and a link to view headers online) and evaluates whatever you paste back.
- PHP Guard is an extra layer, not a replacement for prepared statements, output escaping and keeping PHP patched.
- Linux distros (Debian, RHEL, Ubuntu LTS) backport security fixes without bumping the version number, so an "old" version from your distro may be patched. The auto updater's job is to keep you on the newest package your distro offers.
