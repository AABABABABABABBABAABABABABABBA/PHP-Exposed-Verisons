<?php
/**
 * PHP Exposure Self-Check — tells you whether the PHP running this file is
 * end-of-life or missing security patches, and flags risky php.ini settings.
 *
 *   CLI:  php php-version-check.php          (exit 0 = ok, 1 = outdated/warnings, 2 = end-of-life)
 *   Web:  upload it, set CHECK_TOKEN below, open /php-version-check.php?token=YOUR_TOKEN
 *         then DELETE it — it reveals your exact PHP version.
 */

const CHECK_TOKEN = '';   // required for web access; leave empty to allow CLI only
const DATA_URL    = 'https://aababababababbabaabababababba.github.io/PHP-Exposed-Verisons/data/versions.json';

$cli = PHP_SAPI === 'cli';
if (!$cli) {
    $given = (string) ($_GET['token'] ?? '');
    if (CHECK_TOKEN === '' || !hash_equals(CHECK_TOKEN, $given)) {
        http_response_code(404);
        exit;
    }
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex');
}

function fetch_json(string $url): ?array
{
    $ctx = stream_context_create(['http' => ['timeout' => 10, 'user_agent' => 'php-version-check']]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false && function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true]);
        $raw = curl_exec($ch);
        curl_close($ch);
    }
    $data = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($data) ? $data : null;
}

$version = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION;
$branch  = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$today   = date('Y-m-d');
$status  = 0;
$out     = [];

$out[] = "PHP version:  $version (" . PHP_SAPI . ', ' . PHP_OS_FAMILY . ')';

$data = fetch_json(DATA_URL);
if (!$data) {
    $out[] = '[?] Could not download version data from ' . DATA_URL;
    $status = max($status, 1);
} else {
    $info = null;
    foreach ($data['branches'] as $b) {
        if ($b['branch'] === $branch) {
            $info = $b;
        }
    }
    if (!$info) {
        $out[] = "[?] Branch $branch is not in the version list (pre-release or unknown).";
        $status = max($status, 1);
    } else {
        if ($info['securityUntil'] && $info['securityUntil'] < $today) {
            $out[] = "[!!] EXPOSED: PHP $branch reached end-of-life on {$info['securityUntil']} and gets no security fixes.";
            $status = 2;
        } elseif (version_compare($version, $info['latest'], '<')) {
            $out[] = "[!] OUTDATED: latest $branch release is {$info['latest']} — you are missing security fixes.";
            $status = max($status, 1);
        } else {
            $out[] = "[ok] Up to date with the $branch branch (latest {$info['latest']}).";
        }
        if ($info['securityUntil']) {
            $out[] = "     Security support for $branch ends {$info['securityUntil']}.";
        }
        foreach ($data['cves'] ?? [] as $cve) {
            $fixed = $cve['fixed'][$branch] ?? null;
            $eolMissed = !$fixed && $info['securityUntil'] && $info['securityUntil'] < $cve['date'];
            if (($fixed && version_compare($version, $fixed, '<')) || $eolMissed) {
                $out[] = sprintf('     - %s (%s): %s%s', $cve['id'], $cve['severity'], $cve['title'],
                    $fixed ? " — fixed in $fixed" : ' — never fixed for this branch');
            }
        }
    }
}

$out[] = '';
$out[] = 'php.ini hardening:';
$checks = [
    ['expose_php',         ini_get('expose_php'),         fn($v) => !$v,              'Off — hides the PHP version from X-Powered-By'],
    ['display_errors',     ini_get('display_errors'),     fn($v) => $cli || !$v || strtolower($v) === 'off' || $v === 'stderr', 'Off in production'],
    ['allow_url_include',  ini_get('allow_url_include'),  fn($v) => !$v,              'Off — prevents remote file inclusion'],
    ['session.cookie_httponly', ini_get('session.cookie_httponly'), fn($v) => (bool) $v, 'On'],
    ['session.use_strict_mode', ini_get('session.use_strict_mode'), fn($v) => (bool) $v, 'On'],
    ['disable_functions',  ini_get('disable_functions'),  fn($v) => trim((string) $v) !== '', 'e.g. exec,passthru,shell_exec,system,proc_open,popen'],
    ['open_basedir',       ini_get('open_basedir'),       fn($v) => trim((string) $v) !== '', 'limit PHP to your site directory'],
    ['auto_prepend_file',  ini_get('auto_prepend_file'),  fn($v) => trim((string) $v) !== '', 'set to php-guard.php for injection protection'],
];
if (stripos(PHP_SAPI, 'cgi') !== false) {
    $checks[] = ['cgi.force_redirect', ini_get('cgi.force_redirect'), fn($v) => (bool) $v, 'On'];
}
foreach ($checks as [$name, $value, $ok, $advice]) {
    $good = $ok($value);
    $shown = $value === false ? '(unset)' : ($value === '' ? '(empty)' : $value);
    $out[] = sprintf('  [%s] %-24s = %-12s %s', $good ? 'ok' : '!', $name, $shown, $good ? '' : "→ $advice");
    if (!$good) {
        $status = max($status, 1);
    }
}

echo implode(PHP_EOL, $out), PHP_EOL;
if ($cli) {
    exit($status);
}
