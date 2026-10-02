<?php
/**
 * PHP Guard — lightweight injection protection for any PHP site.
 *
 * Install (runs before every script, no code changes needed):
 *   php.ini / .user.ini:   auto_prepend_file = "/path/to/php-guard.php"
 *   Apache .htaccess:       php_value auto_prepend_file "/path/to/php-guard.php"
 *   Or at the top of a front controller: require __DIR__ . '/php-guard.php';
 *
 * What it does
 *   - Removes the X-Powered-By header so your PHP version is not advertised.
 *   - Sends baseline security headers.
 *   - Inspects query string, POST body, cookies, path and a few headers for
 *     SQL injection, XSS, path traversal / file inclusion, command injection,
 *     PHP stream wrappers, null bytes and the CVE-2024-4577 PHP-CGI soft-hyphen
 *     trick. Matching requests get HTTP 403 (or are only logged in 'log' mode).
 *
 * This is defence in depth, NOT a replacement for prepared statements,
 * output escaping, or keeping PHP itself patched.
 */

if (defined('PHP_GUARD_LOADED')) {
    return;
}
define('PHP_GUARD_LOADED', true);

$PHP_GUARD_CONFIG = array_replace([
    // 'block' returns 403; 'log' only records matches (use this first to check for false positives).
    'mode'          => 'block',
    // Log file; null uses PHP's error_log.
    'log_file'      => null,
    // Request paths (prefix match) that skip inspection, e.g. an admin editor that posts raw HTML.
    'skip_paths'    => [],
    // Parameter names that skip inspection anywhere (e.g. 'content' for a rich-text field).
    'skip_keys'     => [],
    // Categories to enable.
    'rules'         => ['sqli', 'xss', 'traversal', 'rce', 'wrapper', 'nullbyte', 'cgi'],
    'send_headers'  => true,
    // Values longer than this are only checked in their first N bytes (performance cap).
    'max_scan_len'  => 65536,
], isset($PHP_GUARD_CONFIG) && is_array($PHP_GUARD_CONFIG) ? $PHP_GUARD_CONFIG : []);

function php_guard_rules(): array
{
    return [
        'sqli' => [
            '/\bunion\b[\s\/\*\(]+(all\s+)?select\b/i',
            '/\bselect\b[\s\S]{1,200}?\bfrom\b[\s\S]{1,200}?\b(information_schema|mysql\.user|pg_catalog|sqlite_master)\b/i',
            '/[\'"`]\s*(or|and|\|\||&&)\s*[\'"`]?\w+[\'"`]?\s*(=|like|<|>)\s*[\'"`]?\w+/i',
            '/[\'"`]\s*(or|and)\s+\d+\s*=\s*\d+/i',
            '/\b(sleep|benchmark|pg_sleep)\s*\(\s*\d/i',
            '/\bwaitfor\s+delay\s+[\'"]/i',
            '/;\s*(drop|truncate|alter|create|delete|insert|update)\s+(table|database|from|into|\w+\s+set)\b/i',
            '/\b(load_file|into\s+(out|dump)file)\b/i',
            '/\/\*!\d*\s*\w/',
        ],
        'xss' => [
            '/<\s*script\b/i',
            '/<\s*\/\s*script\s*>/i',
            '/\bjavascript\s*:/i',
            '/\bvbscript\s*:/i',
            '/<[^>]*\son[a-z]{3,20}\s*=/i',
            '/<\s*(iframe|object|embed|svg|math|base|meta|form)\b[^>]*>/i',
            '/\bsrcdoc\s*=/i',
            '/expression\s*\(/i',
        ],
        'traversal' => [
            '/(\.\.[\/\\\\]){2,}/',
            '/\.\.[\/\\\\].*(etc\/passwd|etc\/shadow|proc\/self|win\.ini|boot\.ini|\.env\b|wp-config)/i',
            '/\/(etc\/(passwd|shadow|hosts)|proc\/self\/(environ|cmdline|fd))/i',
        ],
        'rce' => [
            '/(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|php|powershell|cmd)\b/i',
            '/\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|eval|create_function)\s*\(/i',
            '/\b(base64_decode|gzinflate|str_rot13)\s*\(/i',
            '/<\?(php|=)/i',
            '/\$\{\s*(jndi|env|sys):/i',
        ],
        'wrapper' => [
            '/\b(php|phar|zip|data|expect|glob|zlib|compress\.zlib|compress\.bzip2|file|ogg|rar|ssh2)\s*:\/\//i',
            '/\bdata\s*:\s*[a-z]+\/[a-z0-9.+-]+\s*;\s*base64/i',
        ],
        'nullbyte' => [
            '/\x00/',
        ],
    ];
}

function php_guard_log(array $cfg, string $category, string $where, string $sample): void
{
    $line = sprintf(
        "[php-guard] %s %s %s ip=%s uri=%s where=%s sample=%s\n",
        date('c'),
        strtoupper($cfg['mode']),
        $category,
        $_SERVER['REMOTE_ADDR'] ?? '-',
        substr($_SERVER['REQUEST_URI'] ?? '-', 0, 300),
        $where,
        json_encode(substr($sample, 0, 200))
    );
    if ($cfg['log_file']) {
        @file_put_contents($cfg['log_file'], $line, FILE_APPEND | LOCK_EX);
    } else {
        error_log(rtrim($line));
    }
}

function php_guard_block(array $cfg, string $category, string $where, string $sample): void
{
    php_guard_log($cfg, $category, $where, $sample);
    if ($cfg['mode'] !== 'block') {
        return;
    }
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, "php-guard: blocked ($category in $where)\n");
        exit(1);
    }
    if (!headers_sent()) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo "403 Forbidden — request blocked by php-guard.\n";
    exit;
}

/** Returns [category, sample] for the first rule that matches, or null. */
function php_guard_match(string $value, array $cfg): ?array
{
    if ($value === '') {
        return null;
    }
    $value = substr($value, 0, $cfg['max_scan_len']);
    // Check both the raw value and a decoded form so double-encoding does not slip past.
    $candidates = [$value];
    $decoded = rawurldecode($value);
    if ($decoded !== $value) {
        $candidates[] = $decoded;
    }
    $entity = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if ($entity !== $decoded) {
        $candidates[] = $entity;
    }
    $rules = php_guard_rules();
    foreach ($cfg['rules'] as $category) {
        if (!isset($rules[$category])) {
            continue;
        }
        foreach ($rules[$category] as $pattern) {
            foreach ($candidates as $c) {
                if (preg_match($pattern, $c)) {
                    return [$category, $c];
                }
            }
        }
    }
    return null;
}

function php_guard_scan($data, string $where, array $cfg): void
{
    if (!is_array($data)) {
        if (is_string($data) && ($hit = php_guard_match($data, $cfg))) {
            php_guard_block($cfg, $hit[0], $where, $hit[1]);
        }
        return;
    }
    foreach ($data as $key => $value) {
        if (in_array((string) $key, $cfg['skip_keys'], true)) {
            continue;
        }
        $path = $where . '[' . $key . ']';
        if ($hit = php_guard_match((string) $key, $cfg)) {
            php_guard_block($cfg, $hit[0], $path . '(key)', $hit[1]);
        }
        php_guard_scan($value, $path, $cfg);
    }
}

function php_guard_run(array $cfg): void
{
    if (PHP_SAPI !== 'cli' && !headers_sent()) {
        header_remove('X-Powered-By');
        if ($cfg['send_headers']) {
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: SAMEORIGIN');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
            if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
                header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
            }
        }
    }
    @ini_set('expose_php', '0');

    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    foreach ($cfg['skip_paths'] as $prefix) {
        if ($prefix !== '' && strpos($path, $prefix) === 0) {
            return;
        }
    }

    // CVE-2024-4577 / CVE-2012-1823: PHP-CGI argument injection via a query
    // string that starts with "-" (or a soft hyphen, 0xAD, on Windows).
    if (in_array('cgi', $cfg['rules'], true)) {
        $qs = $_SERVER['QUERY_STRING'] ?? '';
        if (($qs !== '' && preg_match('/^(-|%2d|%ad|\xad)/i', $qs) && strpos($qs, '=') === false)
            || preg_match('/(^|&)(-|%2d|%ad|\xad)[dsn](\+|%20|\s|$)/i', $qs)) {
            php_guard_block($cfg, 'cgi', 'QUERY_STRING', $qs);
        }
    }

    php_guard_scan(rawurldecode($path), 'PATH', $cfg);
    php_guard_scan($_GET, 'GET', $cfg);
    php_guard_scan($_POST, 'POST', $cfg);
    php_guard_scan($_COOKIE, 'COOKIE', $cfg);
    foreach (['HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR'] as $h) {
        if (isset($_SERVER[$h])) {
            php_guard_scan($_SERVER[$h], $h, $cfg);
        }
    }
    // Raw bodies (JSON APIs) are not in $_POST.
    $type = $_SERVER['CONTENT_TYPE'] ?? '';
    if (stripos($type, 'application/json') !== false) {
        $json = json_decode((string) file_get_contents('php://input'), true);
        if (is_array($json)) {
            php_guard_scan($json, 'JSON', $cfg);
        }
    }
    foreach ($_FILES as $field => $file) {
        foreach ((array) ($file['name'] ?? []) as $name) {
            if (is_string($name) && preg_match('/\.(php\d?|phtml|phar|pht|shtml|htaccess|user\.ini)(\.|$)/i', $name)) {
                php_guard_block($cfg, 'upload', "FILES[$field]", $name);
            }
        }
    }
}

/** Escape a value for HTML output: <?= e($name) ?> */
if (!function_exists('e')) {
    function e($value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}

if (PHP_SAPI !== 'cli' || getenv('PHP_GUARD_TEST')) {
    php_guard_run($PHP_GUARD_CONFIG);
}
