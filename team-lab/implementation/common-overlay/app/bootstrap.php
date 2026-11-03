<?php
declare(strict_types=1);
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/auth/session.php';
require_once __DIR__ . '/auth/mfa.php';

date_default_timezone_set('Asia/Seoul');
define('APP_ROOT', dirname(__DIR__));
define('APP_VERSION', '0.2.0');
$mode = getenv('AIRPORT_LAB_MODE') ?: 'baseline';
if (!in_array($mode, ['baseline', 'legacy-authz'], true)) {
    throw new RuntimeException('Unsupported AIRPORT_LAB_MODE');
}
define('LAB_MODE', $mode);
define('REQUEST_ID', bin2hex(random_bytes(12)));
if (PHP_SAPI !== 'cli') {
    header('X-Request-ID: ' . REQUEST_ID);
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    header('Cache-Control: no-store');
}

function e(mixed $value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function query(string $sql, array $args = []): PDOStatement { $s = db()->prepare($sql); $s->execute($args); return $s; }
function audit(string $event, string $outcome, array $context = []): void {
    $allowed = ['object_type', 'object_id', 'owner_company_id', 'department_id', 'reason', 'authz_decision', 'bytes', 'from_status', 'to_status', 'username', 'http_status'];
    $u = $GLOBALS['app_user'] ?? null;
    $row = array_merge([
        'timestamp' => (new DateTimeImmutable())->format(DateTimeInterface::RFC3339_EXTENDED),
        'request_id' => REQUEST_ID, 'service_id' => service_id(),
        'event' => $event, 'outcome' => $outcome, 'actor_id' => $u['id'] ?? ($_SESSION['user_id'] ?? null),
        'actor_role' => $u['role'] ?? null, 'actor_company_id' => $u['company_id'] ?? null,
        'source_ip' => $_SERVER['REMOTE_ADDR'] ?? 'cli', 'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
        'path' => $_SERVER['SCRIPT_NAME'] ?? 'cli', 'policy_version' => LAB_MODE, 'app_version' => APP_VERSION,
    ], array_intersect_key($context, array_flip($allowed)));
    $dir = APP_ROOT . '/storage/logs';
    if (!is_dir($dir)) { mkdir($dir, 0770, true); }
    file_put_contents($dir . '/audit.jsonl', json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n", FILE_APPEND | LOCK_EX);
}
function user(): ?array {
    if (array_key_exists('app_user', $GLOBALS)) { return $GLOBALS['app_user']; }
    $id = current_user_id();
    $u = $id ? query('SELECT u.*, d.name department_name, c.name company_name, c.contract_status FROM users u LEFT JOIN departments d ON d.id=u.department_id LEFT JOIN companies c ON c.id=u.company_id WHERE u.id=?', [$id])->fetch() : false;
    if ($u && (!is_string($_SESSION['credential_stamp'] ?? null) || !hash_equals(hash('sha256', $u['password_hash']), $_SESSION['credential_stamp']))) {
        $_SESSION = []; session_regenerate_id(true); $u = false;
    }
    if ($u && ($u['account_status'] === 'DISABLED' || ($u['role'] === 'CONTRACTOR' && $u['contract_status'] !== 'ACTIVE'))) {
        $_SESSION = []; $u = false;
    }
    if ($u && mfa_enabled() && !mfa_session_verified($_SESSION,$u,time())) {
        unset($_SESSION['user_id'],$_SESSION['credential_stamp'],$_SESSION['mfa_verified']); $u=false;
    }
    $GLOBALS['app_user'] = $u ?: null;
    return $GLOBALS['app_user'];
}
/** Only local application pages can be used as a post-login destination. */
function safe_login_return(mixed $value): ?string {
    if (!is_string($value) || strlen($value)>2048 || preg_match('/[\x00-\x20\x7f\\\\]/', $value)) { return null; }
    $parts = parse_url($value);
    if ($parts===false || isset($parts['scheme']) || isset($parts['host']) || isset($parts['fragment'])) { return null; }
    $path = $parts['path'] ?? '';
    if (!preg_match('~^/(?:account|customer|portal|reservations)/[A-Za-z0-9_./-]*$~D', $path) || str_contains($path,'..') || str_contains($path,'//')) { return null; }
    return $value;
}
function login_required(): array {
    $u = user();
    if (!$u) {
        if (mfa_enabled() && isset($_SESSION['mfa_pending'])) {
                audit('mfa_access','denied',['object_type'=>'user','object_id'=>(int)$_SESSION['mfa_pending']['user_id'],'reason'=>'mfa_required','http_status'=>302]);
            if (($_SERVER['REQUEST_METHOD']??'')==='GET' && ($next=safe_login_return($_SERVER['REQUEST_URI']??null))) { $_SESSION['login_return_to']=$next; }
            header('Location: /mfa.php',true,302); exit;
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && ($next=safe_login_return($_SERVER['REQUEST_URI'] ?? null))) {
            start_app_session(); $_SESSION['login_return_to']=$next;
        }
        header('Location: /login.php', true, 302); exit;
    }
    return $u;
}
function service_id(): string {
    $path = $_SERVER['SCRIPT_NAME'] ?? '';
    if (str_starts_with($path, '/legacy/')) { return 'legacy-archive'; }
    if (str_starts_with($path, '/reservations/') || $path==='/account/reservations.php') { return 'reservation-service'; }
    if (str_starts_with($path, '/customer/') || str_starts_with($path, '/account/')) { return 'customer-center'; }
    if (str_starts_with($path, '/portal/') || $path === '/download.php') { return 'partner-portal'; }
    return 'public-web';
}
function home_for(array $u): string { return $u['role'] === 'VISITOR' ? '/account/' : '/portal/'; }
function workforce_required(): array {
    $u=login_required();
    if(!in_array($u['role'],['STAFF','CONTRACTOR'],true)) {
        audit('workforce_access','denied',['reason'=>'role','http_status'=>403]);
        abort_page(403,'업무 계정이 필요합니다','일반 이용자 계정은 고객참여 메뉴를 이용해 주세요.');
    }
    return $u;
}
function csrf_token(): string { start_app_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
function check_csrf(): void {
    if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) {
        audit('csrf_rejected', 'denied', ['http_status'=>403]); abort_page(403, '요청을 확인할 수 없습니다', '페이지를 새로 열고 다시 시도해 주세요.');
    }
}
function redirect_to(string $path, string $message = ''): never {
    start_app_session(); if ($message !== '') { $_SESSION['flash'] = $message; }
    header('Location: ' . $path, true, 303); exit;
}
function abort_page(int $code, string $title, string $message): never {
    http_response_code($code); require_once __DIR__ . '/views/layout.php';
    $path = $_SERVER['SCRIPT_NAME'] ?? '';
    $target = str_starts_with($path, '/reservations/') ? ['/reservations/','통합예약으로 이동'] :
        (str_starts_with($path, '/customer/') || str_starts_with($path, '/account/') ? ['/customer/','고객참여로 이동'] :
        (str_starts_with($path, '/portal/') || str_starts_with($path, '/legacy/') ? ['/portal/','업무지원으로 이동'] : ['/','홈으로 이동']));
    page_header($title); echo '<main class="container error-page"><span class="eyebrow">' . $code . '</span><h1>' . e($title) . '</h1><p>' . e($message) . '</p><a class="button" href="' . e($target[0]) . '">' . e($target[1]) . '</a>';
    if ($target[0] !== '/') { echo ' <a class="button button-outline" href="/">홈으로 이동</a>'; }
    echo '</main>'; page_footer(); exit;
}
function job(int $id): array|false {
    return query('SELECT j.*, f.name facility_name, f.department_id, d.name department_name, (SELECT c.name FROM job_assignments a JOIN companies c ON c.id=a.company_id WHERE a.job_id=j.id AND a.is_active=1 ORDER BY a.id DESC LIMIT 1) company_name FROM jobs j JOIN facilities f ON f.id=j.facility_id JOIN departments d ON d.id=f.department_id WHERE j.id=?', [$id])->fetch();
}
function can_view_job(array $u, array $j): bool {
    if ($u['role'] === 'STAFF') { return (int)$u['department_id'] === (int)$j['department_id']; }
    if ($u['role'] !== 'CONTRACTOR') { return false; }
    return (bool)query('SELECT 1 FROM job_assignments WHERE job_id=? AND company_id=? AND is_active=1', [$j['id'], $u['company_id']])->fetchColumn();
}
function enforce_job(array $u, array $j, string $event = 'job_access'): void {
    if (!can_view_job($u, $j)) { audit($event, 'denied', ['object_type'=>'job','object_id'=>(int)$j['id'],'reason'=>'outside_scope','http_status'=>403]); abort_page(403, '접근 권한이 없습니다', '소속 부서 또는 배정된 업체의 업무만 확인할 수 있습니다.'); }
}
function can_approve(array $u, array $j): bool {
    return $u['role'] === 'STAFF' && (int)$u['department_id'] === (int)$j['department_id']
        && (bool)query("SELECT 1 FROM granted_permissions WHERE user_id=? AND department_id=? AND permission_code='JOB_APPROVE' AND is_active=1", [$u['id'],$j['department_id']])->fetchColumn();
}
function scoped_jobs(array $u, string $status = '', string $search = ''): array {
    $sql = 'SELECT j.*, f.name facility_name, d.name department_name FROM jobs j JOIN facilities f ON f.id=j.facility_id JOIN departments d ON d.id=f.department_id WHERE ';
    $args=[];
    if ($u['role']==='STAFF') { $sql.='f.department_id=?'; $args[]=$u['department_id']; }
    else { $sql.='EXISTS (SELECT 1 FROM job_assignments a WHERE a.job_id=j.id AND a.company_id=? AND a.is_active=1)'; $args[]=$u['company_id']; }
    if ($status !== '') { $sql.=' AND j.status=?'; $args[]=$status; }
    if ($search !== '') { $sql.=' AND (j.title LIKE ? OR f.name LIKE ?)'; $args[]='%'.$search.'%'; $args[]='%'.$search.'%'; }
    return query($sql.' ORDER BY j.updated_at DESC,j.id DESC', $args)->fetchAll();
}
function status_label(string $s): string { return ['REGISTERED'=>'접수','ASSIGNED'=>'배정 완료','SUBMITTED'=>'검토 대기','APPROVED'=>'승인 완료','REJECTED'=>'보완 요청'][$s] ?? $s; }
function handover_label(string $s): string { return ['NOT_REQUIRED'=>'해당 없음','IN_PROGRESS'=>'인수인계 진행','PENDING_ARCHIVE'=>'구형 자료 이관 대기','COMPLETED'=>'인수인계 완료'][$s] ?? $s; }
function job_update_label(string $type): string { return ['ASSIGNMENT'=>'업무 배정','REPORT'=>'보고서 제출','REVIEW'=>'검토 결과','HANDOVER'=>'인수인계','ARCHIVE'=>'자료 이관','NOTE'=>'업무 메모'][$type] ?? $type; }
function badge(string $s): string { return '<span class="badge badge-'.strtolower($s).'">'.e(status_label($s)).'</span>'; }
function limited_text(mixed $v, int $length): string { $v = trim((string)$v); if (mb_strlen($v)>$length) { abort_page(422,'입력 내용을 확인해 주세요','허용된 글자 수를 초과했습니다.'); } return $v; }
set_exception_handler(function (Throwable $ex): void {
    error_log((string)$ex);
    if (PHP_SAPI === 'cli') { fwrite(STDERR, "처리 실패. 실행 환경과 로그를 확인하세요.\n"); exit(1); }
    abort_page(500,'일시적으로 서비스를 이용할 수 없습니다','잠시 후 다시 이용해 주세요. 문의 시 요청번호 '.REQUEST_ID.'를 알려 주세요.');
});
