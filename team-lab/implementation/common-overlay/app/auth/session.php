<?php
declare(strict_types=1);

function start_app_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');

    session_name('AIRPORT_SESSION');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'httponly' => true,
        'secure' => !empty($_SERVER['HTTPS']) &&
                    $_SERVER['HTTPS'] !== 'off',
        'samesite' => 'Lax',
    ]);

    session_start();
}

function current_user_id(): ?int
{
    start_app_session();

    if (isset($_SESSION['mfa_pending'])) { return null; }

    return isset($_SESSION['user_id'])
        ? (int)$_SESSION['user_id']
        : null;
}

function require_login(): int
{
    $id = current_user_id();

    if ($id === null) {
        header('Location: /login.php', true, 302);
        exit;
    }

    return $id;
}