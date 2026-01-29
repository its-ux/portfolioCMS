<?php
// Security helpers for escaping, URL validation, tokens and secure sessions

if (!function_exists('esc')) {
    function esc($s) {
        return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('validate_url')) {
    function validate_url($u) {
        $u = trim($u);
        return $u && filter_var($u, FILTER_VALIDATE_URL) ? $u : '';
    }
}

if (!function_exists('secure_session_start')) {
    function secure_session_start() {
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $cookieParams = session_get_cookie_params();
        session_set_cookie_params([
            'lifetime' => $cookieParams['lifetime'],
            'path' => $cookieParams['path'],
            'domain' => $cookieParams['domain'],
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }
}

if (!function_exists('safe_token')) {
    function safe_token($length = 32) {
        try {
            return bin2hex(random_bytes((int)ceil($length / 2)));
        } catch (Exception $e) {
            // fallback
            return bin2hex(openssl_random_pseudo_bytes((int)ceil($length / 2)));
        }
    }
}
?>