<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// For local development
session_set_cookie_params([
    'lifetime' => 3600, // 1 hour
    'path' => '/',
    'domain' => '', // Leave empty for localhost
    'secure' => false, // Set to false for local HTTP
    'httponly' => true,
    'samesite' => 'Lax'
]);
        // IMPORTANT: Make sure path is /
// ini_set('session.cookie_domain', 'ace.auth'); // IMPORTANT: Set explicit domain
ini_set('session.save_path', sys_get_temp_dir()); // Ensure writable path

// IMPORTANT: Start session before creating Auth object
// session_start();

try {
    // --- Database connection (MySQL/MariaDB) ---
    $db = new PDO(
        'mysql:dbname=auth_demo;host=127.0.0.1;charset=utf8mb4',
        'auth_user',
        'formpassword',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );

    // --- SQLite alternative ---
    // $db = new PDO('sqlite:' . __DIR__ . '/../auth_demo.sqlite');
    // $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Instantiate PHP-Auth with the PDO connection
    $auth = new \Delight\Auth\Auth($db);
}
catch (Throwable $e) {
    http_response_code(500);
    echo 'Bootstrap error: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    exit;
}