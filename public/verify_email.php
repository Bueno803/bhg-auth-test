<?php
// public/verify_email.php
require __DIR__ . '/../src/bootstrap.php';

$selector = $_GET['selector'] ?? '';
$token    = $_GET['token'] ?? '';

try {
    $auth->confirmEmail($selector, $token);
    echo 'Email verified. You may now log in. <a href="/login.php">Login</a>';
}
catch (\Delight\Auth\InvalidSelectorTokenPairException $e) { echo 'Invalid token'; }
catch (\Delight\Auth\TokenExpiredException $e) { echo 'Token expired'; }
catch (\Delight\Auth\UserAlreadyExistsException $e) { echo 'Already confirmed'; }
catch (\Delight\Auth\TooManyRequestsException $e) { echo 'Too many requests'; }