
<?php

require_once __DIR__ . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

header('Content-Type: application/json; charset=utf-8');

$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$requestMethod = $_SERVER['REQUEST_METHOD'];

if ($requestUri === '/login' && $requestMethod === 'POST') {
    require_once __DIR__ . '/routes/login.php';
    exit;
}

if ($requestUri === '/register' && $requestMethod === 'POST') {
    require_once __DIR__ . '/routes/register.php';
    exit;
}

if ($requestUri === '/me' && $requestMethod === 'GET') {
    require_once __DIR__ . '/routes/me.php';
    exit;
}

if ($requestUri === '/logout' && $requestMethod === 'POST') {
    require_once __DIR__ . '/routes/logout.php';
    exit;
}

if ($requestUri === '/forgot-password' && $requestMethod === 'POST') {
    require_once __DIR__ . '/routes/forgot-password.php';
    exit;
}

if ($requestUri === '/reset-password' && $requestMethod === 'POST') {
    require_once __DIR__ . '/routes/reset-password.php';
    exit;
}

http_response_code(404);

echo json_encode([
    'message' => 'Rota não encontrada'
], JSON_UNESCAPED_UNICODE);
