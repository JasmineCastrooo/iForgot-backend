
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/auth.php';
require_once __DIR__ . '/../config/login-security.php';

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(
    file_get_contents('php://input'),
    true
);

if (!is_array($data)) {
    http_response_code(400);

    echo json_encode([
        'message' => 'Dados inválidos'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';
$ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if ($email === '' || $password === '') {
    http_response_code(400);

    echo json_encode([
        'message' => 'E-mail e senha são obrigatórios'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

if (isIpLoginBlocked($pdo, $ipAddress)) {
    http_response_code(429);

    echo json_encode([
        'message' => 'Muitas tentativas deste endereço. Tente novamente em 15 minutos.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

if (isLoginBlocked($pdo, $email, $ipAddress)) {
    http_response_code(429);

    echo json_encode([
        'message' => 'Muitas tentativas. Tente novamente em 15 minutos.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$stmt = $pdo->prepare(
    'SELECT id, email, password_hash
     FROM users
     WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || !password_verify($password, $user['password_hash'])) {
    registerFailedLogin($pdo, $email, $ipAddress);
    registerFailedIpLogin($pdo, $ipAddress);

    http_response_code(401);

    echo json_encode([
        'message' => 'E-mail ou senha incorretos'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

clearLoginAttempts($pdo, $email, $ipAddress);
clearIpLoginAttempts($pdo, $ipAddress);

$session = createSession($pdo, (int) $user['id']);

echo json_encode([
    'message' => 'Login realizado com sucesso',
    'user' => [
        'id' => $user['id'],
        'email' => $user['email']
    ],
    'session' => [
        'token' => $session['token'],
        'expires_at' => $session['expires_at']
    ]
], JSON_UNESCAPED_UNICODE);
