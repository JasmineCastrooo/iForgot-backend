
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/auth.php';

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(
    file_get_contents('php://input'),
    true
);

$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

$stmt = $pdo->prepare(
    'SELECT id, email, password_hash
     FROM users
     WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || !password_verify($password, $user['password_hash'])) {
    http_response_code(401);

    echo json_encode([
        'message' => 'E-mail ou senha incorretos'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

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
