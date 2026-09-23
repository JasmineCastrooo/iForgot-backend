<?php

require_once __DIR__ . '/config/database.php';

$data = json_decode(
    file_get_contents('php://input'),
    true
);

$email = $data['email'] ?? '';
$password = $data['password'] ?? '';

$stmt = $pdo->prepare(
    'SELECT id, email, password_hash
     FROM users
     WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    echo json_encode([
        'message' => 'Usuário não encontrado'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

if (!password_verify($password, $user['password_hash'])) {
    echo json_encode([
        'message' => 'Senha incorreta'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

echo json_encode([
    'message' => 'Login realizado com sucesso',
    'user' => [
        'id' => $user['id'],
        'email' => $user['email']
    ]
], JSON_UNESCAPED_UNICODE);