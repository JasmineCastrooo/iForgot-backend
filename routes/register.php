
<?php

require_once __DIR__ . '/../config/database.php';

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(
    file_get_contents('php://input'),
    true
);

$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if ($email === '' || $password === '') {
    http_response_code(400);

    echo json_encode([
        'message' => 'E-mail e senha são obrigatórios'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);

    echo json_encode([
        'message' => 'E-mail inválido'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

if (strlen($password) < 8) {
    http_response_code(400);

    echo json_encode([
        'message' => 'A senha deve ter pelo menos 8 caracteres'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$stmt = $pdo->prepare(
    'SELECT id FROM users WHERE email = ?'
);

$stmt->execute([$email]);

if ($stmt->fetch()) {
    http_response_code(409);

    echo json_encode([
        'message' => 'Este e-mail já está cadastrado'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$passwordHash = password_hash(
    $password,
    PASSWORD_DEFAULT
);

$stmt = $pdo->prepare(
    'INSERT INTO users (email, password_hash)
     VALUES (?, ?)'
);

$stmt->execute([$email, $passwordHash]);

http_response_code(201);

echo json_encode([
    'message' => 'Usuário cadastrado com sucesso',
    'user' => [
        'id' => $pdo->lastInsertId(),
        'email' => $email
    ]
], JSON_UNESCAPED_UNICODE);
