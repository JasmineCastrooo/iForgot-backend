<?php

require_once __DIR__ . '/config/database.php';

$data = json_decode(
    file_get_contents('php://input'),
    true
);

$email = $data['email'] ?? '';

$stmt = $pdo->prepare(
    'SELECT id, email, password_hash, created_at
     FROM users
     WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    echo json_encode([
        'message' => 'Usuário não encontrado'
    ]);

    exit;
}

echo json_encode($user);
