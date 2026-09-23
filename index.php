<?php

require_once __DIR__ . '/config/database.php';

$email = 'teste@iforgot.local';

$stmt = $pdo->prepare(
    'SELECT id, email, password_hash, created_at FROM users WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

echo json_encode($user);