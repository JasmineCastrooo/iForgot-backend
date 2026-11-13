
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/auth.php';

header('Content-Type: application/json; charset=utf-8');

$user = getAuthenticatedUser($pdo);

if (!$user) {
    http_response_code(401);

    echo json_encode([
        'message' => 'Sessão inválida ou expirada'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

echo json_encode([
    'message' => 'Usuário autenticado',
    'user' => $user
], JSON_UNESCAPED_UNICODE);
