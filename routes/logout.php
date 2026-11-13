
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

$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
preg_match('/^Bearer\s+(.+)$/i', $authorization, $matches);

$tokenHash = hash('sha256', $matches[1]);

$stmt = $pdo->prepare(
    'UPDATE user_sessions
     SET revoked_at = UTC_TIMESTAMP()
     WHERE token_hash = ?'
);

$stmt->execute([$tokenHash]);

echo json_encode([
    'message' => 'Logout realizado com sucesso'
], JSON_UNESCAPED_UNICODE);
