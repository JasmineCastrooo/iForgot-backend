
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/reset-validation-security.php';

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['message' => 'Dados inválidos'], JSON_UNESCAPED_UNICODE);
    exit;
}

$email = trim($data['email'] ?? '');
$code = trim($data['code'] ?? '');
$newPassword = $data['new_password'] ?? '';
$ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['message' => 'E-mail inválido'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (!preg_match('/^\d{8}$/', $code)) {
    http_response_code(400);
    echo json_encode(['message' => 'Código de recuperação inválido'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (!is_string($newPassword) || strlen($newPassword) < 8) {
    http_response_code(400);
    echo json_encode(['message' => 'A nova senha deve ter pelo menos 8 caracteres'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (strlen($newPassword) > 4096) {
    http_response_code(400);
    echo json_encode(['message' => 'A nova senha é muito longa'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (
    isResetValidationIpBlocked($pdo, $ipAddress) ||
    isResetValidationBlocked($pdo, $email, $ipAddress)
) {
    http_response_code(429);
    echo json_encode(['message' => 'Muitas tentativas. Tente novamente em 15 minutos.'], JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare(
        'SELECT password_resets.id, password_resets.user_id
         FROM password_resets
         INNER JOIN users ON users.id = password_resets.user_id
         WHERE users.email = ?
         AND password_resets.token_hash = ?
         AND password_resets.expires_at > UTC_TIMESTAMP()
         AND password_resets.used_at IS NULL
         FOR UPDATE'
    );

    $stmt->execute([
        $email,
        hash('sha256', $code)
    ]);

    $reset = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$reset) {
        $pdo->commit();

        registerFailedResetValidation($pdo, $email, $ipAddress);

        http_response_code(400);
        echo json_encode(['message' => 'Código inválido ou expirado'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

    if ($passwordHash === false) {
        throw new RuntimeException('Falha ao gerar hash da senha.');
    }

    $stmt = $pdo->prepare(
        'UPDATE users SET password_hash = ? WHERE id = ?'
    );

    $stmt->execute([$passwordHash, $reset['user_id']]);

    $stmt = $pdo->prepare(
        'UPDATE password_resets
         SET used_at = UTC_TIMESTAMP()
         WHERE user_id = ? AND used_at IS NULL'
    );

    $stmt->execute([$reset['user_id']]);

    $stmt = $pdo->prepare(
        'UPDATE user_sessions
         SET revoked_at = UTC_TIMESTAMP()
         WHERE user_id = ? AND revoked_at IS NULL'
    );

    $stmt->execute([$reset['user_id']]);

    $pdo->commit();

    clearResetValidationAttempts($pdo, $email, $ipAddress);

    echo json_encode([
        'message' => 'Senha redefinida com sucesso'
    ], JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('Erro na redefinição de senha: ' . $e->getMessage());

    http_response_code(500);

    echo json_encode([
        'message' => 'Não foi possível redefinir a senha'
    ], JSON_UNESCAPED_UNICODE);
}
