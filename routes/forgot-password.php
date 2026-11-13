
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/mail.php';
require_once __DIR__ . '/../config/password-reset-security.php';
require_once __DIR__ . '/../config/password-reset-token.php';

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

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);

    echo json_encode([
        'message' => 'Informe um e-mail válido'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

$response = [
    'message' => 'Se o e-mail estiver cadastrado, você receberá um código de recuperação.'
];

if (
    isPasswordResetBlocked($pdo, $email, $ipAddress) ||
    isPasswordResetIpBlocked($pdo, $ipAddress)
) {
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

registerPasswordResetAttempt($pdo, $email, $ipAddress);

$stmt = $pdo->prepare(
    'SELECT id FROM users WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

$code = bin2hex(random_bytes(32));

$expiresAt = gmdate(
    'Y-m-d H:i:s',
    time() + (10 * 60)
);

$resetId = null;

try {
    $tokenHash = hashPasswordResetToken($code);

    $stmt = $pdo->prepare(
        'INSERT INTO password_resets (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)'
    );

    $stmt->execute([
        $user['id'],
        $tokenHash,
        $expiresAt
    ]);

    $resetId = (int) $pdo->lastInsertId();

    $mail = createMailer();

    $mail->addAddress($email);
    $mail->isHTML(true);
    $mail->Subject = 'Recuperação de senha - iForgot';

    $mail->Body = "
        <h2>Recuperação de senha</h2>
        <p>Recebemos uma solicitação para redefinir sua senha mestra.</p>
        <p>Seu token de recuperação é:</p>
        <h1>$code</h1>
        <p>Esse código expira em 10 minutos e só pode ser utilizado uma vez.</p>
        <p>Se você não solicitou essa recuperação, ignore este e-mail.</p>
    ";

    $mail->AltBody = "Seu token de recuperação do iForgot é: $code. Ele expira em 10 minutos.";

    $mail->send();

    $stmt = $pdo->prepare(
        'UPDATE password_resets
         SET used_at = UTC_TIMESTAMP()
         WHERE user_id = ?
         AND id <> ?
         AND used_at IS NULL'
    );

    $stmt->execute([
        $user['id'],
        $resetId
    ]);

} catch (Throwable $e) {
    error_log(
        'Erro na recuperação de senha: ' . $e->getMessage()
    );

    if ($resetId !== null) {
        try {
            $stmt = $pdo->prepare(
                'UPDATE password_resets
                 SET used_at = UTC_TIMESTAMP()
                 WHERE id = ?'
            );

            $stmt->execute([$resetId]);

        } catch (Throwable $cleanupError) {
            error_log(
                'Erro ao invalidar código de recuperação: ' .
                $cleanupError->getMessage()
            );
        }
    }

    http_response_code(500);

    echo json_encode([
        'message' => 'Não foi possível processar a solicitação.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

echo json_encode($response, JSON_UNESCAPED_UNICODE);
