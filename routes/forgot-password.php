
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/mail.php';

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(
    file_get_contents('php://input'),
    true
);

$email = trim($data['email'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);

    echo json_encode([
        'message' => 'Informe um e-mail válido'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$stmt = $pdo->prepare(
    'SELECT id FROM users WHERE email = ?'
);

$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

$response = [
    'message' => 'Se o e-mail estiver cadastrado, você receberá um código de recuperação.'
];

if (!$user) {
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

$code = (string) random_int(10000000, 99999999);
$tokenHash = hash('sha256', $code);

$expiresAt = gmdate(
    'Y-m-d H:i:s',
    time() + (10 * 60)
);

try {
    $stmt = $pdo->prepare(
        'UPDATE password_resets
         SET used_at = UTC_TIMESTAMP()
         WHERE user_id = ?
         AND used_at IS NULL'
    );

    $stmt->execute([$user['id']]);

    $stmt = $pdo->prepare(
        'INSERT INTO password_resets (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)'
    );

    $stmt->execute([
        $user['id'],
        $tokenHash,
        $expiresAt
    ]);

    $mail = createMailer();

    $mail->addAddress($email);
    $mail->isHTML(true);
    $mail->Subject = 'Recuperação de senha - iForgot';

    $mail->Body = "
        <h2>Recuperação de senha</h2>
        <p>Recebemos uma solicitação para redefinir sua senha mestra.</p>
        <p>Seu código de recuperação é:</p>
        <h1>$code</h1>
        <p>Esse código expira em 10 minutos e só pode ser utilizado uma vez.</p>
        <p>Se você não solicitou essa recuperação, ignore este e-mail.</p>
    ";

    $mail->AltBody = "Seu código de recuperação do iForgot é: $code. Ele expira em 10 minutos.";

    $mail->send();

} catch (Throwable $e) {
    http_response_code(500);

    echo json_encode([
        'message' => 'Não foi possível processar a solicitação.'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

echo json_encode($response, JSON_UNESCAPED_UNICODE);
