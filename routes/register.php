
<?php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/password-policy.php';

header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['message' => 'Dados inválidos'], JSON_UNESCAPED_UNICODE);
    exit;
}

$email = is_string($data['email'] ?? null)
    ? trim($data['email'])
    : '';
$password = $data['password'] ?? null;

if ($email === '' || !is_string($password) || $password === '') {
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

if (!isPasswordPolicySatisfied($password)) {
    http_response_code(400);

    echo json_encode([
        'message' => 'A senha deve ter pelo menos 12 caracteres Unicode, no máximo 4096 bytes UTF-8 e incluir maiúscula, minúscula, número e símbolo'
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$passwordHash = password_hash(
    $password,
    PASSWORD_DEFAULT
);

if ($passwordHash === false) {
    throw new RuntimeException('Falha ao gerar hash da senha.');
}

$message = 'Se o e-mail estiver disponível, a conta foi criada. Você pode tentar entrar.';

try {
    $stmt = $pdo->prepare(
        'INSERT INTO users (email, password_hash)
         VALUES (?, ?)'
    );

    $stmt->execute([$email, $passwordHash]);
} catch (PDOException $error) {
    if (($error->errorInfo[1] ?? null) !== 1062) {
        throw $error;
    }
}

http_response_code(202);
echo json_encode(['message' => $message], JSON_UNESCAPED_UNICODE);
