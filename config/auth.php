
<?php

function createSession(PDO $pdo, int $userId): array
{
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);

    $expiresAt = gmdate(
        'Y-m-d H:i:s',
        time() + (30 * 24 * 60 * 60)
    );

    $stmt = $pdo->prepare(
        'INSERT INTO user_sessions (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)'
    );

    $stmt->execute([
        $userId,
        $tokenHash,
        $expiresAt
    ]);

    return [
        'token' => $token,
        'expires_at' => $expiresAt
    ];
}

function getAuthenticatedUser(PDO $pdo): ?array
{
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if (!preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authorization, $matches)) {
    return null;
    }

    $tokenHash = hash('sha256', $matches[1]);

    $stmt = $pdo->prepare(
        'SELECT users.id, users.email
         FROM user_sessions
         INNER JOIN users ON users.id = user_sessions.user_id
         WHERE user_sessions.token_hash = ?
         AND user_sessions.expires_at > UTC_TIMESTAMP()
         AND user_sessions.revoked_at IS NULL'
    );

    $stmt->execute([$tokenHash]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    return $user ?: null;
}
