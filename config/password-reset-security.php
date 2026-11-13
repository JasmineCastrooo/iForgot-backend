
<?php

function isPasswordResetBlocked(PDO $pdo, string $email, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT attempts, last_attempt_at
         FROM password_reset_attempts
         WHERE email = ? AND ip_address = ?'
    );

    $stmt->execute([$email, $ipAddress]);

    $attempt = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$attempt) {
        return false;
    }

    $lastAttempt = strtotime($attempt['last_attempt_at'] . ' UTC');

    if ($lastAttempt === false || $lastAttempt < time() - (15 * 60)) {
        $stmt = $pdo->prepare(
            'DELETE FROM password_reset_attempts
             WHERE email = ? AND ip_address = ?'
        );

        $stmt->execute([$email, $ipAddress]);

        return false;
    }

    return (int) $attempt['attempts'] >= 3;
}

function isPasswordResetIpBlocked(PDO $pdo, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT COALESCE(SUM(attempts), 0)
         FROM password_reset_attempts
         WHERE ip_address = ?
         AND last_attempt_at >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE'
    );

    $stmt->execute([$ipAddress]);

    return (int) $stmt->fetchColumn() >= 10;
}

function registerPasswordResetAttempt(PDO $pdo, string $email, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO password_reset_attempts (
            email,
            ip_address,
            attempts,
            last_attempt_at
        )
        VALUES (?, ?, 1, UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
            attempts = IF(
                last_attempt_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE,
                1,
                attempts + 1
            ),
            last_attempt_at = UTC_TIMESTAMP()'
    );

    $stmt->execute([$email, $ipAddress]);
}
