
<?php

function isResetValidationBlocked(PDO $pdo, string $email, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT blocked_until
         FROM password_reset_validation_attempts
         WHERE email = ? AND ip_address = ?'
    );

    $stmt->execute([$email, $ipAddress]);
    $attempt = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($attempt && $attempt['blocked_until'] !== null) {
        if (strtotime($attempt['blocked_until'] . ' UTC') > time()) {
            return true;
        }

        $stmt = $pdo->prepare(
            'UPDATE password_reset_validation_attempts
             SET attempts = 0, blocked_until = NULL
             WHERE email = ? AND ip_address = ?'
        );

        $stmt->execute([$email, $ipAddress]);
    }

    return false;
}

function isResetValidationIpBlocked(PDO $pdo, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT COALESCE(SUM(attempts), 0)
         FROM password_reset_validation_attempts
         WHERE ip_address = ?
         AND last_attempt_at >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE'
    );

    $stmt->execute([$ipAddress]);

    return (int) $stmt->fetchColumn() >= 20;
}

function registerFailedResetValidation(PDO $pdo, string $email, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO password_reset_validation_attempts (
            email,
            ip_address,
            attempts,
            last_attempt_at
        )
        VALUES (?, ?, 1, UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
            blocked_until = IF(
                last_attempt_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE,
                NULL,
                IF(attempts + 1 >= 5,
                    DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE),
                    blocked_until
                )
            ),
            attempts = IF(
                last_attempt_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE,
                1,
                attempts + 1
            ),
            last_attempt_at = UTC_TIMESTAMP()'
    );

    $stmt->execute([$email, $ipAddress]);

    $stmt = $pdo->prepare(
        'SELECT attempts
         FROM password_reset_validation_attempts
         WHERE email = ? AND ip_address = ?'
    );

    $stmt->execute([$email, $ipAddress]);

    $attempts = (int) $stmt->fetchColumn();

    if ($attempts >= 20) {
        $stmt = $pdo->prepare(
            'UPDATE password_reset_validation_attempts
             SET blocked_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)
             WHERE ip_address = ?
             AND attempts >= 20'
        );

        $stmt->execute([$ipAddress]);
    }
}

function clearResetValidationAttempts(PDO $pdo, string $email, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'DELETE FROM password_reset_validation_attempts
         WHERE email = ? AND ip_address = ?'
    );

    $stmt->execute([$email, $ipAddress]);
}
