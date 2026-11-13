
<?php

function isLoginBlocked(PDO $pdo, string $email, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT blocked_until
         FROM login_attempts
         WHERE email = ? AND ip_address = ?'
    );

    $stmt->execute([$email, $ipAddress]);

    $attempt = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($attempt && $attempt['blocked_until'] !== null) {
        if (strtotime($attempt['blocked_until'] . ' UTC') > time()) {
            return true;
        }

        $stmt = $pdo->prepare(
            'UPDATE login_attempts
             SET attempts = 0, blocked_until = NULL
             WHERE email = ? AND ip_address = ?'
        );

        $stmt->execute([$email, $ipAddress]);
    }

    return false;
}

function registerFailedLogin(PDO $pdo, string $email, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO login_attempts (
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
            blocked_until = IF(
                last_attempt_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE,
                NULL,
                IF(
                    attempts + 1 >= 5,
                    DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE),
                    blocked_until
                )
            ),
            last_attempt_at = UTC_TIMESTAMP()'
    );

    $stmt->execute([$email, $ipAddress]);
}

function clearLoginAttempts(PDO $pdo, string $email, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'DELETE FROM login_attempts
         WHERE email = ? AND ip_address = ?'
    );

    $stmt->execute([$email, $ipAddress]);
}

function isIpLoginBlocked(PDO $pdo, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT blocked_until
         FROM ip_login_attempts
         WHERE ip_address = ?'
    );

    $stmt->execute([$ipAddress]);

    $attempt = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$attempt || $attempt['blocked_until'] === null) {
        return false;
    }

    if (strtotime($attempt['blocked_until'] . ' UTC') > time()) {
        return true;
    }

    $stmt = $pdo->prepare(
        'UPDATE ip_login_attempts
         SET attempts = 0, blocked_until = NULL
         WHERE ip_address = ?'
    );

    $stmt->execute([$ipAddress]);

    return false;
}

function registerFailedIpLogin(PDO $pdo, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO ip_login_attempts (
            ip_address,
            attempts,
            last_attempt_at
        )
        VALUES (?, 1, UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
            attempts = IF(
                last_attempt_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE,
                1,
                attempts + 1
            ),
            blocked_until = IF(
                last_attempt_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE,
                NULL,
                IF(
                    attempts + 1 >= 20,
                    DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE),
                    blocked_until
                )
            ),
            last_attempt_at = UTC_TIMESTAMP()'
    );

    $stmt->execute([$ipAddress]);
}

function clearIpLoginAttempts(PDO $pdo, string $ipAddress): void
{
    $stmt = $pdo->prepare(
        'DELETE FROM ip_login_attempts
         WHERE ip_address = ?'
    );

    $stmt->execute([$ipAddress]);
}
