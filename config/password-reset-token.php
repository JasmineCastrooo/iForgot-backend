<?php

function hashPasswordResetToken(string $token): string
{
    $keyHex = $_ENV['PASSWORD_RESET_HMAC_KEY'] ?? '';

    if (
        !is_string($keyHex) ||
        !preg_match('/\A(?:[a-f0-9]{2}){32,}\z/i', $keyHex)
    ) {
        throw new RuntimeException(
            'PASSWORD_RESET_HMAC_KEY must be at least 32 random bytes encoded as hexadecimal.'
        );
    }

    $key = hex2bin($keyHex);

    if ($key === false || strlen($key) < 32) {
        throw new RuntimeException(
            'PASSWORD_RESET_HMAC_KEY must be at least 32 random bytes encoded as hexadecimal.'
        );
    }

    return hash_hmac('sha256', $token, $key);
}
