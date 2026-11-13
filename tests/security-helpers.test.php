<?php

require_once __DIR__ . '/../config/password-policy.php';
require_once __DIR__ . '/../config/password-reset-token.php';

function expectSecurityTest(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectRuntimeException(callable $callback, string $message): void
{
    try {
        $callback();
    } catch (RuntimeException) {
        return;
    }

    throw new RuntimeException($message);
}

$validUnicodePassword = 'Aa1!' . str_repeat("\u{1F600}", 8);
$shortUnicodePassword = 'Aa1!' . str_repeat("\u{1F600}", 7);
$maxBytesPassword = 'Aa1!' . str_repeat('x', 4092);
$tooManyBytesPassword = 'Aa1!' . str_repeat('x', 4093);

expectSecurityTest(
    isPasswordPolicySatisfied('Aa1!abcdefgh'),
    'A valid minimum-length password should pass.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied('Aa1!abcdefg'),
    'A password shorter than 12 characters should fail.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied('aa1!abcdefgh'),
    'A password without uppercase should fail.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied('AA1!ABCDEFGH'),
    'A password without lowercase should fail.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied('Aa!!abcdefgh'),
    'A password without a digit should fail.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied('Aa11abcdefgh'),
    'A password without a symbol should fail.'
);
expectSecurityTest(
    isPasswordPolicySatisfied($validUnicodePassword),
    'Twelve Unicode code points should pass.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied($shortUnicodePassword),
    'Eleven Unicode code points should fail.'
);
expectSecurityTest(
    isPasswordPolicySatisfied($maxBytesPassword),
    'A password of exactly 4096 UTF-8 bytes should pass.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied($tooManyBytesPassword),
    'A password larger than 4096 UTF-8 bytes should fail.'
);
expectSecurityTest(
    !isPasswordPolicySatisfied("Aa1!1234567\xFF"),
    'Invalid UTF-8 should fail.'
);

unset($_ENV['PASSWORD_RESET_HMAC_KEY']);
expectRuntimeException(
    static fn () => hashPasswordResetToken(str_repeat('a', 64)),
    'A missing HMAC key should fail.'
);

$_ENV['PASSWORD_RESET_HMAC_KEY'] = str_repeat('ab', 31);
expectRuntimeException(
    static fn () => hashPasswordResetToken(str_repeat('a', 64)),
    'A key shorter than 32 bytes should fail.'
);

$_ENV['PASSWORD_RESET_HMAC_KEY'] = str_repeat('z', 64);
expectRuntimeException(
    static fn () => hashPasswordResetToken(str_repeat('a', 64)),
    'A non-hexadecimal key should fail.'
);

$_ENV['PASSWORD_RESET_HMAC_KEY'] = str_repeat('ab', 32);
$token = str_repeat('a', 64);
$originalHash = hashPasswordResetToken($token);

expectSecurityTest(
    hashPasswordResetToken($token) === $originalHash,
    'The same token and key should produce a stable HMAC.'
);
expectSecurityTest(
    hashPasswordResetToken(str_repeat('b', 64)) !== $originalHash,
    'A different token should produce a different HMAC.'
);

$_ENV['PASSWORD_RESET_HMAC_KEY'] = str_repeat('cd', 32);
expectSecurityTest(
    hashPasswordResetToken($token) !== $originalHash,
    'A different key should produce a different HMAC.'
);

unset($_ENV['PASSWORD_RESET_HMAC_KEY']);

echo "Security helper tests passed.\n";
