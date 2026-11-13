<?php

function isPasswordPolicySatisfied(string $password): bool
{
    $characterCount = preg_match_all('/./us', $password);

    return $characterCount !== false
        && $characterCount >= 12
        && strlen($password) <= 4096
        && preg_match('/[A-Z]/', $password) === 1
        && preg_match('/[a-z]/', $password) === 1
        && preg_match('/[0-9]/', $password) === 1
        && preg_match('/[^A-Za-z0-9]/', $password) === 1;
}
