<?php

$requiredDatabaseSettings = [
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD',
];

foreach ($requiredDatabaseSettings as $setting) {
    if (!isset($_ENV[$setting]) || $_ENV[$setting] === '') {
        throw new RuntimeException(
            "Configuração obrigatória ausente: $setting"
        );
    }
}

$environment = $_ENV['APP_ENV'] ?? 'development';
$user = $_ENV['DB_USER'];

if ($environment === 'production' && strtolower($user) === 'root') {
    throw new RuntimeException(
        'A aplicação não pode usar o usuário root do MySQL em produção.'
    );
}

$dsn = sprintf(
    'mysql:host=%s;dbname=%s;charset=utf8mb4',
    $_ENV['DB_HOST'],
    $_ENV['DB_NAME']
);

$pdo = new PDO(
    $dsn,
    $user,
    $_ENV['DB_PASSWORD'],
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);