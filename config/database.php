<?php

$host = '127.0.0.1';
$db = 'iforgot_dev';
$user = 'root';
$password = 'being';

$dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4";

$pdo = new PDO($dsn, $user, $password);

$pdo->setAttribute(
    PDO::ATTR_ERRMODE,
    PDO::ERRMODE_EXCEPTION
);