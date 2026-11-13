
CREATE TABLE password_reset_validation_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    blocked_until DATETIME NULL,
    last_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE INDEX idx_reset_validation_email_ip (email, ip_address),
    INDEX idx_reset_validation_ip (ip_address),
    INDEX idx_reset_validation_blocked (blocked_until)
);
