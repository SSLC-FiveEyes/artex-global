CREATE TABLE customer_ticket_files (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ticket_id BIGINT UNSIGNED NOT NULL,
    stored_filename VARCHAR(60) NOT NULL UNIQUE,
    mime VARCHAR(32) NOT NULL,
    bytes INT UNSIGNED NOT NULL,
    sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_customer_ticket_files_ticket (ticket_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
