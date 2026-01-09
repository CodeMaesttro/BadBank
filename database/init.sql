-- BadBank Database Initialization Script
-- SQLite database schema for the intentionally vulnerable banking application

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
);

-- Accounts table
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    account_type VARCHAR(20) DEFAULT 'checking',
    balance DECIMAL(15,2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account_id INTEGER,
    to_account_id INTEGER,
    amount DECIMAL(15,2) NOT NULL,
    transaction_type VARCHAR(20) NOT NULL, -- 'transfer', 'deposit', 'withdrawal'
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'completed',
    FOREIGN KEY (from_account_id) REFERENCES accounts (id),
    FOREIGN KEY (to_account_id) REFERENCES accounts (id)
);

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert seed users (passwords stored in plaintext)
INSERT OR IGNORE INTO users (username, email, password_hash, full_name, phone, address) VALUES
('alice', 'alice@badbank.com', 'password123', 'Alice Johnson', '555-0101', '123 Main St, Anytown, USA'),
('bob', 'bob@badbank.com', 'password123', 'Bob Smith', '555-0102', '456 Oak Ave, Somewhere, USA'),
('charlie', 'charlie@badbank.com', 'password123', 'Charlie Brown', '555-0103', '789 Pine Rd, Elsewhere, USA');

-- Insert seed accounts
INSERT OR IGNORE INTO accounts (user_id, account_number, balance) VALUES
(1, '1001-2001-3001', 5000.00),
(2, '1001-2002-3002', 3500.00),
(3, '1001-2003-3003', 7500.00);

-- Insert some sample transactions
INSERT OR IGNORE INTO transactions (from_account_id, to_account_id, amount, transaction_type, description) VALUES
(1, 2, 500.00, 'transfer', 'Payment for services'),
(2, 3, 250.00, 'transfer', 'Dinner split'),
(3, 1, 1000.00, 'transfer', 'Loan repayment');