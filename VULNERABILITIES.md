# BadBank Vulnerabilities Documentation

This document describes all intentional vulnerabilities present in BadBank for security training purposes.

## Table of Contents
1. [Authentication & Session Management](#authentication--session-management)
2. [Injection Vulnerabilities](#injection-vulnerabilities)
3. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
4. [Broken Access Control](#broken-access-control)
5. [Security Misconfiguration](#security-misconfiguration)
6. [Business Logic Flaws](#business-logic-flaws)
7. [Information Disclosure](#information-disclosure)

---

## Authentication & Session Management

### 1. Plaintext Password Storage
**CWE:** CWE-256 (Unprotected Storage of Credentials)  
**OWASP Top 10:** A02:2021 – Cryptographic Failures

**Description:** User passwords are stored in plaintext in the database without any hashing or encryption.

**Location:** `app.py` - register function, database storage

**Exploitation:**
- Access the SQLite database file directly
- Use SQL injection to dump user credentials
- Passwords are visible in database queries and logs

**Impact:**
- Complete account compromise for all users
- Credential reuse attacks on other systems
- Regulatory compliance violations (GDPR, PCI-DSS)

### 2. No Login Rate Limiting
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

**Description:** No protection against brute force attacks on login attempts.

**Location:** `app.py` - login function

**Exploitation:**
- Automated brute force attacks using tools like Hydra or Burp Suite
- Dictionary attacks against known usernames
- No account lockout or delay mechanisms

**Impact:**
- Account takeover through password guessing
- Resource exhaustion from excessive login attempts
- Service disruption

---

## Injection Vulnerabilities

### 3. SQL Injection in Login
**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)  
**OWASP Top 10:** A03:2021 – Injection

**Description:** Login function uses string concatenation to build SQL queries, allowing SQL injection attacks.

**Location:** `app.py` - login function, line with `f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"`

**Exploitation:**
```sql
Username: admin' OR '1'='1' --
Password: anything
```

**Impact:**
- Authentication bypass
- Data extraction from database
- Database modification or deletion
- Potential remote code execution

---

## Cross-Site Scripting (XSS)

### 4. Stored XSS in Transaction Descriptions
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**OWASP Top 10:** A03:2021 – Injection

**Description:** Transaction descriptions are stored and displayed without sanitization using the `|safe` filter.

**Location:** `templates/transactions.html`, `templates/dashboard.html`

**Exploitation:**
```html
<script>alert('Stored XSS')</script>
<img src=x onerror=alert('XSS')>
```

**Impact:**
- Session hijacking
- Account takeover
- Malware distribution
- Phishing attacks

### 5. Reflected XSS in Password Reset
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**OWASP Top 10:** A03:2021 – Injection

**Description:** URL parameter `message` is reflected in the password reset page without sanitization.

**Location:** `templates/reset_password.html`, `app.py` - reset_password function

**Exploitation:**
```
/reset-password?message=<script>alert('Reflected XSS')</script>
```

**Impact:**
- Session hijacking
- Credential theft
- Social engineering attacks

### 6. DOM-based XSS
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**OWASP Top 10:** A03:2021 – Injection

**Description:** Client-side JavaScript uses unsafe `innerHTML` with user-controlled data.

**Location:** `static/js/main.js` - multiple functions

**Exploitation:**
```
/dashboard?welcome=<img src=x onerror=alert('DOM XSS')>
/dashboard#<script>alert('Hash XSS')</script>
```

**Impact:**
- Client-side code execution
- Session hijacking
- Data theft

---

## Broken Access Control

### 7. IDOR in Money Transfers
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**OWASP Top 10:** A01:2021 – Broken Access Control

**Description:** Hidden `sender_user_id` field can be manipulated to transfer money from other users' accounts.

**Location:** `templates/transfer.html`, `app.py` - transfer function

**Exploitation:**
- Intercept transfer request
- Modify `sender_user_id` parameter to another user's ID
- Complete transfer from victim's account

**Impact:**
- Unauthorized money transfers
- Financial fraud
- Account balance manipulation

### 8. IDOR in Transaction History
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**OWASP Top 10:** A01:2021 – Broken Access Control

**Description:** `user_id` parameter in transactions endpoint allows viewing any user's transaction history.

**Location:** `app.py` - transactions function

**Exploitation:**
```
/transactions?user_id=2
```

**Impact:**
- Privacy violation
- Financial information disclosure
- Competitive intelligence gathering

---

## Security Misconfiguration

### 9. Debug Mode Enabled
**CWE:** CWE-489 (Active Debug Code)  
**OWASP Top 10:** A05:2021 – Security Misconfiguration

**Description:** Flask application runs with debug mode enabled in production.

**Location:** `app.py` - `app.config['DEBUG'] = True`

**Exploitation:**
- Trigger errors to see stack traces
- Access debug console in some configurations
- Information disclosure through error messages

**Impact:**
- Source code disclosure
- System information leakage
- Potential remote code execution

### 10. CORS Misconfiguration
**CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)  
**OWASP Top 10:** A05:2021 – Security Misconfiguration

**Description:** CORS configured to allow all origins with credentials.

**Location:** `app.py` - `CORS(app, origins="*", supports_credentials=True)`

**Exploitation:**
- Cross-origin requests from malicious sites
- CSRF attacks from external domains
- Session hijacking

**Impact:**
- Cross-site request forgery
- Data theft
- Account compromise

### 11. Raw SQL Error Messages
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)  
**OWASP Top 10:** A09:2021 – Security Logging and Monitoring Failures

**Description:** Database errors are displayed to users with full technical details.

**Location:** `app.py` - error handler

**Exploitation:**
- Trigger SQL errors to reveal database structure
- Learn table names and column information
- Craft more targeted SQL injection attacks

**Impact:**
- Information disclosure
- Database schema enumeration
- Enhanced attack capabilities

---

## Business Logic Flaws

### 12. Negative Balance Allowed
**CWE:** CWE-840 (Business Logic Errors)  
**OWASP Top 10:** A04:2021 – Insecure Design

**Description:** No validation prevents accounts from having negative balances.

**Location:** `app.py` - transfer function

**Exploitation:**
- Transfer more money than available in account
- Create unlimited negative balance
- Exploit race conditions for multiple transfers

**Impact:**
- Financial fraud
- Unlimited money creation
- Business logic bypass

### 13. No Race Condition Protection
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)  
**OWASP Top 10:** A04:2021 – Insecure Design

**Description:** No locking mechanism prevents concurrent balance modifications.

**Location:** `app.py` - transfer function

**Exploitation:**
- Submit multiple simultaneous transfer requests
- Race condition allows multiple transfers before balance check
- Overdraft protection bypass

**Impact:**
- Double spending
- Account balance manipulation
- Financial fraud

---

## Information Disclosure

### 14. Predictable User IDs
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**OWASP Top 10:** A01:2021 – Broken Access Control

**Description:** Sequential user IDs exposed in forms and API endpoints.

**Location:** Templates, JavaScript, API endpoints

**Exploitation:**
- Enumerate users via `/api/user/<id>`
- Predict new user IDs
- Target specific user accounts

**Impact:**
- User enumeration
- Privacy violation
- Targeted attacks

### 15. Exposed User Information in JavaScript
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**OWASP Top 10:** A09:2021 – Security Logging and Monitoring Failures

**Description:** User IDs and usernames exposed in client-side JavaScript.

**Location:** `templates/base.html`, `static/js/main.js`

**Exploitation:**
- View page source to extract user information
- Access global JavaScript variables
- Client-side data mining

**Impact:**
- Information disclosure
- User enumeration
- Enhanced attack reconnaissance

### 16. No CSRF Protection
**CWE:** CWE-352 (Cross-Site Request Forgery)  
**OWASP Top 10:** A01:2021 – Broken Access Control

**Description:** Forms lack CSRF tokens, allowing cross-site request forgery attacks.

**Location:** All forms in templates

**Exploitation:**
- Create malicious webpage with hidden forms
- Trick authenticated users into visiting page
- Perform unauthorized actions on their behalf

**Impact:**
- Unauthorized transactions
- Account modification
- Privilege escalation

---

## Summary

BadBank contains **16 major vulnerability categories** spanning all OWASP Top 10 2021 categories:

- **A01: Broken Access Control** - IDOR, CSRF, Predictable IDs
- **A02: Cryptographic Failures** - Plaintext passwords
- **A03: Injection** - SQL injection, XSS variants
- **A04: Insecure Design** - Business logic flaws
- **A05: Security Misconfiguration** - Debug mode, CORS, error messages
- **A07: Identification and Authentication Failures** - No rate limiting
- **A09: Security Logging and Monitoring Failures** - Information disclosure

This makes BadBank an excellent platform for comprehensive web application security training.
