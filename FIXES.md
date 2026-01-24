# BadBank Security Fixes Guide

This document provides secure mitigation strategies for all vulnerabilities in BadBank. These fixes should be implemented in a real-world application but are intentionally omitted from BadBank for training purposes.

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

### 1. Fix Plaintext Password Storage

**Problem:** Passwords stored in plaintext
**Solution:** Implement proper password hashing

```python
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

# Option 1: Using Werkzeug (Flask's built-in)
password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

# Option 2: Using bcrypt (recommended)
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

# Verification
is_valid = check_password_hash(stored_hash, provided_password)
# or for bcrypt:
is_valid = bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)
```

**Additional Security Measures:**
- Enforce strong password policies (minimum length, complexity)
- Implement password history to prevent reuse
- Use secure random salt for each password
- Consider using Argon2 for maximum security

### 2. Implement Login Rate Limiting

**Problem:** No protection against brute force attacks
**Solution:** Add rate limiting and account lockout

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from datetime import datetime, timedelta

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

# Add rate limiting decorator
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Implementation with account lockout
    username = request.form['username']
    
    # Check if account is locked
    lockout_key = f"lockout:{username}"
    if redis_client.get(lockout_key):
        flash('Account temporarily locked due to too many failed attempts', 'error')
        return render_template('login.html')
    
    # Track failed attempts
    attempts_key = f"attempts:{username}"
    failed_attempts = int(redis_client.get(attempts_key) or 0)
    
    if not authenticate_user(username, password):
        failed_attempts += 1
        redis_client.setex(attempts_key, 300, failed_attempts)  # 5 minute window
        
        if failed_attempts >= 5:
            redis_client.setex(lockout_key, 1800, 1)  # 30 minute lockout
            flash('Account locked due to too many failed attempts', 'error')
        
        return render_template('login.html')
    
    # Clear failed attempts on successful login
    redis_client.delete(attempts_key)
```

**Additional Measures:**
- Implement CAPTCHA after failed attempts
- Use progressive delays (exponential backoff)
- Monitor and alert on suspicious login patterns
- Consider implementing 2FA/MFA

---

## Injection Vulnerabilities

### 3. Fix SQL Injection

**Problem:** String concatenation in SQL queries
**Solution:** Use parameterized queries and ORM

```python
# BAD - String concatenation (current vulnerable code)
query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"

# GOOD - Parameterized queries
cursor = db.execute(
    'SELECT * FROM users WHERE username = ? AND password_hash = ?',
    (username, password_hash)
)

# BETTER - Using SQLAlchemy ORM
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

# Query using ORM
user = session.query(User).filter(
    User.username == username,
    User.password_hash == password_hash
).first()
```

**Input Validation:**
```python
import re
from wtforms import Form, StringField, validators

class LoginForm(Form):
    username = StringField('Username', [
        validators.Length(min=3, max=50),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores")
    ])
    password = StringField('Password', [validators.Length(min=8, max=128)])

# Validate input
form = LoginForm(request.form)
if not form.validate():
    return render_template('login.html', errors=form.errors)
```

---

## Cross-Site Scripting (XSS)

### 4. Fix Stored XSS in Transaction Descriptions

**Problem:** Unsanitized user input displayed with `|safe` filter
**Solution:** Proper input sanitization and output encoding

```python
from markupsafe import escape
import bleach
from html import escape as html_escape

# Option 1: HTML escaping (basic protection)
safe_description = html_escape(description)

# Option 2: Using bleach for HTML sanitization (recommended)
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong']
ALLOWED_ATTRIBUTES = {}

def sanitize_html(content):
    return bleach.clean(content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)

# In template - remove |safe filter
{{ transaction.description }}  # Auto-escaped by Jinja2

# If HTML is needed, sanitize first
{{ sanitize_html(transaction.description)|safe }}
```

**Content Security Policy (CSP):**
```python
from flask_talisman import Talisman

# Add CSP headers
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",  # Remove unsafe-inline in production
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data:",
    'font-src': "'self'",
    'connect-src': "'self'",
    'frame-ancestors': "'none'"
}

Talisman(app, content_security_policy=csp)
```

### 5. Fix Reflected XSS in Password Reset

**Problem:** URL parameter reflected without sanitization
**Solution:** Input validation and output encoding

```python
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        # Validate and sanitize message parameter
        message = request.args.get('message', '')
        if message:
            # Validate message format
            if not re.match(r'^[a-zA-Z0-9\s\.,!?-]+$', message):
                message = ''  # Reject invalid characters
            # Limit length
            message = message[:200]
        
        return render_template('reset_password.html', message=message)
```

**Template Fix:**
```html
<!-- Remove |safe filter -->
{% if message %}
<div class="alert alert-info">
    {{ message }}  <!-- Auto-escaped by Jinja2 -->
</div>
{% endif %}
```

### 6. Fix DOM-based XSS

**Problem:** Unsafe `innerHTML` usage in JavaScript
**Solution:** Use safe DOM manipulation methods

```javascript
// BAD - Unsafe innerHTML
element.innerHTML = userInput;

// GOOD - Safe text content
element.textContent = userInput;

// GOOD - Safe DOM creation
function createSafeElement(tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    return element;
}

// GOOD - Using DOMPurify for HTML sanitization
function sanitizeHTML(html) {
    return DOMPurify.sanitize(html);
}

// Safe search function
function performSearch(query) {
    // Validate input
    if (typeof query !== 'string' || query.length > 100) {
        return;
    }
    
    fetch(`/api/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            const resultsDiv = document.getElementById('search-results');
            if (resultsDiv) {
                // Clear previous results
                resultsDiv.innerHTML = '';
                
                // Create safe elements
                const title = createSafeElement('h3', 'Search Results');
                const message = createSafeElement('p', data.message);
                const results = createSafeElement('div', data.results);
                results.className = 'results';
                
                resultsDiv.appendChild(title);
                resultsDiv.appendChild(message);
                resultsDiv.appendChild(results);
            }
        });
}
```

---

## Broken Access Control

### 7. Fix IDOR in Money Transfers

**Problem:** User can manipulate `sender_user_id` parameter
**Solution:** Server-side authorization checks

```python
@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # Remove sender_user_id from form - use session instead
    sender_user_id = session['user_id']  # Always use authenticated user
    
    recipient_account = request.form['recipient_account']
    amount = float(request.form['amount'])
    description = sanitize_html(request.form.get('description', ''))
    
    # Validate amount
    if amount <= 0:
        flash('Transfer amount must be positive.', 'error')
        return render_template('transfer.html')
    
    db = get_db()
    sender_account = get_user_account(sender_user_id)
    
    # Check sufficient funds
    if sender_account['balance'] < amount:
        flash('Insufficient funds.', 'error')
        return render_template('transfer.html')
    
    # Use database transactions for atomicity
    try:
        db.execute('BEGIN TRANSACTION')
        
        # Update balances
        db.execute(
            'UPDATE accounts SET balance = balance - ? WHERE id = ?',
            (amount, sender_account['id'])
        )
        db.execute(
            'UPDATE accounts SET balance = balance + ? WHERE id = ?',
            (amount, recipient['id'])
        )
        
        # Record transaction
        db.execute(
            'INSERT INTO transactions (from_account_id, to_account_id, amount, transaction_type, description) VALUES (?, ?, ?, ?, ?)',
            (sender_account['id'], recipient['id'], amount, 'transfer', description)
        )
        
        db.execute('COMMIT')
        flash(f'Successfully transferred ${amount:.2f}', 'success')
        
    except Exception as e:
        db.execute('ROLLBACK')
        flash('Transfer failed. Please try again.', 'error')
        app.logger.error(f'Transfer error: {e}')
```

### 8. Fix IDOR in Transaction History

**Problem:** User can view any user's transactions via URL parameter
**Solution:** Enforce proper authorization

```python
@app.route('/transactions')
@login_required
def transactions():
    # Always use authenticated user's ID - ignore URL parameters
    user_id = session['user_id']
    
    account = get_user_account(user_id)
    if not account:
        flash('Account not found.', 'error')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    transactions = db.execute('''
        SELECT t.*, 
               from_acc.account_number as from_account,
               to_acc.account_number as to_account,
               from_user.full_name as from_user_name,
               to_user.full_name as to_user_name
        FROM transactions t
        LEFT JOIN accounts from_acc ON t.from_account_id = from_acc.id
        LEFT JOIN accounts to_acc ON t.to_account_id = to_acc.id
        LEFT JOIN users from_user ON from_acc.user_id = from_user.id
        LEFT JOIN users to_user ON to_acc.user_id = to_user.id
        WHERE t.from_account_id = ? OR t.to_account_id = ?
        ORDER BY t.created_at DESC
    ''', (account['id'], account['id'])).fetchall()
    
    return render_template('transactions.html', transactions=transactions, user_account=account)
```

---

## Security Misconfiguration

### 9. Fix Debug Mode and Error Handling

**Problem:** Debug mode enabled and raw error messages exposed
**Solution:** Proper error handling and logging

```python
import logging
from logging.handlers import RotatingFileHandler

# Disable debug mode in production
app.config['DEBUG'] = False

# Configure proper logging
if not app.debug:
    file_handler = RotatingFileHandler('logs/badbank.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

# Custom error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return render_template('errors/500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error
    app.logger.error(f'Unhandled exception: {e}', exc_info=True)
    
    # Return generic error message
    return render_template('errors/generic.html', 
                         message='An error occurred. Please try again later.'), 500
```

### 10. Fix CORS Misconfiguration

**Problem:** CORS allows all origins with credentials
**Solution:** Restrict CORS to specific trusted origins

```python
from flask_cors import CORS

# Restrict CORS to specific origins
CORS(app, 
     origins=['https://yourdomain.com', 'https://app.yourdomain.com'],
     supports_credentials=True,
     methods=['GET', 'POST'],
     allow_headers=['Content-Type', 'Authorization'])

# Or disable CORS entirely if not needed
# Remove CORS configuration
```

---

## Business Logic Flaws

### 11. Fix Negative Balance Issue

**Problem:** No validation prevents negative balances
**Solution:** Implement proper balance validation

```python
@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # ... existing code ...
    
    # Validate transfer amount
    if amount <= 0:
        flash('Transfer amount must be positive.', 'error')
        return render_template('transfer.html')
    
    if amount > 10000:  # Daily transfer limit
        flash('Transfer amount exceeds daily limit of $10,000.', 'error')
        return render_template('transfer.html')
    
    # Check sufficient funds with buffer
    if sender_account['balance'] < amount:
        flash('Insufficient funds for this transfer.', 'error')
        return render_template('transfer.html')
    
    # Additional business rules
    if sender_account['balance'] - amount < -100:  # Overdraft limit
        flash('Transfer would exceed overdraft limit.', 'error')
        return render_template('transfer.html')
```

### 12. Fix Race Condition in Transfers

**Problem:** No locking mechanism for concurrent balance updates
**Solution:** Implement database locking and transactions

```python
import threading
from contextlib import contextmanager

# Thread-local storage for database connections
thread_local = threading.local()

@contextmanager
def get_db_transaction():
    """Context manager for database transactions with locking"""
    db = get_db()
    try:
        db.execute('BEGIN IMMEDIATE TRANSACTION')  # Exclusive lock
        yield db
        db.execute('COMMIT')
    except Exception as e:
        db.execute('ROLLBACK')
        raise e

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # ... validation code ...
    
    try:
        with get_db_transaction() as db:
            # Lock sender account for update
            sender_account = db.execute(
                'SELECT * FROM accounts WHERE user_id = ? FOR UPDATE',
                (session['user_id'],)
            ).fetchone()
            
            # Re-check balance after lock
            if sender_account['balance'] < amount:
                flash('Insufficient funds.', 'error')
                return render_template('transfer.html')
            
            # Perform atomic updates
            db.execute(
                'UPDATE accounts SET balance = balance - ? WHERE id = ?',
                (amount, sender_account['id'])
            )
            db.execute(
                'UPDATE accounts SET balance = balance + ? WHERE id = ?',
                (amount, recipient['id'])
            )
            
            # Record transaction
            db.execute(
                'INSERT INTO transactions (from_account_id, to_account_id, amount, transaction_type, description) VALUES (?, ?, ?, ?, ?)',
                (sender_account['id'], recipient['id'], amount, 'transfer', description)
            )
            
    except Exception as e:
        app.logger.error(f'Transfer failed: {e}')
        flash('Transfer failed. Please try again.', 'error')
        return render_template('transfer.html')
```

---

## Information Disclosure

### 13. Fix Predictable User IDs and Information Exposure

**Problem:** Sequential user IDs and exposed user information
**Solution:** Use UUIDs and limit information exposure

```python
import uuid
from sqlalchemy.dialects.postgresql import UUID

# Use UUIDs instead of sequential IDs
class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False)
    # ... other fields

# Remove API endpoints that expose user information
# @app.route('/api/user/<user_id>')  # Remove this endpoint

# Limit information in templates
# Remove user ID exposure in JavaScript and HTML
```

**Template Updates:**
```html
<!-- Remove user ID exposure -->
<p>Account Number: {{ account.account_number }}</p>
<!-- Remove: <p><small>User ID: {{ user.id }}</small></p> -->

<!-- Remove JavaScript user exposure -->
<!-- Remove:
<script>
    var userId = {{ session.user_id }};
    var username = "{{ session.username }}";
</script>
-->
```

### 14. Implement CSRF Protection

**Problem:** No CSRF tokens on forms
**Solution:** Add CSRF protection

```python
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Create forms with CSRF protection
class TransferForm(FlaskForm):
    recipient_account = StringField('Recipient Account', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    description = TextAreaField('Description')
    submit = SubmitField('Transfer Money')

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    form = TransferForm()
    
    if form.validate_on_submit():
        # Process form data
        recipient_account = form.recipient_account.data
        amount = form.amount.data
        description = sanitize_html(form.description.data)
        # ... rest of transfer logic
    
    return render_template('transfer.html', form=form)
```

**Template Updates:**
```html
<!-- Add CSRF token to forms -->
<form method="POST">
    {{ form.hidden_tag() }}  <!-- Includes CSRF token -->
    
    <div class="form-group">
        {{ form.recipient_account.label(class="form-label") }}
        {{ form.recipient_account(class="form-control") }}
    </div>
    
    <div class="form-group">
        {{ form.amount.label(class="form-label") }}
        {{ form.amount(class="form-control") }}
    </div>
    
    <div class="form-group">
        {{ form.description.label(class="form-label") }}
        {{ form.description(class="form-control") }}
    </div>
    
    {{ form.submit(class="btn btn-primary") }}
</form>
```

---

## Additional Security Measures

### 15. Implement Security Headers

```python
from flask_talisman import Talisman

# Security headers
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'"
    },
    referrer_policy='strict-origin-when-cross-origin'
)
```

### 16. Input Validation and Sanitization

```python
from wtforms.validators import ValidationError
import re

def validate_account_number(form, field):
    """Custom validator for account numbers"""
    pattern = r'^\d{4}-\d{4}-\d{4}$'
    if not re.match(pattern, field.data):
        raise ValidationError('Invalid account number format')

def validate_amount(form, field):
    """Custom validator for transfer amounts"""
    if field.data <= 0:
        raise ValidationError('Amount must be positive')
    if field.data > 10000:
        raise ValidationError('Amount exceeds daily limit')

class TransferForm(FlaskForm):
    recipient_account = StringField('Recipient Account', 
                                  validators=[DataRequired(), validate_account_number])
    amount = FloatField('Amount', 
                       validators=[DataRequired(), validate_amount])
    description = TextAreaField('Description', 
                               validators=[Length(max=500)])
```

### 17. Logging and Monitoring

```python
import logging
from datetime import datetime

# Security event logging
def log_security_event(event_type, user_id=None, details=None):
    """Log security-related events"""
    security_logger = logging.getLogger('security')
    security_logger.info(f'{datetime.now()}: {event_type} - User: {user_id} - Details: {details}')

# Usage examples
@app.route('/login', methods=['POST'])
def login():
    # ... authentication logic ...
    
    if authentication_failed:
        log_security_event('LOGIN_FAILED', username=username, details=request.remote_addr)
    else:
        log_security_event('LOGIN_SUCCESS', user_id=user.id, details=request.remote_addr)

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # ... transfer logic ...
    
    log_security_event('MONEY_TRANSFER', 
                      user_id=session['user_id'], 
                      details=f'Amount: {amount}, Recipient: {recipient_account}')
```

---

## Summary

Implementing these fixes would transform BadBank from a vulnerable training application into a secure banking platform. Key security principles applied:

1. **Defense in Depth** - Multiple layers of security controls
2. **Principle of Least Privilege** - Users can only access their own data
3. **Input Validation** - All user input is validated and sanitized
4. **Secure by Default** - Secure configurations and safe defaults
5. **Fail Securely** - Errors don't expose sensitive information
6. **Complete Mediation** - All access requests are checked
7. **Security Through Obscurity is Avoided** - No reliance on hidden information

Remember: Security is an ongoing process, not a one-time implementation. Regular security assessments, code reviews, and updates are essential for maintaining a secure application.
