# BadBank - Intentionally Vulnerable Banking Application

⚠️ **SECURITY WARNING: This application is INTENTIONALLY VULNERABLE and should NEVER be deployed in a production environment or exposed to the internet. It is designed solely for educational purposes and security training.**

## Overview

BadBank is a deliberately insecure web application that simulates an online banking platform. It contains multiple security vulnerabilities commonly found in web applications, making it an excellent tool for:

- Security training and education
- Penetration testing practice
- Vulnerability assessment learning
- Secure coding awareness
- OWASP Top 10 demonstration

## Vulnerabilities Included

BadBank contains **16+ intentional vulnerabilities** covering all OWASP Top 10 2021 categories:

- **SQL Injection** - Authentication bypass and data extraction
- **Cross-Site Scripting (XSS)** - Stored, reflected, and DOM-based
- **Insecure Direct Object References (IDOR)** - Unauthorized access to resources
- **Cross-Site Request Forgery (CSRF)** - Unauthorized actions
- **Business Logic Flaws** - Negative balances, race conditions
- **Authentication Issues** - Plaintext passwords, no rate limiting
- **Security Misconfigurations** - Debug mode, CORS issues
- **Information Disclosure** - Error messages, predictable IDs

For detailed vulnerability descriptions, see [VULNERABILITIES.md](VULNERABILITIES.md).

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Frontend**: HTML/CSS with minimal JavaScript
- **Authentication**: Session cookies (insecure implementation)

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Installation & Setup

### 1. Clone or Download the Project

```bash
git clone <repository-url>
cd badbank
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv badbank-env

# Activate virtual environment
# On Windows:
badbank-env\Scripts\activate

# On macOS/Linux:
source badbank-env/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize Database

The SQLite database will be automatically created when you first run the application.

### 5. Run the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

## Default Users and Credentials

BadBank comes with three pre-configured test accounts:

| Username | Password    | User ID | Account Number    | Initial Balance |
|----------|-------------|---------|-------------------|-----------------|
| alice    | password123 | 1       | 1001-2001-3001   | $5,000.00       |
| bob      | password123 | 2       | 1001-2002-3002   | $3,500.00       |
| charlie  | password123 | 3       | 1001-2003-3003   | $7,500.00       |

**Note**: Passwords are stored in plaintext (intentional vulnerability).

## Usage Instructions

### Basic Navigation

1. **Home Page** (`/`) - Application overview and navigation
2. **Registration** (`/register`) - Create new user accounts
3. **Login** (`/login`) - Authenticate with existing credentials
4. **Dashboard** (`/dashboard`) - View account balance and recent transactions
5. **Transfer Money** (`/transfer`) - Send money between accounts
6. **Transaction History** (`/transactions`) - View all transactions
7. **Profile** (`/profile`) - Update user information
8. **Password Reset** (`/reset-password`) - Reset forgotten passwords

### Testing Vulnerabilities

#### SQL Injection
```
Username: admin' OR '1'='1' --
Password: anything
```

#### XSS in Transaction Descriptions
```
Description: <script>alert('XSS')</script>
```

#### IDOR in Transfers
- Modify the hidden `sender_user_id` field in transfer forms
- Access other users' transactions: `/transactions?user_id=2`

#### Reflected XSS
```
/reset-password?message=<script>alert('XSS')</script>
```

For complete exploitation examples, see [EXPLOITS.md](EXPLOITS.md).

## Project Structure

```
badbank/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── VULNERABILITIES.md    # Detailed vulnerability descriptions
├── EXPLOITS.md          # Exploitation examples and PoCs
├── FIXES.md             # Security mitigation strategies
├── database/
│   └── init.sql          # Database schema and seed data
├── static/
│   ├── css/
│   │   └── style.css     # Application styles
│   └── js/
│       └── main.js       # Client-side JavaScript (vulnerable)
└── templates/
    ├── base.html         # Base template
    ├── index.html        # Home page
    ├── login.html        # Login form
    ├── register.html     # Registration form
    ├── dashboard.html    # User dashboard
    ├── transfer.html     # Money transfer form
    ├── transactions.html # Transaction history
    ├── profile.html      # User profile
    └── reset_password.html # Password reset form
```

## API Endpoints

BadBank exposes several API endpoints for testing:

- `GET /api/user/<id>` - Retrieve user information (IDOR vulnerability)
- `GET /api/search?q=<query>` - Search functionality (XSS vulnerability)

## Security Testing Tools

Recommended tools for testing BadBank:

- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Automated vulnerability scanning
- **SQLMap** - SQL injection testing
- **curl** - Command-line HTTP testing
- **Browser Developer Tools** - Client-side testing

## Educational Resources

### Documentation
- [VULNERABILITIES.md](VULNERABILITIES.md) - Detailed vulnerability analysis
- [EXPLOITS.md](EXPLOITS.md) - Step-by-step exploitation guide
- [FIXES.md](FIXES.md) - Secure coding solutions

### Learning Objectives
After using BadBank, learners should understand:

1. **Common Web Vulnerabilities** - How they occur and their impact
2. **Attack Techniques** - Practical exploitation methods
3. **Security Testing** - How to identify vulnerabilities
4. **Secure Coding** - How to prevent vulnerabilities
5. **Risk Assessment** - Understanding business impact

## Troubleshooting

### Common Issues

**Database Errors**
```bash
# Delete existing database and restart
rm badbank.db
python app.py
```

**Port Already in Use**
```bash
# Change port in app.py or kill existing process
lsof -ti:5000 | xargs kill -9  # macOS/Linux
netstat -ano | findstr :5000   # Windows
```

**Module Import Errors**
```bash
# Ensure virtual environment is activated and dependencies installed
pip install -r requirements.txt
```

## Legal and Ethical Considerations

### ⚠️ IMPORTANT DISCLAIMERS

1. **Educational Use Only** - BadBank is designed exclusively for educational purposes
2. **No Production Use** - Never deploy this application in a production environment
3. **Authorized Testing Only** - Only test against your own installations
4. **Legal Compliance** - Ensure all testing complies with local laws and regulations
5. **Responsible Disclosure** - If you find additional vulnerabilities, report them responsibly

### Acceptable Use

✅ **Allowed:**
- Educational training and learning
- Security awareness demonstrations
- Penetration testing practice on your own systems
- Academic research and coursework
- Security tool development and testing

❌ **Prohibited:**
- Testing against systems you don't own
- Unauthorized access to any systems
- Malicious use of discovered techniques
- Production deployment
- Sharing credentials or access with unauthorized parties

## Contributing

If you discover additional vulnerabilities or have suggestions for improvement:

1. Document the vulnerability thoroughly
2. Provide proof-of-concept code
3. Explain the educational value
4. Submit via appropriate channels

## Support and Community

For questions, issues, or discussions about BadBank:

- Check existing documentation first
- Review the troubleshooting section
- Ensure you're using BadBank for authorized educational purposes

## License

This project is released for educational purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations.

---

**Remember: The goal of BadBank is to learn about security vulnerabilities in a safe, controlled environment. Always practice responsible disclosure and ethical security testing.**