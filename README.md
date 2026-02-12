# Password Manager

A secure, terminal-based password manager built in Python. Store, retrieve, and manage your passwords locally with encryption, security question authentication, and session timeout protection.

## Features

- **Encrypted Storage** - Passwords and usernames are encrypted using Fernet symmetric encryption (AES-128-CBC)
- **Security Question Authentication** - Five security questions protect access to your vault
- **Password Generator** - Generate random passwords with customizable length and character composition
- **Password Security Checker** - Audit stored passwords for weaknesses (short length, common patterns, missing character types)
- **Fuzzy Search** - Find passwords by partial, case-insensitive service name matching
- **Session Timeout** - Automatic logout after configurable inactivity period
- **Login Attempt Logging** - Tracks failed login attempts and warns on successful login if unauthorized access was attempted
- **File Integrity Verification** - SHA-256 hashes protect config and password files from tampering
- **Configurable Settings** - Adjust timeout duration and login log retention

## Installation

### Automatic Download

[Click here to automatically download the application](https://download-directory.github.io/?url=https%3A%2F%2Fgithub.com%2FAidan-Walsh%2FPassword-Manager)

### Manual Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Aidan-Walsh/Password-Manager.git
   cd Password-Manager
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python password.py
   ```

## Usage

On first launch, you will be prompted to set up five security questions. These answers are used both to authenticate you and to derive the encryption key for your stored data.

Once authenticated, the main menu provides the following options:

1. **View All Passwords** - List every stored service with its username and password
2. **View Specific Password** - Search for a service by name
3. **Add/Generate/Update Password** - Store a new password or auto-generate one
4. **Delete Password** - Remove a stored entry
5. **Password Checker** - Scan all passwords for security issues
6. **Generate Random Password** - Create a password with specific character requirements
7. **Advanced** - Update settings or view login attempt logs
8. **Logout** - End the current session

## Requirements

- Python 3
- `cryptography` library
