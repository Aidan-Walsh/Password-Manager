import json
import os
import hashlib
from cryptography.fernet import Fernet
import base64
import getpass
import random
import string
import re
import time
from datetime import datetime

class PasswordManager:
    def __init__(self):
        # Create hidden directory for config files
        self.config_dir = ".password_manager"
        self.config_file = os.path.join(self.config_dir, "config.json")
        self.password_file = os.path.join(self.config_dir, "passwords.json")
        self.log_file = os.path.join(self.config_dir, "login_log.json")
        self.settings_file = os.path.join(self.config_dir, "settings.json")
        
        # Ensure the hidden directory exists
        self.ensure_config_directory()
        
        self.setup_complete = self.check_setup()
        self.authenticated = False
        self.encryption_key = None
        self.last_activity_time = time.time()
        
        # Load settings
        self.load_settings()
        
        self.timeout_seconds = self.timeout_minutes * 60
    
    def ensure_config_directory(self):
        """Create the hidden config directory if it doesn't exist"""
        try:
            if not os.path.exists(self.config_dir):
                os.makedirs(self.config_dir)
                # On Unix-like systems, make the directory hidden by setting appropriate permissions
                if os.name != 'nt':  # Not Windows
                    os.chmod(self.config_dir, 0o700)  # Owner read/write/execute only
                print(f"📁 Created hidden config directory: {self.config_dir}")
        except OSError as e:
            print(f"❌ Error creating config directory: {e}")
            raise
    
    def reset_activity_timer(self):
        """Reset the inactivity timer"""
        self.last_activity_time = time.time()
    
    def check_timeout(self):
        """Check if the session has timed out due to inactivity"""
        if not self.authenticated:
            return False
        
        current_time = time.time()
        inactive_time = current_time - self.last_activity_time
        
        if inactive_time >= self.timeout_seconds:
            return True
        return False
    
    def handle_timeout(self):
        """Handle session timeout by logging out the user"""
        self.clear_screen()
        print("=" * 50)
        print("        SESSION TIMEOUT")
        print("=" * 50)
        print(f"\n⏰ You have been automatically logged out due to {self.timeout_minutes} minutes of inactivity.")
        print("This is a security measure to protect your passwords.")
        print("\nPlease authenticate again to continue.")
        input("\nPress Enter to continue...")
        self.logout()
    
    def secure_input(self, prompt):
        """Input function that checks for timeout and resets activity timer"""
        if self.check_timeout():
            self.handle_timeout()
            return None
        
        user_input = input(prompt)
        self.reset_activity_timer()
        return user_input
    
    def secure_getpass(self, prompt):
        """Getpass function that checks for timeout and resets activity timer"""
        if self.check_timeout():
            self.handle_timeout()
            return None
        
        user_input = getpass.getpass(prompt)
        self.reset_activity_timer()
        return user_input
        
    def check_setup(self):
        if not os.path.exists(self.config_file):
            return False
        
        try:
            with open(self.config_file, 'r') as f:
                content = f.read()
            
            if not content.startswith("HASH:"):
                return False
            
            lines = content.split('\n', 1)
            if len(lines) != 2:
                return False
            
            stored_hash = lines[0][5:]  # Remove "HASH:" prefix
            json_content = lines[1]
            
            # Verify hash
            computed_hash = hashlib.sha256(json_content.encode()).hexdigest()
            if stored_hash != computed_hash:
                print("⚠️  Configuration file has been tampered with!")
                return False
            
            # Verify JSON is valid
            json.loads(json_content)
            return True
            
        except (json.JSONDecodeError, IOError):
            return False
    
    def hash_answer(self, answer):
        return hashlib.sha256(answer.lower().strip().encode()).hexdigest()
    
    def generate_key_from_answers(self, answers):
        combined = ''.join(answers).encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(combined).digest())
        return key
    
    def write_secure_file(self, filename, data):
        """Write JSON data to file with integrity hash"""
        json_content = json.dumps(data, indent=2)
        content_hash = hashlib.sha256(json_content.encode()).hexdigest()
        
        with open(filename, 'w') as f:
            f.write(f"HASH:{content_hash}\n{json_content}")
    
    def read_secure_file(self, filename):
        """Read JSON data from file and verify integrity"""
        try:
            with open(filename, 'r') as f:
                content = f.read()
            
            if not content.startswith("HASH:"):
                raise ValueError("Invalid file format")
            
            lines = content.split('\n', 1)
            if len(lines) != 2:
                raise ValueError("Invalid file format")
            
            stored_hash = lines[0][5:]  # Remove "HASH:" prefix
            json_content = lines[1]
            
            # Verify hash
            computed_hash = hashlib.sha256(json_content.encode()).hexdigest()
            if stored_hash != computed_hash:
                raise ValueError("File integrity check failed - file has been tampered with!")
            
            return json.loads(json_content)
            
        except (IOError, json.JSONDecodeError) as e:
            raise ValueError(f"Error reading file: {e}")
    
    def start(self):
        self.clear_screen()
        print("=" * 50)
        print("        PASSWORD MANAGER")
        print("=" * 50)
        
        if not self.setup_complete:
            self.setup_first_time()
        else:
            self.login()
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def setup_first_time(self):
        print("\n🔧 FIRST TIME SETUP")
        print("-" * 30)
        print("Please set up security questions for authentication.")
        print("These will be used to verify your identity.\n")
        
        self.questions = [
            "What was the name of your first pet?",
            "What city were you born in?",
            "What is your mother's maiden name?",
            "What is your Social Security Number?", 
            "What is your date of birth? (MM/DD/YYYY)"
        ]
        
        answers = []
        
        for i, question in enumerate(self.questions):
            while True:
                answer = input(f"{i+1}. {question}: ")
                
                if answer.strip():
                    answers.append(answer)
                    break
                else:
                    print("❌ Please provide an answer.")
        
        self.complete_setup(answers)
    
    def complete_setup(self, answers):
        hashed_answers = [self.hash_answer(answer) for answer in answers]
        
        config = {
            "questions": self.questions,
            "answers": hashed_answers
        }
        
        # Use secure file writing with integrity hash
        self.write_secure_file(self.config_file, config)
        
        self.encryption_key = self.generate_key_from_answers(answers)
        
        # Initialize empty password file with integrity hash
        self.write_secure_file(self.password_file, {})
        
        self.setup_complete = True
        print("\n✅ Setup completed successfully!")
        input("Press Enter to continue...")
        self.login()
    
    def login(self):
        self.clear_screen()
        print("=" * 50)
        print("        PASSWORD MANAGER")
        print("=" * 50)
        print("\n🔐 AUTHENTICATION REQUIRED")
        print("-" * 30)
        print("Please answer your security questions to continue.\n")
        
        try:
            config = self.read_secure_file(self.config_file)
        except ValueError as e:
            print(f"❌ Security error: {e}")
            print("Setup may need to be performed again.")
            input("Press Enter to exit...")
            return
        
        answers = []
        
        for i, question in enumerate(config['questions']):
            while True:
                answer = self.secure_input(f"{i+1}. {question}: ")
                
                if answer is None:  # Timeout occurred
                    return
                
                if answer.strip():
                    answers.append(answer)
                    break
                else:
                    print("❌ Please provide an answer.")
        
        self.authenticate(answers)
    
    def authenticate(self, answers):
        hashed_answers = [self.hash_answer(answer) for answer in answers]
        
        try:
            config = self.read_secure_file(self.config_file)
        except ValueError as e:
            print(f"❌ Security error: {e}")
            input("Press Enter to exit...")
            return
        
        if hashed_answers == config['answers']:
            self.authenticated = True
            self.encryption_key = self.generate_key_from_answers(answers)
            self.reset_activity_timer()  # Reset timer on successful authentication
            
            # Log successful login and get failed attempts count
            failed_attempts_count = self.log_successful_login()
            
            print("\n✅ Authentication successful!")
            
            # Display warning if there were failed attempts since last login
            if failed_attempts_count > 0:
                print(f"\n⚠️  WARNING: {failed_attempts_count} unsuccessful login attempt(s) since last successful login!")
                print("If this wasn't you, your password may be compromised.")
            
            # Migrate existing usernames to encrypted format if needed
            self.migrate_usernames_to_encrypted()
            
            input("Press Enter to continue...")
            self.show_main_menu()
        else:
            # Log failed authentication attempt
            self.log_failed_attempt()
            print("\n❌ Authentication failed! Please try again.")
            input("Press Enter to retry...")
            self.login()
    
    def show_main_menu(self):
        while self.authenticated:
            # Check for timeout before showing menu
            if self.check_timeout():
                self.handle_timeout()
                return
            
            self.clear_screen()
            print("=" * 50)
            print("        PASSWORD MANAGER - MAIN MENU")
            print("=" * 50)
            print("\nPlease select an option:")
            print("1. View All Passwords")
            print("2. View Specific Password")
            print("3. Add/Generate/Update Password")
            print("4. Delete Password")
            print("5. Password Checker")
            print("6. Generate Random Password")
            print("7. Advanced")
            print("8. Logout")
            print("-" * 30)
            
            choice = self.secure_input("Enter your choice (1-8): ")
            if choice is None:  # Timeout occurred
                return
            choice = choice.strip()
            
            if choice == "1":
                self.view_all_passwords()
            elif choice == "2":
                self.view_specific_password()
            elif choice == "3":
                self.add_password()
            elif choice == "4":
                self.delete_password()
            elif choice == "5":
                self.password_checker()
            elif choice == "6":
                self.generate_random_password()
            elif choice == "7":
                self.show_advanced_menu()
            elif choice == "8":
                self.logout()
                break
            else:
                print("\n❌ Invalid choice. Please enter 1-8.")
                input("Press Enter to continue...")
    
    def encrypt_password(self, password):
        f = Fernet(self.encryption_key)
        return f.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_password.encode()).decode()
    
    def encrypt_username(self, username):
        """Encrypt username for secure storage"""
        f = Fernet(self.encryption_key)
        return f.encrypt(username.encode()).decode()
    
    def decrypt_username(self, encrypted_username):
        """Decrypt username for display"""
        try:
            f = Fernet(self.encryption_key)
            return f.decrypt(encrypted_username.encode()).decode()
        except Exception:
            # Handle backwards compatibility - if decryption fails, assume it's plaintext
            return encrypted_username
    
    def is_password_secure(self, password):
        """Check if a password meets security criteria"""
        issues = []
        
        # Check length
        if len(password) < 8:
            issues.append("Too short (less than 8 characters)")
        
        # Check for common patterns
        if password.lower() in ['password', '123456', 'qwerty', 'abc123', 'password123', 'admin', 'letmein']:
            issues.append("Common weak password")
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            issues.append("Contains sequential characters")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            issues.append("Contains repeated characters")
        
        # Check character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        if char_types < 3:
            missing = []
            if not has_lower: missing.append("lowercase letters")
            if not has_upper: missing.append("uppercase letters") 
            if not has_digit: missing.append("numbers")
            if not has_special: missing.append("special characters")
            issues.append(f"Missing character types: {', '.join(missing)}")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', '4321', 'abcd', 'dcba']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                issues.append("Contains keyboard pattern")
                break
        
        return len(issues) == 0, issues
    
    def load_passwords(self):
        try:
            return self.read_secure_file(self.password_file)
        except ValueError as e:
            print(f"❌ Password file integrity error: {e}")
            print("Your password file may have been tampered with!")
            input("Press Enter to continue...")
            return {}
        except:
            return {}
    
    def save_passwords(self, passwords):
        try:
            self.write_secure_file(self.password_file, passwords)
        except Exception as e:
            print(f"❌ Error saving passwords: {e}")
            input("Press Enter to continue...")
    
    def migrate_usernames_to_encrypted(self):
        """Migrate existing plaintext usernames to encrypted format"""
        try:
            passwords = self.load_passwords()
            needs_migration = False
            
            for service, data in passwords.items():
                try:
                    # Try to decrypt the username - if it fails, it's plaintext
                    f = Fernet(self.encryption_key)
                    f.decrypt(data['username'].encode())
                except Exception:
                    # Username is plaintext, needs encryption
                    data['username'] = self.encrypt_username(data['username'])
                    needs_migration = True
            
            if needs_migration:
                self.save_passwords(passwords)
                print("🔄 Migrated existing usernames to encrypted format.")
                
        except Exception as e:
            print(f"❌ Error during username migration: {e}")
    
    def load_login_log(self):
        """Load login attempt log from file"""
        try:
            if os.path.exists(self.log_file):
                return self.read_secure_file(self.log_file)
            else:
                # Initialize empty log structure
                return {
                    "failed_attempts_since_success": 0,
                    "last_successful_login": None,
                    "failed_attempts": []
                }
        except Exception:
            # If log file is corrupted, start fresh
            return {
                "failed_attempts_since_success": 0,
                "last_successful_login": None,
                "failed_attempts": []
            }
    
    def save_login_log(self, log_data):
        """Save login attempt log to file"""
        try:
            self.write_secure_file(self.log_file, log_data)
        except Exception as e:
            print(f"❌ Error saving login log: {e}")
    
    def log_failed_attempt(self):
        """Log a failed login attempt"""
        log_data = self.load_login_log()
        
        # Increment failed attempts counter
        log_data["failed_attempts_since_success"] += 1
        
        # Add detailed failed attempt record
        failed_attempt = {
            "timestamp": datetime.now().isoformat(),
            "attempt_number": log_data["failed_attempts_since_success"]
        }
        
        # Keep only the last N failed attempts based on user settings
        log_data["failed_attempts"].append(failed_attempt)
        if len(log_data["failed_attempts"]) > self.max_login_attempts_tracked:
            log_data["failed_attempts"] = log_data["failed_attempts"][-self.max_login_attempts_tracked:]
        
        self.save_login_log(log_data)
    
    def log_successful_login(self):
        """Log a successful login and get failed attempts count"""
        log_data = self.load_login_log()
        
        # Get the number of failed attempts since last success
        failed_count = log_data["failed_attempts_since_success"]
        
        # Reset failed attempts counter and update last successful login
        log_data["failed_attempts_since_success"] = 0
        log_data["last_successful_login"] = datetime.now().isoformat()
        
        # Keep the failed attempts history but trim to max allowed
        # Don't clear the history - preserve it for viewing
        if len(log_data["failed_attempts"]) > self.max_login_attempts_tracked:
            log_data["failed_attempts"] = log_data["failed_attempts"][-self.max_login_attempts_tracked:]
        
        self.save_login_log(log_data)
        
        return failed_count
    
    def load_settings(self):
        """Load user settings from file"""
        try:
            if os.path.exists(self.settings_file):
                settings = self.read_secure_file(self.settings_file)
            else:
                # Default settings
                settings = {
                    "timeout_minutes": 5,
                    "max_login_attempts_tracked": 10
                }
                self.save_settings(settings)
            
            self.timeout_minutes = settings.get("timeout_minutes", 5)
            self.max_login_attempts_tracked = settings.get("max_login_attempts_tracked", 10)
            
        except Exception:
            # If settings file is corrupted, use defaults
            self.timeout_minutes = 5
            self.max_login_attempts_tracked = 10
    
    def save_settings(self, settings):
        """Save user settings to file"""
        try:
            self.write_secure_file(self.settings_file, settings)
        except Exception as e:
            print(f"❌ Error saving settings: {e}")
    
    def view_all_passwords(self):
        if self.check_timeout():
            self.handle_timeout()
            return
            
        passwords = self.load_passwords()
        
        self.clear_screen()
        print("=" * 50)
        print("        ALL STORED PASSWORDS")
        print("=" * 50)
        
        if not passwords:
            print("\n📝 No passwords stored yet.")
        else:
            print()
            # Sort passwords alphabetically by service name (case insensitive)
            sorted_services = sorted(passwords.items(), key=lambda x: x[0].lower())
            
            for service, data in sorted_services:
                decrypted_password = self.decrypt_password(data['password'])
                decrypted_username = self.decrypt_username(data['username'])
                print(f"🔐 Service: {service}")
                print(f"👤 Username: {decrypted_username}")
                print(f"🔑 Password: {decrypted_password}")
                print("-" * 40)
        
        self.secure_input("\nPress Enter to return to main menu...")
    
    def view_specific_password(self):
        if self.check_timeout():
            self.handle_timeout()
            return
            
        self.clear_screen()
        print("=" * 50)
        print("        VIEW SPECIFIC PASSWORD")
        print("=" * 50)
        
        service = self.secure_input("\nEnter service name: ")
        if service is None:  # Timeout occurred
            return
        service = service.strip()
        if not service:
            return
        
        passwords = self.load_passwords()
        
        while service:
            # Find matching services (case insensitive, partial match)
            matches = []
            search_term = service.lower()
            
            for stored_service, data in passwords.items():
                stored_service_lower = stored_service.lower()
                # Check if search term is contained in the stored service name
                if search_term in stored_service_lower:
                    matches.append((stored_service, data))
            
            if matches:
                if len(matches) == 1:
                    # Single match - display it
                    stored_service, data = matches[0]
                    decrypted_password = self.decrypt_password(data['password'])
                    decrypted_username = self.decrypt_username(data['username'])
                    print(f"\n🔐 Service: {stored_service}")
                    print(f"👤 Username: {decrypted_username}")
                    print(f"🔑 Password: {decrypted_password}")
                else:
                    # Multiple matches - display all
                    print(f"\n🔍 Found {len(matches)} matching services:")
                    for i, (stored_service, data) in enumerate(matches, 1):
                        decrypted_password = self.decrypt_password(data['password'])
                        decrypted_username = self.decrypt_username(data['username'])
                        print(f"\n{i}. 🔐 Service: {stored_service}")
                        print(f"   👤 Username: {decrypted_username}")
                        print(f"   🔑 Password: {decrypted_password}")
                        print("-" * 30)
            else:
                print(f"\n❌ No services found containing '{service}'!")
            
            service = self.secure_input("\nEnter another service name or press Enter to return to main menu: ")
            if service is None:  # Timeout occurred
                return
            service = service.strip()
        
        
    def password_checker(self):
        """Check all stored passwords for security issues"""
        if self.check_timeout():
            self.handle_timeout()
            return
            
        passwords = self.load_passwords()
        
        self.clear_screen()
        print("=" * 50)
        print("        PASSWORD SECURITY CHECKER")
        print("=" * 50)
        
        if not passwords:
            print("\n📝 No passwords stored yet.")
            input("\nPress Enter to return to main menu...")
            return
        
        insecure_passwords = []
        
        for service, data in passwords.items():
            decrypted_password = self.decrypt_password(data['password'])
            decrypted_username = self.decrypt_username(data['username'])
            is_secure, issues = self.is_password_secure(decrypted_password)
            
            if not is_secure:
                insecure_passwords.append({
                    'service': service,
                    'username': decrypted_username,
                    'password': decrypted_password,
                    'issues': issues
                })
        
        if not insecure_passwords:
            print("\n✅ All your passwords are secure! Good job!")
        else:
            print(f"\n⚠️  Found {len(insecure_passwords)} insecure password(s):\n")
            
            for i, entry in enumerate(insecure_passwords, 1):
                print(f"{i}. 🔐 Service: {entry['service']}")
                print(f"   👤 Username: {entry['username']}")
                print(f"   🔑 Password: {entry['password']}")
                print(f"   ❌ Issues:")
                for issue in entry['issues']:
                    print(f"      • {issue}")
                print("-" * 40)
        
        input("\nPress Enter to return to main menu...")
    
    def generate_random_password(self):
        """Generate a random password with user-specified criteria"""
        if self.check_timeout():
            self.handle_timeout()
            return
            
        self.clear_screen()
        print("=" * 50)
        print("        RANDOM PASSWORD GENERATOR")
        print("=" * 50)
        
        # Get password length
        while True:
            try:
                length = int(input("\nEnter desired password length (8-128): "))
                if 8 <= length <= 128:
                    break
                else:
                    print("❌ Length must be between 8 and 128 characters.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Get number of uppercase letters
        while True:
            try:
                uppercase_count = int(input(f"Number of uppercase letters (0-{length}): "))
                if 0 <= uppercase_count <= length:
                    break
                else:
                    print(f"❌ Must be between 0 and {length}.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Get number of lowercase letters
        remaining = length - uppercase_count
        while True:
            try:
                lowercase_count = int(input(f"Number of lowercase letters (0-{remaining}): "))
                if 0 <= lowercase_count <= remaining:
                    break
                else:
                    print(f"❌ Must be between 0 and {remaining}.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Get number of digits
        remaining = length - uppercase_count - lowercase_count
        while True:
            try:
                digit_count = int(input(f"Number of digits (0-{remaining}): "))
                if 0 <= digit_count <= remaining:
                    break
                else:
                    print(f"❌ Must be between 0 and {remaining}.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Get number of special characters
        remaining = length - uppercase_count - lowercase_count - digit_count
        while True:
            try:
                special_count = int(input(f"Number of special characters (0-{remaining}): "))
                if 0 <= special_count <= remaining:
                    break
                else:
                    print(f"❌ Must be between 0 and {remaining}.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Check if all characters are accounted for
        total_specified = uppercase_count + lowercase_count + digit_count + special_count
        if total_specified > length:
            print("❌ Total specified characters exceed password length!")
            input("Press Enter to try again...")
            return self.generate_random_password()
        
        # Fill remaining slots with random character types if needed
        remaining_slots = length - total_specified
        if remaining_slots > 0:
            print(f"\n📝 {remaining_slots} remaining characters will be filled with random character types.")
        
        # Generate password
        password_chars = []
        
        # Add specified character types
        if uppercase_count > 0:
            password_chars.extend(random.choices(string.ascii_uppercase, k=uppercase_count))
        if lowercase_count > 0:
            password_chars.extend(random.choices(string.ascii_lowercase, k=lowercase_count))
        if digit_count > 0:
            password_chars.extend(random.choices(string.digits, k=digit_count))
        if special_count > 0:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            password_chars.extend(random.choices(special_chars, k=special_count))
        
        # Fill remaining slots with random mix
        if remaining_slots > 0:
            all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            password_chars.extend(random.choices(all_chars, k=remaining_slots))
        
        # Shuffle the password to avoid predictable patterns
        random.shuffle(password_chars)
        generated_password = ''.join(password_chars)
        
        # Display results
        print("\n" + "=" * 50)
        print("        GENERATED PASSWORD")
        print("=" * 50)
        print(f"\n🔑 Generated Password: {generated_password}")
        print(f"📏 Length: {len(generated_password)} characters")
        
        # Show character breakdown
        actual_upper = sum(1 for c in generated_password if c.isupper())
        actual_lower = sum(1 for c in generated_password if c.islower())
        actual_digits = sum(1 for c in generated_password if c.isdigit())
        actual_special = sum(1 for c in generated_password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?")
        
        print(f"\n📊 Character Breakdown:")
        print(f"   • Uppercase letters: {actual_upper}")
        print(f"   • Lowercase letters: {actual_lower}")
        print(f"   • Digits: {actual_digits}")
        print(f"   • Special characters: {actual_special}")
        
        # Check security
        is_secure, issues = self.is_password_secure(generated_password)
        if is_secure:
            print("\n✅ This password meets security requirements!")
        else:
            print("\n⚠️  Security issues with this password:")
            for issue in issues:
                print(f"   • {issue}")
        
        # Ask if user wants to save this password
        save_option = input("\nWould you like to save this password to a service? (y/N): ").strip().lower()
        if save_option == 'y':
            service = input("Enter service name: ").strip()
            if service:
                username = input("Enter username: ").strip()
                if username:
                    passwords = self.load_passwords()
                    
                    # Check for existing service (case insensitive)
                    existing_service_key = None
                    for existing_service in passwords.keys():
                        if existing_service.lower() == service.lower():
                            existing_service_key = existing_service
                            break
                    
                    if existing_service_key:
                        overwrite = input(f"⚠️  Service '{existing_service_key}' already exists. Overwrite? (y/N): ").strip().lower()
                        if overwrite != 'y':
                            print("❌ Operation cancelled.")
                            input("Press Enter to continue...")
                            return
                        # Remove the old entry so we can add the new one with the user's preferred casing
                        del passwords[existing_service_key]
                    
                    encrypted_password = self.encrypt_password(generated_password)
                    encrypted_username = self.encrypt_username(username)
                    passwords[service] = {
                        'username': encrypted_username,
                        'password': encrypted_password
                    }
                    
                    self.save_passwords(passwords)
                    print(f"\n✅ Password saved for '{service}'!")
        
        input("\nPress Enter to return to main menu...")
    
    def add_password(self):
        self.clear_screen()
        print("=" * 50)
        print("        ADD NEW PASSWORD")
        print("=" * 50)
        
        service = input("\nEnter service name: ").strip()
        if not service:
            print("❌ Service name cannot be empty.")
            input("Press Enter to continue...")
            return
        
        username = input("Enter username: ").strip()
        if not username:
            print("❌ Username cannot be empty.")
            input("Press Enter to continue...")
            return
        
        password = input("Enter password: (leave blank to generate a random password) ")
        if not password:
            password = ''.join(random.choices(string.ascii_letters + string.digits + "!_?*@#$%^&()", k=12))
            print(f"🔑 Generated password: {password}")
        
        passwords = self.load_passwords()
        
        # Check for existing service (case insensitive)
        existing_service_key = None
        for existing_service in passwords.keys():
            if existing_service.lower() == service.lower():
                existing_service_key = existing_service
                break
        
        if existing_service_key:
            overwrite = input(f"⚠️  Service '{existing_service_key}' already exists. Overwrite? (y/N): ").strip().lower()
            if overwrite != 'y':
                print("❌ Operation cancelled.")
                input("Press Enter to continue...")
                return
            # Remove the old entry so we can add the new one with the user's preferred casing
            del passwords[existing_service_key]
        
        encrypted_password = self.encrypt_password(password)
        encrypted_username = self.encrypt_username(username)
        passwords[service] = {
            'username': encrypted_username,
            'password': encrypted_password
        }
        
        self.save_passwords(passwords)
        print(f"\n✅ Password for '{service}' added successfully!")
        input("Press Enter to continue...")
    
    def delete_password(self):
        self.clear_screen()
        print("=" * 50)
        print("        DELETE PASSWORD")
        print("=" * 50)
        
        service = input("\nEnter service name to delete: ").strip()
        if not service:
            return
        
        passwords = self.load_passwords()
        passwords_lower = {k.lower(): v for k, v in passwords.items()}
        if service.lower() in passwords_lower:
            confirm = input(f"⚠️  Are you sure you want to delete the password for '{service}'? (y/N): ").strip().lower()
            if confirm == 'y':
                del passwords[service]
                self.save_passwords(passwords)
                print(f"\n✅ Password for '{service}' deleted successfully!")
            else:
                print("❌ Operation cancelled.")
        else:
            print(f"\n❌ Service '{service}' not found!")
        
        input("Press Enter to continue...")
    
    def logout(self):
        self.authenticated = False
        self.encryption_key = None
        print("\n👋 Logged out successfully!")
        input("Press Enter to continue...")
    
    def show_advanced_menu(self):
        """Show advanced options menu"""
        if self.check_timeout():
            self.handle_timeout()
            return
        
        while self.authenticated:
            if self.check_timeout():
                self.handle_timeout()
                return
                
            self.clear_screen()
            print("=" * 50)
            print("        ADVANCED OPTIONS")
            print("=" * 50)
            print("\nPlease select an option:")
            print("1. Update Settings")
            print("2. View Login Logs")
            print("3. Back to Main Menu")
            print("-" * 30)
            
            choice = self.secure_input("Enter your choice (1-3): ")
            if choice is None:  # Timeout occurred
                return
            choice = choice.strip()
            
            if choice == "1":
                self.update_settings()
            elif choice == "2":
                self.view_login_logs()
            elif choice == "3":
                return
            else:
                print("\n❌ Invalid choice. Please enter 1-3.")
                input("Press Enter to continue...")
    
    def update_settings(self):
        """Allow user to update application settings"""
        if self.check_timeout():
            self.handle_timeout()
            return
            
        self.clear_screen()
        print("=" * 50)
        print("        UPDATE SETTINGS")
        print("=" * 50)
        print(f"\nCurrent Settings:")
        print(f"• Timeout: {self.timeout_minutes} minutes")
        print(f"• Max login attempts tracked: {self.max_login_attempts_tracked}")
        print()
        
        # Update timeout
        while True:
            timeout_input = self.secure_input("Enter new timeout in minutes (1-60) or press Enter to keep current: ")
            if timeout_input is None:  # Timeout occurred
                return
            
            if timeout_input.strip() == "":
                break
            
            try:
                new_timeout = int(timeout_input)
                if 1 <= new_timeout <= 60:
                    self.timeout_minutes = new_timeout
                    self.timeout_seconds = self.timeout_minutes * 60
                    break
                else:
                    print("❌ Timeout must be between 1 and 60 minutes.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Update max login attempts
        while True:
            attempts_input = self.secure_input("Enter max login attempts to track (1-1000) or press Enter to keep current: ")
            if attempts_input is None:  # Timeout occurred
                return
            
            if attempts_input.strip() == "":
                break
            
            try:
                new_max_attempts = int(attempts_input)
                if 1 <= new_max_attempts <= 1000:
                    self.max_login_attempts_tracked = new_max_attempts
                    break
                else:
                    print("❌ Max attempts must be between 1 and 1000.")
            except ValueError:
                print("❌ Please enter a valid number.")
        
        # Save settings
        settings = {
            "timeout_minutes": self.timeout_minutes,
            "max_login_attempts_tracked": self.max_login_attempts_tracked
        }
        self.save_settings(settings)
        
        print(f"\n✅ Settings updated successfully!")
        print(f"• New timeout: {self.timeout_minutes} minutes")
        print(f"• New max login attempts tracked: {self.max_login_attempts_tracked}")
        input("\nPress Enter to continue...")
    
    def view_login_logs(self):
        """View login logs with pagination"""
        if self.check_timeout():
            self.handle_timeout()
            return
            
        self.clear_screen()
        print("=" * 50)
        print("        LOGIN LOGS")
        print("=" * 50)
        
        log_data = self.load_login_log()
        failed_attempts = log_data.get("failed_attempts", [])
        last_success = log_data.get("last_successful_login")
        
        failed_since_success = log_data.get('failed_attempts_since_success', 0)
        print(f"\nFailed attempts since last successful login: {failed_since_success}")
        if last_success:
            try:
                last_success_dt = datetime.fromisoformat(last_success)
                print(f"Last successful login: {last_success_dt.strftime('%Y-%m-%d %H:%M:%S')}")
            except:
                print(f"Last successful login: {last_success}")
        else:
            print("Last successful login: Never")
        
        if not failed_attempts:
            print("\n📝 No failed login attempts recorded.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nShowing login attempt history (Total: {len(failed_attempts)})")
        if failed_since_success > 0:
            print(f"📊 Most recent {failed_since_success} attempts occurred since last successful login")
        print("\nLegend: 🔴 = Since last successful login, ⚪ = Historical")
        print("=" * 50)
        
        # Paginate logs - 10 at a time
        page_size = 10
        current_page = 0
        total_pages = (len(failed_attempts) + page_size - 1) // page_size
        
        while current_page < total_pages:
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, len(failed_attempts))
            
            print(f"\nPage {current_page + 1} of {total_pages}")
            print("-" * 30)
            
            for i in range(start_idx, end_idx):
                attempt = failed_attempts[i]
                try:
                    timestamp_dt = datetime.fromisoformat(attempt['timestamp'])
                    formatted_time = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    formatted_time = attempt['timestamp']
                
                # Mark recent failed attempts (since last successful login)
                total_attempts = len(failed_attempts)
                recent_start_index = total_attempts - failed_since_success
                is_recent = i >= recent_start_index
                marker = "🔴" if is_recent else "⚪"
                
                print(f"{i + 1:2d}. {marker} Attempt #{attempt['attempt_number']} - {formatted_time}")
            
            if current_page < total_pages - 1:
                print(f"\nPress SPACEBAR for next page, 'c' to continue to end, or ENTER to return to menu...")
                user_input = input().strip().lower()
                
                if user_input == 'c':
                    # Show remaining pages quickly
                    for page in range(current_page + 1, total_pages):
                        start_idx = page * page_size
                        end_idx = min(start_idx + page_size, len(failed_attempts))
                        
                        print(f"\nPage {page + 1} of {total_pages}")
                        print("-" * 30)
                        
                        for i in range(start_idx, end_idx):
                            attempt = failed_attempts[i]
                            try:
                                timestamp_dt = datetime.fromisoformat(attempt['timestamp'])
                                formatted_time = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                formatted_time = attempt['timestamp']
                            
                            # Mark recent failed attempts (since last successful login)
                            total_attempts = len(failed_attempts)
                            recent_start_index = total_attempts - failed_since_success
                            is_recent = i >= recent_start_index
                            marker = "🔴" if is_recent else "⚪"
                            
                            print(f"{i + 1:2d}. {marker} Attempt #{attempt['attempt_number']} - {formatted_time}")
                    break
                elif user_input == '':
                    break
                else:
                    current_page += 1
            else:
                current_page += 1
        
        input("\nPress Enter to continue...")
    
    def run(self):
        self.start()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()