import os
import base64
import hashlib
import getpass
import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet

class SecureCredentialManager:
    def __init__(self):
        self.env_file = '.env'
    
    def _derive_key(self, password):
        """Derive encryption key from user password"""
        # Use PBKDF2 to derive a strong key from the password
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'blog_admin_salt', 100000)
        return base64.urlsafe_b64encode(key)
    
    def encrypt_credentials(self, ftp_password, user_password):
        """Encrypt FTP password with user's chosen password"""
        key = self._derive_key(user_password)
        f = Fernet(key)
        encrypted = f.encrypt(ftp_password.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_credentials(self, encrypted_password, user_password):
        """Decrypt FTP password using user's password"""
        try:
            key = self._derive_key(user_password)
            f = Fernet(key)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
            return f.decrypt(encrypted_bytes).decode()
        except Exception:
            return None  # Wrong password or corrupted data
    
    def setup_credentials(self):
        """Interactive setup for encrypted credentials"""
        print("🔐 Secure FTP Credential Setup")
        print("=" * 40)
        
        # Get FTP details
        server = input("FTP Server: ").strip()
        username = input("FTP Username: ").strip()
        ftp_password = getpass.getpass("FTP Password: ")
        path = input("FTP Path (default /public_html/): ").strip() or "/public_html/"
        
        if not all([server, username, ftp_password]):
            print("❌ All fields required!")
            return False
        
        # Get user's encryption password
        print("\nChoose a password to protect your FTP credentials:")
        print("(This password will be required each time you upload/download)")
        
        while True:
            encrypt_password = getpass.getpass("Encryption Password: ")
            confirm_password = getpass.getpass("Confirm Password: ")
            
            if encrypt_password == confirm_password:
                break
            print("❌ Passwords don't match. Try again.")
        
        # Encrypt the FTP password
        encrypted_ftp_password = self.encrypt_credentials(ftp_password, encrypt_password)
        
        # Create .env file
        env_content = f"""# FTP Configuration (password encrypted with your chosen password)
FTP_SERVER={server}
FTP_USERNAME={username}
FTP_PASSWORD_PROTECTED={encrypted_ftp_password}
FTP_PATH={path}
"""
        
        with open(self.env_file, 'w') as f:
            f.write(env_content)
        
        print("\n✅ Setup complete!")
        print("\n📁 Created .env file with encrypted credentials")
        print("⚠️  Remember your encryption password - you'll need it to upload/download")
        print("✅ The .env file is now safe to share publicly")
        
        return True

class SecureBlogCredentials:
    """Add this to your blog admin app"""
    
    def __init__(self):
        self.credential_manager = SecureCredentialManager()
        self._cached_password = None  # Cache during session
    
    def get_ftp_credentials(self):
        """Get FTP credentials with password protection"""
        server = os.getenv('FTP_SERVER')
        username = os.getenv('FTP_USERNAME')
        path = os.getenv('FTP_PATH', '/public_html/')
        encrypted_password = os.getenv('FTP_PASSWORD_PROTECTED')
        
        if not all([server, username, encrypted_password]):
            messagebox.showerror("Error", 
                "Missing FTP configuration. Please run setup first.")
            return None, None, None, None
        
        # Use cached password if available
        if self._cached_password:
            ftp_password = self.credential_manager.decrypt_credentials(
                encrypted_password, self._cached_password)
            if ftp_password:
                return server, username, ftp_password, path
        
        # Prompt for encryption password
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        user_password = simpledialog.askstring(
            "Encryption Password", 
            "Enter your encryption password:",
            show='*'
        )
        
        if not user_password:
            return None, None, None, None
        
        # Try to decrypt
        ftp_password = self.credential_manager.decrypt_credentials(
            encrypted_password, user_password)
        
        if not ftp_password:
            messagebox.showerror("Error", "Wrong encryption password!")
            return None, None, None, None
        
        # Cache password for this session
        self._cached_password = user_password
        
        return server, username, ftp_password, path
    
    def clear_cached_password(self):
        """Clear cached password (for security)"""
        self._cached_password = None

# Setup script
def main():
    """Run this once to set up encrypted credentials"""
    manager = SecureCredentialManager()
    manager.setup_credentials()

if __name__ == "__main__":
    main()
