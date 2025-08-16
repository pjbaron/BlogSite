import sys
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import ftplib
import json
import os
import glob
import threading
from datetime import datetime
from dotenv import load_dotenv
import base64
import hashlib
from cryptography.fernet import Fernet
import traceback

def save_json_simple(data, filepath):
    """Save JSON data to file - guaranteed to work or tell you why it doesn't"""
    try:
        # Make sure directory exists
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        
        # Write the file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Verify it was written
        if not os.path.exists(filepath):
            raise Exception("File was not created")
        
        # Verify content
        with open(filepath, 'r', encoding='utf-8') as f:
            test_data = json.load(f)
        
        return True, f"Success: {len(str(data))} chars written to {filepath}"
        
    except Exception as e:
        return False, f"Failed: {str(e)}"

def show_exception_dialog(exc_type, exc_value, exc_traceback):
    """Show a dialog with exception details"""
    # Format the exception
    error_msg = f"Exception Type: {exc_type.__name__}\n"
    error_msg += f"Error Message: {str(exc_value)}\n\n"
    error_msg += "Full Traceback:\n"
    error_msg += "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    
    # Create a root window if one doesn't exist
    try:
        root = tk._default_root
        if root is None:
            root = tk.Tk()
            root.withdraw()  # Hide the main window
    except:
        root = tk.Tk()
        root.withdraw()
    
    # Create error dialog
    error_window = tk.Toplevel(root)
    error_window.title("Application Error")
    error_window.geometry("800x600")
    error_window.grab_set()
    
    # Center the window
    error_window.update_idletasks()
    x = (error_window.winfo_screenwidth() // 2) - (800 // 2)
    y = (error_window.winfo_screenheight() // 2) - (600 // 2)
    error_window.geometry(f"800x600+{x}+{y}")
    
    # Add content
    main_frame = ttk.Frame(error_window, padding="20")
    main_frame.pack(fill='both', expand=True)
    
    ttk.Label(main_frame, text="An unexpected error occurred:", font=("Arial", 12, "bold")).pack(anchor='w', pady=(0, 10))
    
    # Text widget with scrollbar
    text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Consolas", 10))
    text_widget.pack(fill='both', expand=True, pady=(0, 10))
    text_widget.insert('1.0', error_msg)
    text_widget.config(state='disabled')
    
    # Buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(fill='x', pady=(10, 0))
    
    def copy_to_clipboard():
        error_window.clipboard_clear()
        error_window.clipboard_append(error_msg)
        messagebox.showinfo("Copied", "Error details copied to clipboard")
    
    def save_to_file():
        try:
            # Default to executable directory or current directory
            if getattr(sys, 'frozen', False):
                default_dir = os.path.dirname(sys.executable)
            else:
                default_dir = os.getcwd()
            
            filename = f"error_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join(default_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(error_msg)
            
            messagebox.showinfo("Saved", f"Error log saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not save error log: {e}")
    
    def close_app():
        error_window.destroy()
        if root:
            root.quit()
    
    ttk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard).pack(side='left', padx=(0, 10))
    ttk.Button(button_frame, text="Save to File", command=save_to_file).pack(side='left', padx=(0, 10))
    ttk.Button(button_frame, text="Close Application", command=close_app).pack(side='right')
    
    # Make sure the window stays on top and is modal
    error_window.transient(root)
    error_window.focus_force()
    error_window.mainloop()

def custom_exception_handler(exc_type, exc_value, exc_traceback):
    """Custom exception handler that shows GUI dialog"""
    # Don't catch KeyboardInterrupt
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    # Show the exception dialog
    show_exception_dialog(exc_type, exc_value, exc_traceback)


def get_application_path():
    """Get the directory where the application is located"""
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller bundle - use the directory containing the .exe
        application_path = os.path.dirname(sys.executable)
    else:
        # Running as script
        application_path = os.path.dirname(os.path.abspath(__file__))
    return application_path


def get_data_directory():
    """Get a writable data directory for the application"""
    if getattr(sys, 'frozen', False):
        # For PyInstaller executable, use the same directory as the .exe
        # or a subdirectory that's guaranteed to be writable
        exe_dir = os.path.dirname(sys.executable)
        
        # Try to use the exe directory first
        if os.access(exe_dir, os.W_OK):
            return exe_dir
        
        # If exe directory isn't writable, use user's documents or AppData
        import tempfile
        user_dir = os.path.expanduser("~")
        app_data_dir = os.path.join(user_dir, "SimpleBlogAdmin")
        os.makedirs(app_data_dir, exist_ok=True)
        return app_data_dir
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))


class SimpleBlogAdmin:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Blog Admin v0.1")
        self.root.geometry("600x700")
        
        # Load environment variables
        load_dotenv()
        
        # Get the actual application directory and data directory
        app_dir = get_application_path()
        data_dir = get_data_directory()
        
        # Define base paths for your specific folder structure
        # First, try the expected structure relative to executable
        if getattr(sys, 'frozen', False):
            # Running as PyInstaller executable
            # app_dir is ./project/tools/, so go up one level to ./project/
            project_dir = os.path.dirname(app_dir)
            potential_site_content = os.path.join(project_dir, "site-content")
            
            # If that doesn't exist, try relative to working directory
            if not os.path.exists(potential_site_content):
                potential_site_content = os.path.join(os.getcwd(), "site-content")
                
                # If still not found, try going up from working directory
                if not os.path.exists(potential_site_content):
                    potential_site_content = os.path.join(os.path.dirname(os.getcwd()), "site-content")
                    
                    # If still not found, create in writable location
                    if not os.path.exists(potential_site_content):
                        potential_site_content = os.path.join(data_dir, "site-content")
            
            self.site_content_dir = potential_site_content
        else:
            # Running as script - assume same structure
            project_dir = os.path.dirname(app_dir)
            self.site_content_dir = os.path.join(project_dir, "site-content")

        # Ensure the site-content directory exists and is writable
        try:
            os.makedirs(self.site_content_dir, exist_ok=True)
            # Test write permission
            test_file = os.path.join(self.site_content_dir, ".write_test")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            # Fall back to data directory
            self.site_content_dir = os.path.join(data_dir, "site-content")
            os.makedirs(self.site_content_dir, exist_ok=True)
        
        self.posts_dir = os.path.join(self.site_content_dir, "posts")
        self.images_dir = os.path.join(self.site_content_dir, "images")
        self.fonts_dir = os.path.join(self.site_content_dir, "fonts")
        self.posts_index_file = os.path.join(self.site_content_dir, "posts-index.json")
        self.index_html_file = os.path.join(self.site_content_dir, "index.html")
        self.styles_css_file = os.path.join(self.site_content_dir, "styles.css")
        
        # Backups should definitely be in a writable location
        self.backups_dir = os.path.join(data_dir, "backups")
        
        # Convert to absolute paths to avoid any ambiguity
        self.site_content_dir = os.path.abspath(self.site_content_dir)
        self.posts_dir = os.path.abspath(self.posts_dir)
        self.images_dir = os.path.abspath(self.images_dir)
        self.fonts_dir = os.path.abspath(self.fonts_dir)
        self.posts_index_file = os.path.abspath(self.posts_index_file)
        self.index_html_file = os.path.abspath(self.index_html_file)
        self.styles_css_file = os.path.abspath(self.styles_css_file)
        self.backups_dir = os.path.abspath(self.backups_dir)
        
        # Debug info (will be shown in error messages if needed)
        self.debug_info = {
            'project_dir': project_dir,
            'app_dir': app_dir,
            'data_dir': data_dir,
            'working_dir': os.getcwd(),
            'frozen': getattr(sys, 'frozen', False),
            'executable': sys.executable,
            'site_content_dir': self.site_content_dir,
            'site_content_writable': os.access(self.site_content_dir, os.W_OK),
            'site_content_exists': os.path.exists(self.site_content_dir)
        }
        
        # Rest of your existing __init__ code...
        self.posts_data = {"stickyPosts": [], "latestPosts": []}
        self._cached_unlock_password = None
        
        self.create_widgets()
        self.load_posts_if_exists()
        
        # Create necessary directories with error handling
        try:
            os.makedirs(self.posts_dir, exist_ok=True)
            os.makedirs(self.backups_dir, exist_ok=True)
            os.makedirs(self.images_dir, exist_ok=True)
            os.makedirs(self.fonts_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Directory Error", 
                f"Failed to create directories: {str(e)}\n\n"
                f"site-content dir: {self.site_content_dir}\n"
                f"Writable: {os.access(os.path.dirname(self.site_content_dir), os.W_OK)}")
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Progress section at top
        progress_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        progress_frame.pack(fill='x', pady=(0, 20))
        
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack()
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.pack(fill='x', pady=(10, 0))
        
        # Posts list
        posts_frame = ttk.LabelFrame(main_frame, text="Posts", padding="10")
        posts_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        self.posts_listbox = tk.Listbox(posts_frame, height=8)
        posts_scroll = ttk.Scrollbar(posts_frame, orient="vertical", command=self.posts_listbox.yview)
        self.posts_listbox.configure(yscrollcommand=posts_scroll.set)
        
        self.posts_listbox.pack(side='left', fill='both', expand=True)
        posts_scroll.pack(side='right', fill='y')
        
        # Post management buttons
        post_buttons_frame = ttk.Frame(main_frame)
        post_buttons_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Button(post_buttons_frame, text="Add Post", command=self.add_post).pack(side='left', padx=(0, 10))
        ttk.Button(post_buttons_frame, text="Remove Post", command=self.remove_post).pack(side='left', padx=(0, 10))

        # Site management buttons
        site_buttons_frame = ttk.Frame(main_frame)
        site_buttons_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Button(site_buttons_frame, text="Publish to Site", command=self.publish_site).pack(side='left', padx=(0, 10))
        ttk.Button(site_buttons_frame, text="Download from Site", command=self.download_from_site).pack(side='left', padx=(0, 10))
        
        # Backup buttons
        backup_buttons_frame = ttk.Frame(main_frame)
        backup_buttons_frame.pack(fill='x')
        
        ttk.Button(backup_buttons_frame, text="Backup Local Copy", command=self.backup_local).pack(side='left', padx=(0, 10))
        ttk.Button(backup_buttons_frame, text="Restore from Backup", command=self.restore_from_backup).pack(side='left', padx=(0, 10))
        ttk.Button(backup_buttons_frame, text="Refresh List", command=self.refresh_display).pack(side='left', padx=(0, 10))

    def _derive_key(self, password):
        """Derive encryption key from user password"""
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'blog_admin_salt', 100000)
        return base64.urlsafe_b64encode(key)
    
    def decrypt_ftp_password(self, encrypted_password, user_password):
        """Decrypt FTP password using user's unlock password"""
        try:
            key = self._derive_key(user_password)
            f = Fernet(key)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
            return f.decrypt(encrypted_bytes).decode()
        except Exception:
            return None  # Wrong password or corrupted data
    
    def get_ftp_credentials(self):
        """Get FTP credentials with password protection"""
        server = os.getenv('FTP_SERVER')
        username = os.getenv('FTP_USERNAME')
        path = os.getenv('FTP_PATH', '/public_html/')
        encrypted_password = os.getenv('FTP_PASSWORD_PROTECTED')
        
        # Check for old-style plain password (for backwards compatibility)
        plain_password = os.getenv('FTP_PASSWORD')
        
        if not all([server, username]) or not (encrypted_password or plain_password):
            messagebox.showerror("Error", 
                "Missing FTP configuration. Please check your .env file.\n\n"
                "Required: FTP_SERVER, FTP_USERNAME, and either:\n"
                "- FTP_PASSWORD_PROTECTED (encrypted), or\n"
                "- FTP_PASSWORD (plain text)")
            return None, None, None, None
        
        # If using plain password (old method), return directly
        if plain_password and not encrypted_password:
            return server, username, plain_password, path
        
        # Use cached unlock password if available
        if self._cached_unlock_password:
            ftp_password = self.decrypt_ftp_password(encrypted_password, self._cached_unlock_password)
            if ftp_password:
                return server, username, ftp_password, path
        
        # Prompt for unlock password
        unlock_password = simpledialog.askstring(
            "Unlock Password", 
            "Enter your password to unlock FTP credentials:",
            show='*'
        )
        
        if not unlock_password:
            return None, None, None, None
        
        # Try to decrypt
        ftp_password = self.decrypt_ftp_password(encrypted_password, unlock_password)
        
        if not ftp_password:
            messagebox.showerror("Error", "Incorrect password")
            return None, None, None, None
        
        # Cache unlock password for this session
        self._cached_unlock_password = unlock_password
        self.update_status("Password unlocked for this session")
        
        return server, username, ftp_password, path
    
    def refresh_display(self):
        """Refresh the posts display to check for file changes"""
        self.refresh_posts_list()
        self.update_status("Posts list refreshed")

    def update_status(self, message):
        """Update status label thread-safely"""
        self.root.after(0, lambda: self.status_label.config(text=message))
    
    def start_progress(self):
        """Start progress bar"""
        self.root.after(0, lambda: self.progress.start())
    
    def stop_progress(self):
        """Stop progress bar"""
        self.root.after(0, lambda: self.progress.stop())
    
    def refresh_posts_list(self):
        """Refresh the posts listbox"""
        self.posts_listbox.delete(0, tk.END)
        
        # Add featured posts
        for post in self.posts_data["stickyPosts"]:
            content_file = post.get('contentFile', f"posts/{post['id']}.html")
            # Convert relative path to absolute path for checking existence
            if not os.path.isabs(content_file):
                full_path = os.path.join(self.site_content_dir, content_file)
            else:
                full_path = content_file
            
            missing_indicator = "[missing file] " if not os.path.exists(full_path) else ""
            self.posts_listbox.insert(tk.END, f"[FEATURED] {missing_indicator}{post['title']} ({post['date']})")
        
        # Add latest posts
        for post in self.posts_data["latestPosts"]:
            content_file = post.get('contentFile', f"posts/{post['id']}.html")
            # Convert relative path to absolute path for checking existence
            if not os.path.isabs(content_file):
                full_path = os.path.join(self.site_content_dir, content_file)
            else:
                full_path = content_file
            
            missing_indicator = "[missing file] " if not os.path.exists(full_path) else ""
            self.posts_listbox.insert(tk.END, f"[LATEST] {missing_indicator}{post['title']} ({post['date']})")
    
    def load_posts_if_exists(self):
        """Load posts from posts-index.json if it exists"""
        try:
            if os.path.exists(self.posts_index_file):
                with open(self.posts_index_file, 'r', encoding='utf-8') as f:
                    self.posts_data = json.load(f)
                self.refresh_posts_list()
            else:
                messagebox.showwarning("Load Warning", f"Posts index file does not exist: {self.posts_index_file}")
        except Exception as e:
            messagebox.showwarning("Load Warning", f"Could not load existing posts: {str(e)}")

    def save_posts_index(self):
        """JSON save"""
        success, message = save_json_simple(self.posts_data, self.posts_index_file)
        
        if success:
            messagebox.showinfo("Save Result", message)
            self.update_status("Posts saved successfully")
        else:
            messagebox.showerror("Save Failed", message)
            self.update_status("Save failed")
        
        return success
    
    def add_post(self):
        """Add a new post with better error handling for EXE deployment"""
        try:
            print("add_post")

            dialog = PostDialog(self.root)
            dialog.dialog.wait_window()

            if dialog.result:
                print(f"add_post results {dialog.result}")

                post_data = dialog.result
                
                # Generate unique ID
                post_id = f"post-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                
                # Ensure posts directory exists
                os.makedirs(self.posts_dir, exist_ok=True)
                
                # Save content to file
                content_file = os.path.join(self.posts_dir, f"{post_id}.html")
                
                with open(content_file, 'w', encoding='utf-8') as f:
                    f.write(post_data['content'])

                print(f"add_post saved to {content_file}")

                # Create post object
                post = {
                    'id': post_id,
                    'title': post_data['title'],
                    'excerpt': post_data['excerpt'],
                    'date': datetime.now().strftime('%Y-%m-%d'),
                    'lastModified': datetime.now().isoformat(),
                    'contentFile': f"posts/{post_id}.html"
                }
                
                if post_data['thumbnail']:
                    post['thumbnail'] = post_data['thumbnail']
                
                # Add to appropriate list
                if post_data['type'] == 'Featured':
                    self.posts_data["stickyPosts"].append(post)
                else:
                    self.posts_data["latestPosts"].insert(0, post)
                
                # Save the posts index
                self.save_posts_index()
                
                # Refresh the display
                self.refresh_posts_list()
            else:
                print("add_post NO RESULTS")
                
        except Exception as e:
            print("add_post exception")
            error_details = (
                f"Failed to add post: {str(e)}\n\n"
                f"Debug Information:\n"
                f"App Directory: {self.debug_info['app_dir']}\n"
                f"Data Directory: {self.debug_info['data_dir']}\n"
                f"Working Directory: {self.debug_info['working_dir']}\n"
                f"site-content Directory: {self.debug_info['site_content_dir']}\n"
                f"site-content Exists: {self.debug_info['site_content_exists']}\n"
                f"site-content Writable: {self.debug_info['site_content_writable']}\n"
                f"Running as EXE: {self.debug_info['frozen']}\n\n"
                f"Please check that the application has write permissions."
            )
            
            self.update_status("Error: Failed to add post")
            messagebox.showerror("Add Post Error", error_details)
    
    def remove_post(self):
        """Remove selected post"""
        selection = self.posts_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a post to remove")
            return
        
        if not messagebox.askyesno("Confirm", "Are you sure you want to remove this post?"):
            return
        
        # Find the post to remove
        index = selection[0]
        total_featured = len(self.posts_data["stickyPosts"])
        
        if index < total_featured:
            # It's a featured post
            post = self.posts_data["stickyPosts"][index]
            self.posts_data["stickyPosts"].remove(post)
        else:
            # It's a latest post
            latest_index = index - total_featured
            post = self.posts_data["latestPosts"][latest_index]
            self.posts_data["latestPosts"].remove(post)
        
        # Remove content file - use full path
        content_file = post.get('contentFile', f"posts/{post['id']}.html")
        if not os.path.isabs(content_file):
            content_file = os.path.join(self.site_content_dir, content_file)
        
        if os.path.exists(content_file):
            os.remove(content_file)
        
        self.save_posts_index()
        self.refresh_posts_list()
        messagebox.showinfo("Success", "Post removed successfully!")

    def publish_site(self):
        """Publish the site to the web server"""
        credentials = self.get_ftp_credentials()
        if not all(credentials):
            return
        
        server, username, password, path = credentials
        
        # Run upload in background thread
        thread = threading.Thread(target=self._publish_worker, args=(server, username, password, path))
        thread.daemon = True
        thread.start()
    
    def _publish_worker(self, server, username, password, path):
        """Background worker for publishing"""
        files_uploaded = []
        try:
            self.update_status("Publishing to site...")
            self.start_progress()
            
            # Connect to FTP
            ftp = ftplib.FTP()
            ftp.connect(server)
            ftp.login(username, password)
            ftp.cwd(path)
            
            # Define files and directories to upload with correct paths
            upload_items = [
                # Single files from site-content directory
                (self.posts_index_file, 'posts-index.json'),
                (self.index_html_file, 'index.html'),
                (self.styles_css_file, 'styles.css'),
            ]
            
            # Directories to upload from site-content
            directories = [
                (self.posts_dir, 'posts'),
                (self.images_dir, 'images'),
                (self.fonts_dir, 'fonts')
            ]
            
            # Upload single files
            for local_file, remote_file in upload_items:
                if os.path.exists(local_file):
                    with open(local_file, 'rb') as f:
                        ftp.storbinary(f'STOR {remote_file}', f)
                    files_uploaded.append(remote_file)
            
            # Upload directories
            for local_dir, remote_dir in directories:
                if os.path.exists(local_dir) and os.path.isdir(local_dir):
                    # Create directory on server
                    try:
                        ftp.mkd(remote_dir)
                    except ftplib.error_perm:
                        pass
                    
                    # Upload all files in directory
                    for filename in os.listdir(local_dir):
                        local_path = os.path.join(local_dir, filename)
                        if os.path.isfile(local_path):
                            with open(local_path, 'rb') as f:
                                ftp.storbinary(f'STOR {remote_dir}/{filename}', f)
                            files_uploaded.append(f"{remote_dir}/{filename}")
            
            ftp.quit()
            
            self.update_status("Published successfully!")
            self.stop_progress()
            
            self.root.after(0, lambda: messagebox.showinfo("Success", 
                f"Site published successfully!\nUploaded {len(files_uploaded)} files."))
            
        except Exception as e:
            self.stop_progress()
            self.update_status("Publish failed")
            error_message = str(e)
            if files_uploaded:
                detailed_message = f"Failed to publish: {error_message}\n\nFiles uploaded before error:\n" + "\n".join(files_uploaded)
            else:
                detailed_message = f"Failed to publish: {error_message}\n\nNo files were uploaded."
            
            self.root.after(0, lambda msg=detailed_message: messagebox.showerror("Error", msg))

    def download_from_site(self):
        """Download files from the server"""
        if not messagebox.askyesno("Confirm", "This will overwrite your local files. Continue?"):
            return
        
        credentials = self.get_ftp_credentials()
        if not all(credentials):
            return
        
        server, username, password, path = credentials
        
        thread = threading.Thread(target=self._download_worker, args=(server, username, password, path))
        thread.daemon = True
        thread.start()
    
    def _download_worker(self, server, username, password, path):
        """Background worker for downloading"""
        try:
            self.update_status("Downloading from site...")
            self.start_progress()
            
            ftp = ftplib.FTP()
            ftp.connect(server)
            ftp.login(username, password)
            ftp.cwd(path)
            
            files_downloaded = []
            
            # Download posts-index.json to site-content directory
            try:
                with open(self.posts_index_file, 'wb') as f:
                    ftp.retrbinary('RETR posts-index.json', f.write)
                files_downloaded.append('posts-index.json')
            except ftplib.error_perm:
                pass
            
            # Download other main files to site-content directory
            main_files = [
                ('index.html', self.index_html_file),
                ('styles.css', self.styles_css_file)
            ]
            for remote_filename, local_path in main_files:
                try:
                    with open(local_path, 'wb') as f:
                        ftp.retrbinary(f'RETR {remote_filename}', f.write)
                    files_downloaded.append(remote_filename)
                except ftplib.error_perm:
                    pass
            
            # Download posts directory
            try:
                ftp.cwd('posts')
                post_files = ftp.nlst()
                
                for post_file in post_files:
                    if post_file.endswith('.html'):
                        local_path = os.path.join(self.posts_dir, post_file)
                        with open(local_path, 'wb') as f:
                            ftp.retrbinary(f'RETR {post_file}', f.write)
                        files_downloaded.append(f"posts/{post_file}")
                
                ftp.cwd('..')
            except ftplib.error_perm:
                pass
            
            # Download images directory
            try:
                ftp.cwd('images')
                image_files = ftp.nlst()
                
                for image_file in image_files:
                    try:
                        local_path = os.path.join(self.images_dir, image_file)
                        with open(local_path, 'wb') as f:
                            ftp.retrbinary(f'RETR {image_file}', f.write)
                        files_downloaded.append(f"images/{image_file}")
                    except ftplib.error_perm:
                        pass
                
                ftp.cwd('..')
            except ftplib.error_perm:
                pass
            
            # Download fonts directory
            try:
                ftp.cwd('fonts')
                font_files = ftp.nlst()
                
                for font_file in font_files:
                    try:
                        local_path = os.path.join(self.fonts_dir, font_file)
                        with open(local_path, 'wb') as f:
                            ftp.retrbinary(f'RETR {font_file}', f.write)
                        files_downloaded.append(f"fonts/{font_file}")
                    except ftplib.error_perm:
                        pass
                
                ftp.cwd('..')
            except ftplib.error_perm:
                pass
            
            ftp.quit()
            
            # Reload posts
            if 'posts-index.json' in files_downloaded:
                self.root.after(0, self.load_posts_if_exists)
            
            self.update_status("Downloaded successfully!")
            self.stop_progress()
            
            self.root.after(0, lambda: messagebox.showinfo("Success", 
                f"Downloaded {len(files_downloaded)} files successfully!"))
            
        except Exception as e:
            self.stop_progress()
            self.update_status("Download failed")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to download: {str(e)}"))
    
    def backup_local(self):
        """Create a backup of all local files"""
        try:
            self.update_status("Creating backup...")
            self.start_progress()
            
            # Create backup data
            backup_data = {
                'created_at': datetime.now().isoformat(),
                'posts_index': self.posts_data.copy(),
                'post_files': {}
            }
            
            # Read all post content files
            for post_list in [self.posts_data["stickyPosts"], self.posts_data["latestPosts"]]:
                for post in post_list:
                    content_file = post.get('contentFile', f"posts/{post['id']}.html")
                    if not os.path.isabs(content_file):
                        content_file = os.path.join(self.site_content_dir, content_file)
                    
                    if os.path.exists(content_file):
                        with open(content_file, 'r', encoding='utf-8') as f:
                            # Store with relative path for compatibility
                            relative_path = os.path.relpath(content_file, self.site_content_dir)
                            backup_data['post_files'][relative_path] = f.read()
            
            # Generate backup filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = os.path.join(self.backups_dir, f'backup_{timestamp}.json')
            
            # Save backup file
            with open(backup_filename, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            self.update_status("Backup created successfully!")
            self.stop_progress()
            
            messagebox.showinfo("Success", 
                f"Backup created successfully!\n\nFile: {backup_filename}\n"
                f"Posts backed up: {len(backup_data['post_files'])}")
            
        except Exception as e:
            self.stop_progress()
            self.update_status("Backup failed")
            messagebox.showerror("Error", f"Failed to create backup: {str(e)}")
    
    def restore_from_backup(self):
        """Restore from a backup file"""
        # Show file dialog to select backup
        backup_file = filedialog.askopenfilename(
            title="Select Backup File to Restore",
            initialdir=self.backups_dir,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not backup_file:
            return
        
        # Confirm restoration
        if not messagebox.askyesno("Confirm Restore", 
                                   f"This will overwrite your local site-content.\n\n"
                                   f"Selected backup: {os.path.basename(backup_file)}\n\n"
                                   f"Are you sure you want to continue?"):
            return
        
        try:
            self.update_status("Restoring from backup...")
            self.start_progress()
            
            # Load backup data
            with open(backup_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            # Restore posts index
            self.posts_data = backup_data['posts_index']
            self.save_posts_index()
            
            # Restore post files
            restored_files = []
            for file_path, content in backup_data.get('post_files', {}).items():
                # Convert relative path to absolute path in site-content
                if not os.path.isabs(file_path):
                    full_path = os.path.join(self.site_content_dir, file_path)
                else:
                    full_path = file_path
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                # Write file
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                restored_files.append(full_path)
            
            # Refresh the posts view
            self.refresh_posts_list()
            
            self.update_status("Restored successfully!")
            self.stop_progress()
            
            # Show success message
            backup_date = backup_data.get('created_at', 'Unknown')
            messagebox.showinfo("Success", 
                              f"Backup restored successfully!\n\n"
                              f"Backup date: {backup_date}\n"
                              f"Posts restored: {len(restored_files)}")
            
        except Exception as e:
            self.stop_progress()
            self.update_status("Restore failed")
            messagebox.showerror("Error", f"Failed to restore backup: {str(e)}")


class PostDialog:
    def __init__(self, parent):
        self.result = None
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Add New Post")
        self.dialog.geometry("500x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (600 // 2)
        self.dialog.geometry(f"500x600+{x}+{y}")
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Post type
        ttk.Label(main_frame, text="Post Type:").grid(row=0, column=0, sticky='w', pady=5)
        self.post_type = ttk.Combobox(main_frame, values=['Latest', 'Featured'], state='readonly')
        self.post_type.grid(row=0, column=1, sticky='ew', pady=5, padx=(10, 0))
        self.post_type.set('Latest')
        
        # Title
        ttk.Label(main_frame, text="Title:").grid(row=1, column=0, sticky='w', pady=5)
        self.title_entry = ttk.Entry(main_frame, width=40)
        self.title_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Excerpt
        ttk.Label(main_frame, text="Excerpt:").grid(row=2, column=0, sticky='nw', pady=5)
        self.excerpt_text = scrolledtext.ScrolledText(main_frame, height=3, width=40)
        self.excerpt_text.grid(row=2, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Thumbnail
        ttk.Label(main_frame, text="Thumbnail URL:").grid(row=3, column=0, sticky='w', pady=5)
        self.thumbnail_entry = ttk.Entry(main_frame, width=40)
        self.thumbnail_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Content
        ttk.Label(main_frame, text="Content (HTML):").grid(row=4, column=0, sticky='nw', pady=5)
        self.content_text = scrolledtext.ScrolledText(main_frame, height=15, width=40)
        self.content_text.grid(row=4, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Load HTML file button
        ttk.Button(main_frame, text="Load HTML File", command=self.load_html_file).grid(row=5, column=1, sticky='w', pady=5, padx=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Save", command=self.save_post).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side='left', padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Focus on title entry
        self.title_entry.focus()
    
    def load_html_file(self):
        """Load HTML content from a file"""
        file_path = filedialog.askopenfilename(
            title="Select HTML File",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.content_text.delete('1.0', 'end')
                    self.content_text.insert('1.0', content)
                messagebox.showinfo("Success", "HTML file loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load HTML file: {str(e)}")
    
    def save_post(self):
        """Verify the post fields and group them in self.result before closing the dialog"""

        print("save_post")
        
        if not self.title_entry.get():
            messagebox.showerror("Error", "Title is required")
            return
        
        if not self.excerpt_text.get('1.0', 'end-1c'):
            messagebox.showerror("Error", "Excerpt is required")
            return
        
        if not self.content_text.get('1.0', 'end-1c'):
            messagebox.showerror("Error", "Content is required")
            return
        
        self.result = {
            'type': self.post_type.get(),
            'title': self.title_entry.get(),
            'excerpt': self.excerpt_text.get('1.0', 'end-1c'),
            'thumbnail': self.thumbnail_entry.get(),
            'content': self.content_text.get('1.0', 'end-1c')
        }
        
        print(f"save_post {self.result}")

        self.dialog.destroy()

    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()


# Set the custom exception handler
sys.excepthook = custom_exception_handler

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SimpleBlogAdmin(root)
        root.mainloop()
    except Exception as e:
        # This catches exceptions during startup
        show_exception_dialog(type(e), e, e.__traceback__)
    finally:
        # Ensure we exit cleanly
        try:
            root.quit()
        except:
            pass
