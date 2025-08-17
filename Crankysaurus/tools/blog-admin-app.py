import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import ftplib
import json
import os
import threading
from datetime import datetime
from dotenv import load_dotenv
import base64
import hashlib
from cryptography.fernet import Fernet

def get_application_path():
    """Get the directory where the application is located"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def get_data_directory():
    """Get a writable data directory for the application"""
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        if os.access(exe_dir, os.W_OK):
            return exe_dir
        # Fallback to user directory
        user_dir = os.path.expanduser("~")
        app_data_dir = os.path.join(user_dir, "SimpleBlogAdmin")
        os.makedirs(app_data_dir, exist_ok=True)
        return app_data_dir
    else:
        return os.path.dirname(os.path.abspath(__file__))

class SimpleBlogAdmin:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Blog Admin v0.1")
        self.root.geometry("600x700")
        
        load_dotenv()
        
        # Setup directory structure
        app_dir = get_application_path()
        data_dir = get_data_directory()
        
        if getattr(sys, 'frozen', False):
            project_dir = os.path.dirname(app_dir)
            potential_site_content = os.path.join(project_dir, "site-content")
            if not os.path.exists(potential_site_content):
                potential_site_content = os.path.join(data_dir, "site-content")
            self.site_content_dir = potential_site_content
        else:
            project_dir = os.path.dirname(app_dir)
            self.site_content_dir = os.path.join(project_dir, "site-content")

        # Ensure directories exist
        os.makedirs(self.site_content_dir, exist_ok=True)
        
        self.posts_dir = os.path.join(self.site_content_dir, "posts")
        self.images_dir = os.path.join(self.site_content_dir, "images")
        self.fonts_dir = os.path.join(self.site_content_dir, "fonts")
        self.posts_index_file = os.path.join(self.site_content_dir, "posts-index.json")
        self.index_html_file = os.path.join(self.site_content_dir, "index.html")
        self.styles_css_file = os.path.join(self.site_content_dir, "styles.css")
        self.backups_dir = os.path.join(data_dir, "backups")
        
        # Create directories
        for directory in [self.posts_dir, self.images_dir, self.fonts_dir, self.backups_dir]:
            os.makedirs(directory, exist_ok=True)
        
        self.posts_data = {"stickyPosts": [], "latestPosts": []}
        self._cached_unlock_password = None
        
        self.create_widgets()
        self.load_posts_if_exists()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Status
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
        
        # Buttons
        post_buttons_frame = ttk.Frame(main_frame)
        post_buttons_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Button(post_buttons_frame, text="Add Post", command=self.add_post).pack(side='left', padx=(0, 10))
        ttk.Button(post_buttons_frame, text="Remove Post", command=self.remove_post).pack(side='left', padx=(0, 10))
        ttk.Button(post_buttons_frame, text="Edit Post", command=self.edit_post).pack(side='left', padx=(0, 10))

        site_buttons_frame = ttk.Frame(main_frame)
        site_buttons_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Button(site_buttons_frame, text="Publish to Site", command=self.publish_site).pack(side='left', padx=(0, 10))
        ttk.Button(site_buttons_frame, text="Download from Site", command=self.download_from_site).pack(side='left', padx=(0, 10))
        
        backup_buttons_frame = ttk.Frame(main_frame)
        backup_buttons_frame.pack(fill='x')
        
        ttk.Button(backup_buttons_frame, text="Backup Local Copy", command=self.backup_local).pack(side='left', padx=(0, 10))
        ttk.Button(backup_buttons_frame, text="Restore from Backup", command=self.restore_from_backup).pack(side='left', padx=(0, 10))

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
            return None
    
    def get_ftp_credentials(self):
        """Get FTP credentials with password protection"""
        server = os.getenv('FTP_SERVER')
        username = os.getenv('FTP_USERNAME')
        path = os.getenv('FTP_PATH', '/public_html/')
        encrypted_password = os.getenv('FTP_PASSWORD_PROTECTED')
        plain_password = os.getenv('FTP_PASSWORD')
        
        if not all([server, username]) or not (encrypted_password or plain_password):
            messagebox.showerror("Error", 
                "Missing FTP configuration. Check your .env file.")
            return None, None, None, None
        
        if plain_password and not encrypted_password:
            return server, username, plain_password, path
        
        if self._cached_unlock_password:
            ftp_password = self.decrypt_ftp_password(encrypted_password, self._cached_unlock_password)
            if ftp_password:
                return server, username, ftp_password, path
        
        unlock_password = simpledialog.askstring(
            "Unlock Password", 
            "Enter your password to unlock FTP credentials:",
            show='*'
        )
        
        if not unlock_password:
            return None, None, None, None
        
        ftp_password = self.decrypt_ftp_password(encrypted_password, unlock_password)
        
        if not ftp_password:
            messagebox.showerror("Error", "Incorrect password")
            return None, None, None, None
        
        self._cached_unlock_password = unlock_password
        self.update_status("Password unlocked for this session")
        
        return server, username, ftp_password, path
    
    def update_status(self, message):
        """Update status label"""
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
        
        for post in self.posts_data["stickyPosts"]:
            content_file = os.path.join(self.site_content_dir, post.get('contentFile', f"posts/{post['id']}.html"))
            missing = "[missing file] " if not os.path.exists(content_file) else ""
            self.posts_listbox.insert(tk.END, f"[FEATURED] {missing}{post['title']} ({post['date']})")
        
        for post in self.posts_data["latestPosts"]:
            content_file = os.path.join(self.site_content_dir, post.get('contentFile', f"posts/{post['id']}.html"))
            missing = "[missing file] " if not os.path.exists(content_file) else ""
            self.posts_listbox.insert(tk.END, f"[LATEST] {missing}{post['title']} ({post['date']})")
    
    def load_posts_if_exists(self):
        """Load posts from posts-index.json if it exists"""
        try:
            if os.path.exists(self.posts_index_file):
                with open(self.posts_index_file, 'r', encoding='utf-8') as f:
                    self.posts_data = json.load(f)
                self.refresh_posts_list()
        except Exception as e:
            messagebox.showwarning("Load Warning", f"Could not load existing posts: {str(e)}")

    def save_posts_index(self):
        """Save posts index to JSON"""
        try:
            os.makedirs(os.path.dirname(self.posts_index_file), exist_ok=True)
            with open(self.posts_index_file, 'w', encoding='utf-8') as f:
                json.dump(self.posts_data, f, indent=2, ensure_ascii=False)
            self.update_status("Posts saved successfully")
            return True
        except Exception as e:
            messagebox.showerror("Save Failed", f"Failed to save: {str(e)}")
            self.update_status("Save failed")
            return False
    
    def add_post(self):
        """Add a new post"""
        dialog = PostDialog(self.root)
        dialog.dialog.wait_window()

        if dialog.result:
            post_data = dialog.result
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            if post_data.get('loaded_filename'):
                post_id = f"{post_data['loaded_filename']}_{timestamp}"
            else:
                post_id = f"post-{timestamp}"
            
            # Save content to file
            content_file = os.path.join(self.posts_dir, f"{post_id}.html")
            with open(content_file, 'w', encoding='utf-8') as f:
                f.write(post_data['content'])

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
            
            self.save_posts_index()
            self.refresh_posts_list()
    
    def remove_post(self):
        """Remove selected post"""
        selection = self.posts_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a post to remove")
            return
        
        if not messagebox.askyesno("Confirm", "Are you sure you want to remove this post?"):
            return
        
        index = selection[0]
        total_featured = len(self.posts_data["stickyPosts"])
        
        if index < total_featured:
            post = self.posts_data["stickyPosts"][index]
            self.posts_data["stickyPosts"].remove(post)
        else:
            latest_index = index - total_featured
            post = self.posts_data["latestPosts"][latest_index]
            self.posts_data["latestPosts"].remove(post)
        
        # Remove content file
        content_file = os.path.join(self.site_content_dir, post.get('contentFile', f"posts/{post['id']}.html"))
        if os.path.exists(content_file):
            os.remove(content_file)
        
        self.save_posts_index()
        self.refresh_posts_list()
        messagebox.showinfo("Success", "Post removed successfully!")

    def edit_post(self):
        """Edit selected post"""
        selection = self.posts_listbox.curselection()
        if not selection:
            return  # Ignore click if no selection
        
        index = selection[0]
        total_featured = len(self.posts_data["stickyPosts"])
        
        # Get the selected post
        if index < total_featured:
            post = self.posts_data["stickyPosts"][index]
            post_list = "stickyPosts"
        else:
            latest_index = index - total_featured
            post = self.posts_data["latestPosts"][latest_index]
            post_list = "latestPosts"
        
        # Read the content file
        content_file = os.path.join(self.site_content_dir, post.get('contentFile', f"posts/{post['id']}.html"))
        try:
            with open(content_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            content = ""
        
        # Open dialog with existing data
        dialog = PostDialog(self.root, edit_mode=True)
        current_type = "Featured" if post_list == "stickyPosts" else "Latest"
        dialog.populate_fields(post, content, current_type)
        dialog.dialog.wait_window()

        if dialog.result:
            post_data = dialog.result
            
            # Update the post with new data
            post['title'] = post_data['title']
            post['excerpt'] = post_data['excerpt']
            post['lastModified'] = datetime.now().isoformat()
            
            if post_data['thumbnail']:
                post['thumbnail'] = post_data['thumbnail']
            elif 'thumbnail' in post:
                del post['thumbnail']
            
            # Save updated content to file
            with open(content_file, 'w', encoding='utf-8') as f:
                f.write(post_data['content'])
            
            # Handle post type change
            new_type = post_data['type']
            current_type = "Featured" if post_list == "stickyPosts" else "Latest"
            
            if new_type != current_type:
                # Remove from current list
                if post_list == "stickyPosts":
                    self.posts_data["stickyPosts"].remove(post)
                else:
                    self.posts_data["latestPosts"].remove(post)
                
                # Add to new list
                if new_type == "Featured":
                    self.posts_data["stickyPosts"].append(post)
                else:
                    self.posts_data["latestPosts"].insert(0, post)
            
            self.save_posts_index()
            self.refresh_posts_list()

    def publish_site(self):
        """Publish the site to the web server"""
        credentials = self.get_ftp_credentials()
        if not all(credentials):
            return
        
        server, username, password, path = credentials
        thread = threading.Thread(target=self._publish_worker, args=(server, username, password, path))
        thread.daemon = True
        thread.start()
    
    def _publish_worker(self, server, username, password, path):
        """Background worker for publishing"""
        try:
            self.update_status("Publishing to site...")
            self.start_progress()
            
            ftp = ftplib.FTP()
            ftp.connect(server)
            ftp.login(username, password)
            ftp.cwd(path)
            
            files_uploaded = []
            
            # Upload single files
            upload_items = [
                (self.posts_index_file, 'posts-index.json'),
                (self.index_html_file, 'index.html'),
                (self.styles_css_file, 'styles.css'),
            ]
            
            for local_file, remote_file in upload_items:
                if os.path.exists(local_file):
                    with open(local_file, 'rb') as f:
                        ftp.storbinary(f'STOR {remote_file}', f)
                    files_uploaded.append(remote_file)
            
            # Upload directories
            directories = [(self.posts_dir, 'posts'), (self.images_dir, 'images'), (self.fonts_dir, 'fonts')]
            
            for local_dir, remote_dir in directories:
                if os.path.exists(local_dir) and os.path.isdir(local_dir):
                    try:
                        ftp.mkd(remote_dir)
                    except ftplib.error_perm:
                        pass
                    
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
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to publish: {str(e)}"))

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
            
            # Download main files
            main_files = [
                ('posts-index.json', self.posts_index_file),
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
            
            # Download directories
            for remote_dir, local_dir in [('posts', self.posts_dir), ('images', self.images_dir), ('fonts', self.fonts_dir)]:
                try:
                    ftp.cwd(remote_dir)
                    file_list = ftp.nlst()
                    
                    for filename in file_list:
                        try:
                            local_path = os.path.join(local_dir, filename)
                            with open(local_path, 'wb') as f:
                                ftp.retrbinary(f'RETR {filename}', f.write)
                            files_downloaded.append(f"{remote_dir}/{filename}")
                        except ftplib.error_perm:
                            pass
                    
                    ftp.cwd('..')
                except ftplib.error_perm:
                    pass
            
            ftp.quit()
            
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
            
            backup_data = {
                'created_at': datetime.now().isoformat(),
                'posts_index': self.posts_data.copy(),
                'post_files': {}
            }
            
            # Read all post content files
            for post_list in [self.posts_data["stickyPosts"], self.posts_data["latestPosts"]]:
                for post in post_list:
                    content_file = os.path.join(self.site_content_dir, post.get('contentFile', f"posts/{post['id']}.html"))
                    if os.path.exists(content_file):
                        with open(content_file, 'r', encoding='utf-8') as f:
                            relative_path = os.path.relpath(content_file, self.site_content_dir)
                            backup_data['post_files'][relative_path] = f.read()
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = os.path.join(self.backups_dir, f'backup_{timestamp}.json')
            
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
        backup_file = filedialog.askopenfilename(
            title="Select Backup File to Restore",
            initialdir=self.backups_dir,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not backup_file:
            return
        
        if not messagebox.askyesno("Confirm Restore", 
                                   f"This will overwrite your local site-content.\n\n"
                                   f"Selected backup: {os.path.basename(backup_file)}\n\n"
                                   f"Are you sure you want to continue?"):
            return
        
        try:
            self.update_status("Restoring from backup...")
            self.start_progress()
            
            with open(backup_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            self.posts_data = backup_data['posts_index']
            self.save_posts_index()
            
            # Restore post files
            restored_files = []
            for file_path, content in backup_data.get('post_files', {}).items():
                full_path = os.path.join(self.site_content_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                restored_files.append(full_path)
            
            self.refresh_posts_list()
            
            self.update_status("Restored successfully!")
            self.stop_progress()
            
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
    def __init__(self, parent, edit_mode=False):
        self.result = None
        self.loaded_filename = None
        self.edit_mode = edit_mode

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Edit Post" if edit_mode else "Add New Post")
        self.dialog.geometry("600x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (600 // 2)
        self.dialog.geometry(f"600x600+{x}+{y}")
        
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
        
        ttk.Button(button_frame, text="Update" if self.edit_mode else "Save", command=self.save_post).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side='left', padx=5)
        
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        self.title_entry.focus()
    
    def populate_fields(self, post, content, post_type="Latest"):
        """Populate dialog fields with existing post data"""
        self.post_type.set(post_type)
        
        self.title_entry.delete(0, 'end')
        self.title_entry.insert(0, post.get('title', ''))
        
        self.excerpt_text.delete('1.0', 'end')
        self.excerpt_text.insert('1.0', post.get('excerpt', ''))
        
        self.thumbnail_entry.delete(0, 'end')
        self.thumbnail_entry.insert(0, post.get('thumbnail', ''))
        
        self.content_text.delete('1.0', 'end')
        self.content_text.insert('1.0', content)

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
                
                # Store the filename without extension for later use
                filename = os.path.basename(file_path)
                self.loaded_filename = os.path.splitext(filename)[0]
                
                messagebox.showinfo("Success", f"HTML file loaded successfully!\nUsing '{self.loaded_filename}' as the name.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load HTML file: {str(e)}")
    
    def save_post(self):
        """Verify the post fields and group them in self.result before closing the dialog"""

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
            'content': self.content_text.get('1.0', 'end-1c'),
            'loaded_filename': self.loaded_filename  # ADD THIS LINE
        }
        
        self.dialog.destroy()

    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleBlogAdmin(root)
    root.mainloop()
