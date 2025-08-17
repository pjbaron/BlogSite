# Simple Blog Admin

A lightweight desktop application for managing blog posts with FTP publishing capabilities.

## Features

- Add/remove blog posts with HTML content
- Featured and Latest post categories
- FTP publishing to web server
- Local backup and restore
- Password-protected FTP credentials
- Auto-naming from loaded HTML files

## Setup

1. **Install dependencies:**
   ```bash
   pip install tkinter python-dotenv cryptography
   ```

2. **Create `.env` file:**
   ```
   FTP_SERVER=your-ftp-server.com
   FTP_USERNAME=your-username
   FTP_PATH=/public_html/
   FTP_PASSWORD_PROTECTED=your-encrypted-password
   ```

3. **Directory structure:**
   ```
   project/
   ├── tools/
   │   ├── blog-admin-app.py
   │   ├── blog-admin-app.spec
   │   └── .env
   └── site-content/
       ├── posts/
       ├── images/
       ├── fonts/
       └── posts-index.json
   ```

## Building Executable

```bash
python -m PyInstaller blog-admin-app.spec
```

Executable will be created in `dist/blog-admin-app.exe`

## Usage

1. **Add Post:** Click "Add Post", fill form, optionally load HTML file
2. **Publish:** Click "Publish to Site" to upload via FTP
3. **Backup:** Click "Backup Local Copy" to save current state
4. **Download:** Click "Download from Site" to sync from server

## Notes

- HTML files loaded will use filename as post identifier
- Encrypted FTP password unlocks for session duration
- Backups saved to writable application directory
