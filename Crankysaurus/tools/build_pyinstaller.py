# build_apps.py - Script to build both applications

import os
import subprocess
import sys

def build_apps():
    print("\nBuilding Blog Admin...")
    
    # Build Blog Admin
    blog_admin_cmd = [
        'pyinstaller',
        '--onefile',
        '--windowed',
        '--name=BlogAdmin',
        '--icon=blog.ico',  # optional - add if you have an icon
        'blog-admin-app.py'
    ]
    
    try:
        subprocess.run(blog_admin_cmd, check=True)
        print("✓ Blog Admin built successfully!")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to build Blog Admin: {e}")
        return False
    
    print("\n🎉 Both applications built successfully!")
    print("Executables are in the 'dist' folder")
    
    return True

if __name__ == "__main__":
    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    # Check for required packages
    required_packages = ['python-dotenv']
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', package])
    
    build_apps()
