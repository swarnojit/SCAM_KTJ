#!/usr/bin/env python3
"""
ScamShield Setup Script
Automates the setup process for the ScamShield application
"""

import os
import sys
import subprocess
import shutil

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")

def check_python_version():
    """Check if Python version is 3.8 or higher"""
    print_header("Checking Python Version")
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Error: Python 3.8 or higher is required")
        print("   Please upgrade Python and try again")
        sys.exit(1)
    
    print("✅ Python version is compatible")

def create_directory_structure():
    """Create necessary directories"""
    print_header("Creating Directory Structure")
    
    directories = ['static', 'templates']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✅ Created directory: {directory}/")
        else:
            print(f"ℹ️  Directory already exists: {directory}/")

def install_dependencies():
    """Install Python dependencies"""
    print_header("Installing Dependencies")
    
    try:
        print("Installing Flask and required packages...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "Flask==3.0.0", 
            "Flask-CORS==4.0.0", 
            "Werkzeug==3.0.1",
            "--quiet"
        ])
        print("✅ All dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("   Try running manually: pip install -r requirements.txt")
        sys.exit(1)

def create_requirements_file():
    """Create requirements.txt if it doesn't exist"""
    print_header("Creating Requirements File")
    
    requirements_content = """Flask==3.0.0
Flask-CORS==4.0.0
Werkzeug==3.0.1
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements_content)
    
    print("✅ Created requirements.txt")

def check_html_files():
    """Check if HTML files exist in static directory"""
    print_header("Checking HTML Files")
    
    required_files = [
        'index.html',
        'home.html',
        'check-link.html',
        'recent-alerts.html',
        'my-family.html',
        'teach-me.html'
    ]
    
    missing_files = []
    
    for file in required_files:
        file_path = os.path.join('static', file)
        if os.path.exists(file_path):
            print(f"✅ Found: {file}")
        else:
            print(f"❌ Missing: {file}")
            missing_files.append(file)
    
    if missing_files:
        print("\n⚠️  Warning: Some HTML files are missing")
        print("   Please copy the following files to the static/ directory:")
        for file in missing_files:
            print(f"   - {file}")
        print("\n   The application will not work properly without these files.")
    else:
        print("\n✅ All HTML files are present")

def create_run_script():
    """Create a simple run script"""
    print_header("Creating Run Script")
    
    # For Windows
    windows_script = """@echo off
echo Starting ScamShield Server...
python app.py
pause
"""
    
    with open('run.bat', 'w') as f:
        f.write(windows_script)
    print("✅ Created run.bat (Windows)")
    
    # For Unix/Linux/Mac
    unix_script = """#!/bin/bash
echo "Starting ScamShield Server..."
python3 app.py
"""
    
    with open('run.sh', 'w') as f:
        f.write(unix_script)
    
    # Make it executable
    try:
        os.chmod('run.sh', 0o755)
        print("✅ Created run.sh (Unix/Linux/Mac)")
    except:
        print("ℹ️  Created run.sh (you may need to make it executable)")

def print_next_steps():
    """Print next steps for the user"""
    print_header("Setup Complete! 🎉")
    
    print("Next Steps:")
    print("\n1. Ensure all HTML files are in the static/ directory")
    print("\n2. Start the server:")
    print("   • Windows: Double-click run.bat or run: python app.py")
    print("   • Mac/Linux: Run ./run.sh or: python3 app.py")
    print("\n3. Open your browser and navigate to:")
    print("   http://localhost:5000")
    print("\n4. Login with any phone number and use 123456 as OTP")
    print("\n" + "=" * 60)
    print("\nFor more information, see README.md")
    print("=" * 60 + "\n")

def main():
    """Main setup function"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║              🛡️  SCAMSHIELD SETUP WIZARD                  ║
    ║                                                           ║
    ║           AI-Powered Scam Detection System                ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Run setup steps
        check_python_version()
        create_directory_structure()
        create_requirements_file()
        install_dependencies()
        check_html_files()
        create_run_script()
        print_next_steps()
        
    except KeyboardInterrupt:
        print("\n\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Setup failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()