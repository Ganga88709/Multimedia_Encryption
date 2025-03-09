import os
import sys

# Prompt user to enter paths
PROJECT_PATH = input("Enter the absolute path of your Django project (where manage.py is located): ").strip()
VENV_PATH = input("Enter the absolute path of your virtual environment's Scripts folder: ").strip()

# Validate project path
if not os.path.exists(PROJECT_PATH):
    print("Error: Invalid project path! Please check and enter the correct path.")
    sys.exit(1)

# Validate virtual environment path
if not os.path.exists(VENV_PATH):
    print("Error: Virtual environment not found! Please check the path.")
    sys.exit(1)

# Change directory to Django project
os.chdir(PROJECT_PATH)

# Check if manage.py exists
if not os.path.exists(os.path.join(PROJECT_PATH, "manage.py")):
    print("Error: manage.py not found! Please check the project path.")
    sys.exit(1)

# Activate virtual environment and run Django server
os.system(f'cmd /c "{os.path.join(VENV_PATH, "activate")} & python manage.py runserver"')
