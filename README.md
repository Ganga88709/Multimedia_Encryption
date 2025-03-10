# Multimedia Encryption and Decryption System using AES, ECC and Chaos-Based Techniques

## Overview

This project implements a multimedia encryption and decryption system using asymmetric key exchange (ECDH) and AES encryption. The sender uses their private key along with the receiver's public key to derive a shared key. This key is then used to encrypt multimedia files (images, videos, etc.), ensuring that only the intended recipient can decrypt and access the original file.

## Table of Contents

- [Features](#features)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Installation and Setup](#installation-and-setup)
- [Database Configuration](#database-configuration)
- [Execution Steps](#execution-steps)
- [Results and Metrics](#results-and-metrics)
- [Project Report](#project-report)
- [Executable File](#executable-file)
- [License](#license)
- [Contact](#contact)

## Features

- **Asymmetric Key Exchange:** Uses Elliptic Curve Diffie-Hellman (ECDH) to derive a shared secret.
- **AES Encryption/Decryption:** Secures multimedia files using the derived shared key.
- **Django Integration:** Provides a web interface for user authentication and encryption/decryption operations.
- **MySQL Database:** Uses MySQL to store user credentials and keys. (Database tables are auto-created by the project.)
- **File Storage:** Encrypted and decrypted files are stored in designated directories on the C drive.
- **Error Handling:** Displays user-friendly alerts when decryption fails.

## Repository Structure

```plaintext
multimedia-encryption-decryption/
├── README.md                      # Overview, installation, and usage instructions.
├── src/                           # Django project source code.
│   ├── manage.py                  # Django's command-line utility.
│   ├── encrypt_decrypt/           # App with encryption/decryption logic.
│   │   ├── views.py               # Business logic for encryption/decryption.
│   │   ├── models.py              # Data models.
│   │   ├── urls.py                # URL routing for the app.
│   │   └── templates/             # HTML templates.
│   │         └── encrypt_decrypt.html  # Main UI template.
│   └── requirements.txt           # Python package dependencies.
├── executable/                    # Compiled executable (if applicable).
│   └── multimedia_project.exe     # Example executable for Windows.
├── report/                        # Project report.
│   └── Project_Report.pdf         # Detailed project report in PDF format.
└── results/                       # Results and metrics.
    └── metrics.txt                # Performance metrics and test results.
```

## Prerequisites

- **Python 3.x**
- **MySQL Server**
- **Django** (see `src/requirements.txt` for specific versions)
- **Required libraries:** `cryptography`, and either `mysqlclient` or `PyMySQL`

## Installation and Setup

1. **Clone the Repository:**

       git clone https://github.com/yourusername/multimedia-encryption-decryption.git

2. **Navigate to the Project Directory:**
    
       cd multimedia-encryption-decryption

3. **Create and Activate a Virtual Environment (Recommended):**

       python -m venv venv

   **On Windows:** venv\Scripts\activate
   
   **On macOS/Linux:** source venv/bin/activate

4. **Install Dependencies:**

       pip install -r src/requirements.txt

## **Database Configuration:**

1. **Install a MySQL Client:**

   Use either:

   **mysqlclient:**

       pip install mysqlclient

   **PyMySQL (alternative):**

       pip install PyMySQL

   If using PyMySQL, add the following to your project’s `__init__.py` file:
   
       import pymysql
   
       pymysql.install_as_MySQLdb()

2. **Update Django Settings:**

    In src/your_project/settings.py, update the DATABASES section with your MySQL credentials:

        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.mysql',
                'NAME': 'multimedia_encryption',  # Your database name
                'USER': 'your_mysql_username',    # Your MySQL username
                'PASSWORD': 'your_mysql_password',# Your MySQL password
                'HOST': 'your_mysql_host',        # e.g., "127.0.0.1" or a remote host
                'PORT': '3306',                   # Default MySQL port
            }
        }

3. **Run Migrations:**

    Navigate to the src directory and run:

        python manage.py makemigrations
        python manage.py migrate

    This will automatically create the required tables in your MySQL database.

## **Execution Steps**

1. **Run the Django Development Server:**

   From the src directory, run:

       python manage.py runserver

2. **Access the Application:**

   Open your browser and navigate to: http://127.0.0.1:8000/

3. **Encryption Workflow:**
  - Log in with your credentials.
  - Navigate to the encryption page.
  - Upload a multimedia file and enter the receiver's username.
  - Click "Encrypt". The encrypted file will be stored on the C drive under C:\encrypted_media.

4 **Decryption Workflow:**

  - Log in as the intended receiver.
  - Enter the sender's username and the path to the encrypted file.
  - Click "Decrypt". The decrypted file will be saved on the C drive under C:\decrypted_media.
  - If decryption fails (e.g., due to an incorrect sender username), an alert will notify you.

## **Executable File**

1. **How to Generate and Run the Executable**

   Install PyInstaller(if not installed):

       pip install pyinstaller

   Create the Executable:

       pyinstaller --onefile --name=multimedia_encryption_decryption run_django.py

   Run the Executable:

       dist\multimedia_encryption_decryption.exe




