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
- [Executable File](#executable-file)

## Features

- **Asymmetric Key Exchange:** Uses Elliptic Curve Diffie-Hellman (ECDH) to derive a shared secret.
- **AES Encryption/Decryption:** Secures multimedia files using the derived shared key.
- **Django Integration:** Provides a web interface for user authentication and encryption/decryption operations.
- **MySQL Database:** Uses MySQL to store user credentials and keys. (Database tables are auto-created by the project.)
- **File Storage:** Encrypted and decrypted files are stored in designated directories on the C drive.
- **Error Handling:** Displays user-friendly alerts when decryption fails.

## Repository Structure

```plaintext
│── media_cipher/                 # Your Django project folder
│   │── media_cipher/             # Main Django app
│   │   │── __init__.py
│   │   │── settings.py
│   │   │── urls.py
│   │   │── wsgi.py
│   │   │── asgi.py
│   │
│   │── multimedia_encryption_decryption/                 # Your Django app
│   │   │── migrations/           # Database migrations (ignored in Git)
│   │   │── templates/            # HTML templates
│   │   │── static/               # Static files (CSS, JS, images)
│   │   │── views.py
│   │   │── models.py
│   │   │── urls.py
│   │   │── admin.py
│   │
│   │── multimedia_encryption_decryption.exe #Project Executable
│   │── manage.py                 # Django project management file
│   │── requirements.txt          # Dependencies
│   │
│── report.pdf              
│── README.md                     

```

## Prerequisites

- **Python 3.x**
- **MySQL Server**
- **Django** (see `src/requirements.txt` for specific versions)
- **Required libraries:** `cryptography`, and either `mysqlclient` or `PyMySQL`

## Installation and Setup

1. **Clone the Repository:**

       git clone https://github.com/Ganga88709/Multimedia_Encryption_Decryption_AES_ECC_Chaos.git

2. **Navigate to the Project Directory:**
    
       cd Multimedia_Encryption_Decryption_AES_ECC_Chaos

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
  - Click "Encrypt". The encrypted file will be stored in Downloads folder.

4 **Decryption Workflow:**

  - Log in as the intended receiver.
  - Enter the sender's username and the path to the encrypted file.
  - Click "Decrypt". The decrypted file will be saved in Downloads folder.
  - If decryption fails (e.g., due to an incorrect sender username), an alert will notify you.

## **Executable File**

1. **How to Generate and Run the Executable**

   Install PyInstaller(if not installed):

       pip install pyinstaller

   Create the Executable:

       pyinstaller --onefile --name=multimedia_encryption_decryption run_django.py

   Run the Executable:

       dist\multimedia_encryption_decryption.exe




