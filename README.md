# Multimedia Encryption and Decryption Project

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

  multimedia-encryption-decryption/
│
├── README.txt                  - This file.
├── src/                        - Source code files (Django project, encryption modules, etc.)
│     ├── manage.py
│     ├── encrypt_decrypt/
│     │      ├── views.py
│     │      ├── models.py
│     │      └── ... (other source files)
│     └── requirements.txt      - Python package requirements.
│
├── executable/                 - Compiled executable file (if applicable)
│     └── multimedia_project.exe    - Example for Windows.
│
├── database/                   - Database files.
│     └── schema.sql            - SQL script to create and initialize the database tables.
│
├── report/                     - Project report.
│     └── Project_Report.pdf    - Detailed project report in PDF format.
│
└── results/                    - Results and metrics.
      └── metrics.txt           - File containing performance data, encryption/decryption times, etc.

## Prerequisites

- **Python 3.x**
- **MySQL Server**
- **Django** (see `src/requirements.txt` for specific versions)
- Required libraries: `cryptography`, and either `mysqlclient` or `PyMySQL`
