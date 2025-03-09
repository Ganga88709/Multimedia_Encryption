from django.shortcuts import render,redirect,get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User,auth
from django.urls import reverse
from .models import UserKeys
import rsa
import base64
from cryptography.hazmat.primitives import serialization
from .utils import *
from django.http import JsonResponse, HttpResponse, FileResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from django.http import JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
from media_cipher import settings
def home(request):
    return render(request,'home.html')

def register(request):
    if request.method == "POST":
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        email = request.POST['email']

        if password1 == password2:
            if User.objects.filter(username=username).exists():
                return JsonResponse({'status': 'error', 'message': 'Username already exists'})
            elif User.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Email already exists'})
            else:
                # Create the user
                user = User.objects.create_user(username=username, password=password1, email=email, first_name=first_name, last_name=last_name)
                user.save()

                # Generate ECC key pair (using SECP256R1 curve)
                private_key = ec.generate_private_key(ec.SECP256R1())

                # Serialize the ECC keys
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode('utf-8')

                public_key_pem = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')

                # Save keys to the database
                UserKeys.objects.create(user=user, public_key=public_key_pem, private_key=private_key_pem)

                return JsonResponse({'status': 'success', 'message': 'Registration successful!'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Passwords do not match'})
    else:
        return render(request, 'register.html')

def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            return JsonResponse({'status': 'success', 'message': 'Login Successful'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid credentials'})
    else:
        return render(request, 'login.html')

def landing(request):
    return render(request,"landing.html")

from django.http import HttpResponse
import io

def encrypt_text(request):
    if request.method == "POST":
        try:
            receiver_username = request.POST.get("receiver_username")
            input_text = request.POST.get("input_text")

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch receiver's public key
            receiver = get_object_or_404(User, username=receiver_username)
            receiver_keys = get_object_or_404(UserKeys, user=receiver)
            public_key = serialization.load_pem_public_key(
                receiver_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Encrypt the text using AES
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(input_text.encode()) + encryptor.finalize()

            # Combine IV and encrypted data
            combined_data = iv + encrypted_data
            encrypted_text = base64.b64encode(combined_data).decode()

            # Create response with encrypted text as downloadable file
            response = HttpResponse(encrypted_text, content_type='text/plain')
            response['Content-Disposition'] = 'attachment; filename="encrypted_text.txt"'
            return response

        except Exception as e:
            print("Encryption Error:", str(e))
            return render(request, "text_encrypt_decrypt.html", 
                        {"error": f"Encryption failed: {str(e)}"})

    return render(request, "text_encrypt_decrypt.html")

def decrypt_text(request):
    if request.method == "POST":
        try:
            sender_username = request.POST.get("sender_username")
            encrypted_file = request.FILES.get("encrypted_file")

            if not encrypted_file:
                return render(request, "text_encrypt_decrypt.html", 
                            {"error": "Please upload an encrypted file"})

            # Read the encrypted text from the uploaded file
            encrypted_text = encrypted_file.read().decode('utf-8')

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch sender's public key
            sender = get_object_or_404(User, username=sender_username)
            sender_keys = get_object_or_404(UserKeys, user=sender)
            public_key = serialization.load_pem_public_key(
                sender_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Decrypt the text using AES
            combined_data = base64.b64decode(encrypted_text.encode())
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(encrypted_data) + decryptor.finalize()

            # Decode the decrypted text
            decrypted_text = decrypted_text.decode('utf-8')

            # Create response with decrypted text as downloadable file
            response = HttpResponse(decrypted_text, content_type='text/plain')
            response['Content-Disposition'] = 'attachment; filename="decrypted_text.txt"'
            return response

        except Exception as e:
            print("Decryption Error:", str(e))
            return render(request, "text_encrypt_decrypt.html", 
                        {"error": f"Decryption failed: {str(e)}"})

    return render(request, "text_encrypt_decrypt.html")
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.http import HttpResponse
from .models import UserKeys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import tempfile

def audio_encrypt_decrypt(request):
    """
    Renders the single-page interface for encryption and decryption.
    """
    return render(request, "audio_encrypt_decrypt.html")

def encrypt_audio(request):
    """
    Handles audio encryption and returns the encrypted file for download.
    """
    if request.method == "POST":
        try:
            receiver_username = request.POST.get("receiver_username")
            audio_file = request.FILES.get("audio_file")
            
            if not audio_file:
                return render(request, "audio_encrypt_decrypt.html", 
                            {"error": "Please select an audio file"})

            # Get original file extension
            file_extension = os.path.splitext(audio_file.name)[1]

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch receiver's public key
            receiver = get_object_or_404(User, username=receiver_username)
            receiver_keys = get_object_or_404(UserKeys, user=receiver)
            public_key = serialization.load_pem_public_key(
                receiver_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Read the audio file
            audio_data = audio_file.read()

            # Encrypt the audio data using AES
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(audio_data) + encryptor.finalize()

            # Combine IV and encrypted data
            combined_data = iv + encrypted_data

            # Create response for file download
            response = HttpResponse(combined_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="encrypted_audio{file_extension}"'
            
            return response

        except Exception as e:
            print("Encryption Error:", str(e))
            return render(request, "audio_encrypt_decrypt.html", 
                        {"error": f"Encryption failed: {str(e)}"})

    return render(request, "audio_encrypt_decrypt.html")

def decrypt_audio(request):
    """
    Handles audio decryption and returns the decrypted file for download.
    """
    if request.method == "POST":
        try:
            sender_username = request.POST.get("sender_username")
            encrypted_file = request.FILES.get("encrypted_audio")

            if not encrypted_file:
                return render(request, "audio_encrypt_decrypt.html", 
                            {"error": "Please select an encrypted audio file"})

            # Get file extension
            file_extension = os.path.splitext(encrypted_file.name)[1]

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch sender's public key
            sender = get_object_or_404(User, username=sender_username)
            sender_keys = get_object_or_404(UserKeys, user=sender)
            public_key = serialization.load_pem_public_key(
                sender_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Read the encrypted file
            combined_data = encrypted_file.read()
            
            # Extract IV and encrypted data
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]

            # Decrypt the audio data
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_audio = decryptor.update(encrypted_data) + decryptor.finalize()

            # Create response for file download
            response = HttpResponse(decrypted_audio, content_type='audio/mpeg')
            response['Content-Disposition'] = f'attachment; filename="decrypted_audio{file_extension}"'
            
            return response

        except Exception as e:
            print("Decryption Error:", str(e))
            return render(request, "audio_encrypt_decrypt.html", 
                        {"error": f"Decryption failed: {str(e)}"})

    return render(request, "audio_encrypt_decrypt.html")

from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import numpy as np
import io
import os
import logging

logger = logging.getLogger(__name__)
import numpy as np

def generate_chaos_sequence(seed, size):
    """
    Generate a chaos sequence using the logistic map.

    Args:
        seed (float): Initial seed value (between 0 and 1).
        size (int): Length of the chaos sequence to generate.

    Returns:
        np.ndarray: A 1D array of integers (0-255) representing the chaos sequence.
    """
    # Ensure the seed is within the valid range for the logistic map
    if not (0 < seed < 1):
        raise ValueError("Seed must be between 0 and 1.")

    # Parameters for the logistic map
    r = 3.99  # Chaotic parameter
    sequence = np.zeros(size, dtype=np.uint8)

    # Generate the chaos sequence in chunks for better performance
    chunk_size = 1000000  # Adjust based on memory constraints
    x = seed  # Initial value

    for i in range(0, size, chunk_size):
        end = min(i + chunk_size, size)
        chunk_len = end - i
        chunk = np.zeros(chunk_len, dtype=np.float64)
        chunk[0] = x

        # Vectorized logistic map iteration
        for j in range(1, chunk_len):
            chunk[j] = r * chunk[j - 1] * (1 - chunk[j - 1])

        # Store the chunk in the sequence
        sequence[i:end] = (chunk * 255).astype(np.uint8)
        x = chunk[-1]  # Update the initial value for the next chunk

    return sequence
def encrypt_image(request):
    """
    Encrypts an image using chaos-based encryption with a shared key derived from ECDH.
    """
    if request.method == "POST" and request.FILES.get("image"):
        try:
            # Load image
            image = Image.open(request.FILES["image"])
            if image.mode != 'RGB':
                image = image.convert('RGB')
            width, height = image.size

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch receiver's public key
            receiver_username = request.POST.get("receiver_username")
            receiver = get_object_or_404(User, username=receiver_username)
            receiver_keys = get_object_or_404(UserKeys, user=receiver)
            public_key = serialization.load_pem_public_key(
                receiver_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Use the derived key to generate the initial seed for chaos
            initial_seed = int.from_bytes(derived_key[:8], byteorder='big') / (2**64)

            # Convert image to numpy array
            image_array = np.array(image)

            # Generate chaos sequences
            pixels = width * height
            chaos_seq_scramble = generate_chaos_sequence(initial_seed, pixels)
            chaos_seq_xor = generate_chaos_sequence(initial_seed + 0.1, pixels * 3)

            # Scramble pixels (vectorized)
            indices = np.argsort(chaos_seq_scramble)
            scrambled = image_array.reshape(-1, 3)[indices]

            # XOR operation (vectorized)
            xor_array = scrambled.reshape(-1)
            xor_array ^= chaos_seq_xor
            encrypted_array = xor_array.reshape(height, width, 3)

            # Convert to image
            encrypted_image = Image.fromarray(encrypted_array, 'RGB')

            # Save to BytesIO
            img_io = io.BytesIO()
            encrypted_image.save(img_io, 'PNG', optimize=True)
            img_io.seek(0)

            # Return response
            response = HttpResponse(img_io.getvalue(), content_type='image/png')
            response['Content-Disposition'] = f'attachment; filename="encrypted_image.png"'
            return response

        except Exception as e:
            logger.error(f"Encryption Error: {str(e)}")
            return render(request, "image_encrypt_decrypt.html", 
                        {"error": f"Encryption failed: {str(e)}"})

    return render(request, "image_encrypt_decrypt.html")
def decrypt_image(request):
    """
    Decrypts an image using chaos-based decryption with a shared key derived from ECDH.
    """
    if request.method == "POST" and request.FILES.get("encrypted_image"):
        try:
            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch sender's public key
            sender_username = request.POST.get("sender_username")
            sender = get_object_or_404(User, username=sender_username)
            sender_keys = get_object_or_404(UserKeys, user=sender)
            public_key = serialization.load_pem_public_key(
                sender_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Use the derived key to generate the initial seed for chaos
            initial_seed = int.from_bytes(derived_key[:8], byteorder='big') / (2**64)

            # Load encrypted image
            encrypted_image = Image.open(request.FILES["encrypted_image"])
            if encrypted_image.mode != 'RGB':
                encrypted_image = encrypted_image.convert('RGB')
            encrypted_array = np.array(encrypted_image)
            width, height = encrypted_image.size

            # Generate chaos sequences
            pixels = width * height
            chaos_seq_scramble = generate_chaos_sequence(initial_seed, pixels)
            chaos_seq_xor = generate_chaos_sequence(initial_seed + 0.1, pixels * 3)

            # Reverse XOR (vectorized)
            xor_array = encrypted_array.reshape(-1)
            xor_array ^= chaos_seq_xor
            unxored = xor_array.reshape(-1, 3)

            # Unscramble (vectorized)
            indices = np.argsort(chaos_seq_scramble)
            decrypted_array = np.zeros_like(unxored)
            decrypted_array[indices] = unxored
            decrypted_array = decrypted_array.reshape(height, width, 3)

            # Convert to image
            decrypted_image = Image.fromarray(decrypted_array, 'RGB')

            # Save to BytesIO
            img_io = io.BytesIO()
            decrypted_image.save(img_io, 'PNG', optimize=True)
            img_io.seek(0)

            # Return response
            response = HttpResponse(img_io.getvalue(), content_type='image/png')
            response['Content-Disposition'] = f'attachment; filename="decrypted_image.png"'
            return response

        except Exception as e:
            logger.error(f"Decryption Error: {str(e)}")
            return render(request, "image_encrypt_decrypt.html", 
                        {"error": f"Decryption failed: {str(e)}"})

    return render(request, "image_encrypt_decrypt.html")
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from .models import UserKeys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import mimetypes

# List of allowed file extensions
ALLOWED_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', 
    '.ppt', '.pptx', '.csv', '.rtf', '.odt', '.ods',
    '.odp', '.zip', '.rar', '.7z'
}

def is_allowed_file(filename):
    """Check if the file extension is allowed"""
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def get_file_extension(filename):
    """Get the file extension including the dot"""
    return os.path.splitext(filename)[1].lower()

def encrypt_document(request):
    if request.method == "POST":
        try:
            receiver_username = request.POST.get("receiver_username")
            document_file = request.FILES.get("document_file")

            if not document_file:
                return render(request, "file_encrypt_decrypt.html", 
                            {"error": "Please select a file"})

            # Check file extension
            if not is_allowed_file(document_file.name):
                return render(request, "file_encrypt_decrypt.html", 
                            {"error": "File type not supported"})

            # Get file extension
            file_extension = get_file_extension(document_file.name)

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch receiver's public key
            receiver = get_object_or_404(User, username=receiver_username)
            receiver_keys = get_object_or_404(UserKeys, user=receiver)
            public_key = serialization.load_pem_public_key(
                receiver_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Read the document file
            file_data = document_file.read()

            # Encrypt the document data using AES
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()

            # Combine IV and encrypted data
            combined_data = iv + encrypted_data

            # Create response for encrypted file download
            response = HttpResponse(combined_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="encrypted_document{file_extension}"'
            
            # Store the original filename in a custom header
            original_filename = os.path.splitext(document_file.name)[0]
            response['X-Original-Filename'] = base64.b64encode(original_filename.encode()).decode()

            return response

        except Exception as e:
            print("Encryption Error:", str(e))
            return render(request, "file_encrypt_decrypt.html", 
                        {"error": f"Encryption failed: {str(e)}"})

    return render(request, "file_encrypt_decrypt.html")

def decrypt_document(request):
    if request.method == "POST":
        try:
            sender_username = request.POST.get("sender_username")
            encrypted_file = request.FILES.get("encrypted_file")

            if not encrypted_file:
                return render(request, "file_encrypt_decrypt.html", 
                            {"error": "Please upload an encrypted file"})

            # Get file extension
            file_extension = get_file_extension(encrypted_file.name)

            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch sender's public key
            sender = get_object_or_404(User, username=sender_username)
            sender_keys = get_object_or_404(UserKeys, user=sender)
            public_key = serialization.load_pem_public_key(
                sender_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Read the encrypted file
            encrypted_data = encrypted_file.read()

            # Extract IV and encrypted content
            iv = encrypted_data[:16]
            file_content = encrypted_data[16:]

            # Decrypt the document
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(file_content) + decryptor.finalize()

            # Get the appropriate MIME type
            mime_type, _ = mimetypes.guess_type(f"file{file_extension}")
            if not mime_type:
                mime_type = 'application/octet-stream'

            # Create response for decrypted file download
            response = HttpResponse(decrypted_data, content_type=mime_type)
            response['Content-Disposition'] = f'attachment; filename="decrypted_document{file_extension}"'
            
            return response

        except Exception as e:
            print("Decryption Error:", str(e))
            return render(request, "file_encrypt_decrypt.html", 
                        {"error": f"Decryption failed: {str(e)}"})

    return render(request, "file_encrypt_decrypt.html")

import os
import tempfile
import numpy as np
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_chaos_sequence(seed, size):
    """Generate chaos sequence using logistic map."""
    x = seed
    r = 3.99  # Chaos parameter
    sequence = np.zeros(size, dtype=np.float64)
    sequence[0] = x
    
    for i in range(1, size):
        x = r * x * (1 - x)
        sequence[i] = x
        
    return (sequence * 255).astype(np.uint8)

def encrypt_video(request):
    """
    Encrypts a video using chaos-based encryption with a shared key derived from ECDH.
    """
    if request.method == "POST" and request.FILES.get("video"):
        try:
            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch receiver's public key
            receiver_username = request.POST.get("receiver_username")
            receiver = get_object_or_404(User, username=receiver_username)
            receiver_keys = get_object_or_404(UserKeys, user=receiver)
            public_key = serialization.load_pem_public_key(
                receiver_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Use the derived key to generate the initial seed for chaos
            initial_seed = int.from_bytes(derived_key[:8], byteorder='big') / (2**64)

            # Create temporary file for the uploaded video
            video_file = request.FILES["video"]
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_input:
                for chunk in video_file.chunks():
                    temp_input.write(chunk)
                temp_input_path = temp_input.name

            # Read the video file
            with open(temp_input_path, 'rb') as f:
                video_data = f.read()

            # Generate chaos sequence for encryption
            chaos_sequence = generate_chaos_sequence(initial_seed, len(video_data))

            # Encrypt the video data using chaos sequence
            encrypted_data = bytearray()
            for i, byte in enumerate(video_data):
                encrypted_data.append(byte ^ chaos_sequence[i])

            # Encrypt the chaos-encrypted data using AES
            iv = os.urandom(16)  # Generate a random IV
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            final_encrypted_data = encryptor.update(encrypted_data) + encryptor.finalize()

            # Combine IV and final encrypted data
            combined_data = iv + final_encrypted_data

            # Create temporary file for encrypted video
            temp_output_path = tempfile.mktemp(suffix='.mp4')
            with open(temp_output_path, 'wb') as f:
                f.write(combined_data)

            # Prepare encrypted video for download
            with open(temp_output_path, 'rb') as f:
                response = HttpResponse(f.read(), content_type='video/mp4')
                response['Content-Disposition'] = f'attachment; filename="encrypted_video.mp4"'

            # Cleanup
            os.unlink(temp_input_path)
            os.unlink(temp_output_path)

            return response

        except Exception as e:
            print(f"Encryption Error: {str(e)}")
            return render(request, "video_encrypt_decrypt.html", {"error": str(e)})

    return render(request, "video_encrypt_decrypt.html")
def decrypt_video(request):
    """
    Decrypts a video using chaos-based decryption with a shared key derived from ECDH.
    """
    if request.method == "POST" and request.FILES.get("encrypted_video"):
        try:
            # Fetch current user's private key
            current_user = request.user
            current_user_keys = get_object_or_404(UserKeys, user=current_user)
            private_key = serialization.load_pem_private_key(
                current_user_keys.private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Fetch sender's public key
            sender_username = request.POST.get("sender_username")
            sender = get_object_or_404(User, username=sender_username)
            sender_keys = get_object_or_404(UserKeys, user=sender)
            public_key = serialization.load_pem_public_key(
                sender_keys.public_key.encode(),
                backend=default_backend()
            )

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)

            # Use the derived key to generate the initial seed for chaos
            initial_seed = int.from_bytes(derived_key[:8], byteorder='big') / (2**64)

            # Read the encrypted file
            encrypted_file = request.FILES["encrypted_video"]
            combined_data = encrypted_file.read()

            # Extract IV and final encrypted data
            iv = combined_data[:16]
            final_encrypted_data = combined_data[16:]

            # Decrypt the AES-encrypted data
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            chaos_encrypted_data = decryptor.update(final_encrypted_data) + decryptor.finalize()

            # Generate chaos sequence for decryption
            chaos_sequence = generate_chaos_sequence(initial_seed, len(chaos_encrypted_data))

            # Decrypt the chaos-encrypted data
            decrypted_data = bytearray()
            for i, byte in enumerate(chaos_encrypted_data):
                decrypted_data.append(byte ^ chaos_sequence[i])

            # Create temporary file for decrypted video
            temp_output_path = tempfile.mktemp(suffix='.mp4')
            with open(temp_output_path, 'wb') as f:
                f.write(decrypted_data)

            # Prepare decrypted video for download
            with open(temp_output_path, 'rb') as f:
                response = HttpResponse(f.read(), content_type='video/mp4')
                response['Content-Disposition'] = 'attachment; filename="decrypted_video.mp4"'

            # Cleanup
            os.unlink(temp_output_path)

            return response

        except Exception as e:
            print(f"Decryption Error: {str(e)}")
            return render(request, "video_encrypt_decrypt.html", {"error": str(e)})

    return render(request, "video_encrypt_decrypt.html")
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')  # Replace 'login' with your login page URL name
