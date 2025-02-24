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

def encrypt_text(request):
    if request.method == "POST":
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

        # Combine IV and encrypted data for storage
        combined_data = iv + encrypted_data
        encrypted_text = base64.b64encode(combined_data).decode()

        return render(request, "encrypt_text.html", {"encrypted_text": encrypted_text})
    return render(request, "encrypt_text.html")


def decrypt_text(request):
    if request.method == "POST":
        sender_username = request.POST.get("sender_username")
        encrypted_text = request.POST.get("encrypted_text")

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

            # Try decoding as UTF-8
            try:
                decrypted_text = decrypted_text.decode("utf-8")
            except UnicodeDecodeError:
                # If decoding fails, encode the binary data in Base64
                decrypted_text = base64.b64encode(decrypted_text).decode("utf-8")

            return render(request, "encrypt_text.html", {"decrypted_text": decrypted_text,"decryption_attempted": True})

        except Exception as e:
            print("Decryption Error:", str(e))
            return render(request, "encrypt_text.html", {"decrypted_text": "","decryption_attempted": True})

    return render(request, "encrypt_text.html",{"decryption_attempted": False})
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from .models import UserKeys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def audio_encrypt_decrypt(request):
    """
    Renders the single-page interface for encryption and decryption.
    """
    return render(request, "audio_encrypt_decrypt.html")

def encrypt_audio(request):
    """
    Handles audio encryption and returns the encrypted data.
    """
    if request.method == "POST":
        receiver_username = request.POST.get("receiver_username")
        audio_file = request.FILES.get("audio_file")

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

        # Combine IV and encrypted data for storage
        combined_data = iv + encrypted_data
        encrypted_audio = base64.b64encode(combined_data).decode()

        return render(request, "audio_encrypt_decrypt.html", {"encrypted_audio": encrypted_audio})

    return render(request, "audio_encrypt_decrypt.html")

def decrypt_audio(request):
    """
    Handles audio decryption and returns the decrypted audio for playback.
    """
    if request.method == "POST":
        sender_username = request.POST.get("sender_username")
        encrypted_audio = request.POST.get("encrypted_audio")

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

            # Decrypt the audio data using AES
            combined_data = base64.b64decode(encrypted_audio.encode())
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_audio = decryptor.update(encrypted_data) + decryptor.finalize()

            # Encode the decrypted audio in base64 for playback
            decrypted_audio_base64 = base64.b64encode(decrypted_audio).decode()

            return render(request, "audio_encrypt_decrypt.html", {"decrypted_audio": decrypted_audio_base64})

        except Exception as e:
            # Log the error and display a user-friendly message
            print("Decryption Error:", str(e))
            return render(request, "audio_encrypt_decrypt.html", {"error": "Decryption failed. Please check the input data and try again."})

    return render(request, "audio_encrypt_decrypt.html")
'''
from django.shortcuts import render, get_object_or_404
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.http import HttpResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

def encrypt_file(request):
    if request.method == "POST":
        receiver_username = request.POST.get("receiver_username")
        uploaded_file = request.FILES.get("input_file")

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

        # Encrypt the file using AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        file_data = uploaded_file.read()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        # Combine IV and encrypted data for storage
        combined_data = iv + encrypted_data
        encrypted_file = ContentFile(combined_data)
        encrypted_file_name = default_storage.save(f"encrypted_{uploaded_file.name}", encrypted_file)

        return render(request, "encrypt_file.html", {"encrypted_file_name": encrypted_file_name})
    return render(request, "encrypt_file.html")

def decrypt_file(request):
    if request.method == "POST":
        sender_username = request.POST.get("sender_username")
        encrypted_file = request.FILES.get("encrypted_file")

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

            # Decrypt the file using AES
            file_data = encrypted_file.read()
            iv = file_data[:16]
            encrypted_data = file_data[16:]
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Save the decrypted file
            decrypted_file = ContentFile(decrypted_data)
            decrypted_file_name = default_storage.save(f"decrypted_{encrypted_file.name}", decrypted_file)

            return render(request, "decrypt_file.html", {"decrypted_file_name": decrypted_file_name})

        except Exception as e:
            # Log the error and display a user-friendly message
            print("Decryption Error:", str(e))
            return render(request, "decrypt_file.html", {"error": "Decryption failed. Please check the input data and try again."})

    return render(request, "decrypt_file.html")
from django.http import HttpResponse
from django.core.files.storage import default_storage

def download_file(request, file_name):
    file_path = default_storage.path(file_name)
    with open(file_path, 'rb') as file:
        response = HttpResponse(file.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response
'''
import base64
import os
import numpy as np
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .models import UserKeys
from PIL import Image
import io

def logistic_map(seed, length):
    """Generate a chaotic sequence using the Logistic Map."""
    x = seed
    sequence = []
    r = 3.99  # Chaos parameter (near the edge of chaos)
    
    for _ in range(length):
        x = r * x * (1 - x)  # Logistic map equation
        sequence.append(int(x * 256) % 256)  # Convert to byte range (0-255)
    
    return bytes(sequence)
def encrypt_image(request):
    if request.method == "POST" and request.FILES.get("image"):
        receiver_username = request.POST.get("receiver_username")
        image_file = request.FILES["image"]

        # Convert image to bytes
        image_bytes = image_file.read()

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

        # Generate a Chaos-Based Key
        chaos_seed = derived_key[0] / 255.0  # Use first byte of key as chaos seed
        chaos_key = logistic_map(chaos_seed, 32)  # Generate 32-byte chaotic key

        # Encrypt the image using AES with chaos key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(chaos_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_image = encryptor.update(image_bytes) + encryptor.finalize()

        # Combine IV and encrypted image for storage
        combined_data = iv + encrypted_image
        encrypted_image_base64 = base64.b64encode(combined_data).decode()

        return render(request, "encrypt_image.html", {"encrypted_image": encrypted_image_base64})

    return render(request, "encrypt_image.html")
def decrypt_image(request):
    if request.method == "POST":
        sender_username = request.POST.get("sender_username")
        encrypted_image = request.POST.get("encrypted_image")

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

            # Generate the same Chaos-Based Key
            chaos_seed = derived_key[0] / 255.0
            chaos_key = logistic_map(chaos_seed, 32)

            # Decrypt the image using AES
            combined_data = base64.b64decode(encrypted_image.encode())
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]
            cipher = Cipher(algorithms.AES(chaos_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_image_bytes = decryptor.update(encrypted_data) + decryptor.finalize()

            # Convert decrypted bytes back to image
            image = Image.open(io.BytesIO(decrypted_image_bytes))
            image.show()  # Display the decrypted image (or save it)

            return render(request, "encrypt_image.html", {"message": "Decryption Successful. Image is displayed."})

        except Exception as e:
            print("Decryption Error:", str(e))
            return render(request, "encrypt_image.html", {"error": "Decryption failed. Please check the input data and try again."})

    return render(request, "encrypt_image.html")

'''
import os
import base64
import io
from PIL import Image
from django.shortcuts import render, get_object_or_404
from django.core.files.base import ContentFile
from django.http import HttpResponse
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .models import ImageHistory, UserKeys, User

# 🔹 Chaos-Based Key Generation (Logistic Map)
def logistic_map(seed, size):
    chaotic_sequence = []
    if seed <= 0 or seed >= 1:  # Ensure valid seed
        seed = 0.5
    x = seed
    for _ in range(size):
        x = 3.99 * x * (1 - x)  # Logistic map formula
        chaotic_sequence.append(int(x * 255) % 256)
    return bytes(chaotic_sequence[:32])  # Ensure exactly 32 bytes for AES

# 🔹 Image Encryption
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
from django.shortcuts import render
from django.http import JsonResponse

def encrypt_image(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            plaintext = data.get("image_data")  # The image data before encryption
            
            if not plaintext:
                return JsonResponse({"error": "No image data received"}, status=400)

            key = bytes.fromhex("e55bea4cd589fc082277fd061a60ef3bb6cf9af32d94f71c64f32d94f71e6af7")  # 32-byte AES key
            iv = get_random_bytes(16)  # Generate a random IV (16 bytes)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext.encode(), AES.block_size)  # Pad the plaintext
            encrypted_data = cipher.encrypt(padded_data)

            encrypted_image_base64 = base64.b64encode(iv + encrypted_data).decode("utf-8")  # Store IV + Encrypted Data

            return JsonResponse({"encrypted_image": encrypted_image_base64})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    # Handle GET request by rendering a form or initial page (add your template if needed)
    return render(request, 'encryption/encrypt_image.html')

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import base64
from Crypto.Cipher import AES
import json

@csrf_exempt  # TEMPORARY: Remove this later when CSRF token is handled
def decrypt_image(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            encrypted_image_base64 = data.get("encrypted_data")

            if not encrypted_image_base64:
                return JsonResponse({"error": "No encrypted data received"}, status=400)

            encrypted_bytes = base64.b64decode(encrypted_image_base64)
            iv = encrypted_bytes[:16]  # Extract IV (first 16 bytes)
            encrypted_data = encrypted_bytes[16:]  # The actual encrypted data
            
            key = bytes.fromhex("e55bea4cd589fc082277fd061a60ef3bb6cf9af32d94f71c64f32d94f71e6af7")  

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = cipher.decrypt(encrypted_data)

            decrypted_image = unpad(decrypted_bytes, AES.block_size).decode('utf-8')  # 🚀 Remove padding

            return JsonResponse({"decrypted_image": decrypted_image})

        except ValueError as ve:
            return JsonResponse({"error": "Decryption error: " + str(ve)}, status=500)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)

# 🔹 Download Image Function
def download_image(request, image_type, image_id):
    history_entry = get_object_or_404(ImageHistory, id=image_id)

    if image_type == "decrypted":
        image_path = history_entry.decrypted_image.path
        with open(image_path, "rb") as f:
            response = HttpResponse(f.read(), content_type="image/png")
            response["Content-Disposition"] = f'attachment; filename="{history_entry.decrypted_image.name}"'
            return response

    return HttpResponse("Invalid request", status=400)'''
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.http import HttpResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .models import UserKeys
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from cryptography.hazmat.backends import default_backend
import base64
import os
import struct
def encrypt_decrypt(request):
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "encrypt":
            try:
                receiver_username = request.POST.get("receiver_username")
                uploaded_file = request.FILES.get("input_file")

                if not uploaded_file:
                    return render(request, "encrypt_decrypt.html", {"error": "No file uploaded!"})

                # Fetch sender's private key
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

                # Derive shared key
                shared_key = private_key.exchange(ec.ECDH(), public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_key)

                # Encrypt file
                # Encrypt file
                # Encrypt file
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                # Read the file in binary mode
                file_data = uploaded_file.read()

                # Get the file extension from the uploaded file's name
                file_extension = os.path.splitext(uploaded_file.name)[1]  # e.g., ".xlsx", ".jpg"
                file_extension_encoded = file_extension.encode('utf-8')

                # Store the length of the file extension (1 byte)
                ext_length = len(file_extension_encoded)
                ext_length_bytes = struct.pack("B", ext_length)  # Store length as a single byte

                # Encrypt the binary data
                encrypted_data = encryptor.update(file_data) + encryptor.finalize()

                # Combine IV, extension length, extension, and encrypted data
                combined_data = iv + ext_length_bytes + file_extension_encoded + encrypted_data
                encrypted_base64 = base64.b64encode(combined_data).decode('utf-8')  # Ensure UTF-8 encoding
                return render(request, "encrypt_decrypt.html", {"encrypted_file_data": encrypted_base64})

            except Exception as e:
                return render(request, "encrypt_decrypt.html", {"error": f"Encryption failed: {str(e)}"})

        elif action == "decrypt":
            try:
                sender_username = request.POST.get("sender_username")
                encrypted_file_data = request.POST.get("encrypted_file_data")

                if not encrypted_file_data:
                    return render(request, "encrypt_decrypt.html", {"error": "No encrypted data provided!"})

                # Fetch keys
                current_user = request.user
                current_user_keys = get_object_or_404(UserKeys, user=current_user)
                private_key = serialization.load_pem_private_key(
                    current_user_keys.private_key.encode(),
                    password=None,
                    backend=default_backend()
                )
                sender = get_object_or_404(User, username=sender_username)
                sender_keys = get_object_or_404(UserKeys, user=sender)
                public_key = serialization.load_pem_public_key(
                    sender_keys.public_key.encode(),
                    backend=default_backend()
                )

                # Derive shared key
                shared_key = private_key.exchange(ec.ECDH(), public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_key)

                # Decrypt file
                # Decrypt file
                # Decrypt file
                combined_data = base64.b64decode(encrypted_file_data.encode('utf-8'))  # Decode Base64 to binary
                # Extract IV, extension length, file extension, and encrypted data
                iv = combined_data[:16]
                ext_length = struct.unpack("B", combined_data[16:17])[0]  # Extract the stored length
                file_extension = combined_data[17:17 + ext_length].decode('utf-8')  # Extract extension
                encrypted_data = combined_data[17 + ext_length:]

                cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                # Decrypt the binary data
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

                # Save the decrypted binary data to a file with the correct extension
                decrypted_file = ContentFile(decrypted_data)
                decrypted_file_name = default_storage.save(f"decrypted_file{file_extension}", decrypted_file)  # Use extracted extension
                decrypted_file_url = default_storage.url(decrypted_file_name)
                return render(request, "encrypt_decrypt.html", {"decrypted_file_data": decrypted_file_url})

            except Exception as e:
                return render(request, "encrypt_decrypt.html", {"error": f"Decryption failed: {str(e)}"})

    return render(request, "encrypt_decrypt.html")
'''
def encrypt_image(request):
    if request.method == "POST" and request.FILES.get("image"):
        receiver_username = request.POST.get("receiver_username")
        image_file = request.FILES["image"]
        image_bytes = image_file.read()
        
        current_user = request.user
        current_user_keys = get_object_or_404(UserKeys, user=current_user)
        private_key = serialization.load_pem_private_key(
            current_user_keys.private_key.encode(), password=None
        )
        receiver = get_object_or_404(User, username=receiver_username)
        receiver_keys = get_object_or_404(UserKeys, user=receiver)
        public_key = serialization.load_pem_public_key(receiver_keys.public_key.encode())
        
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake'
        ).derive(shared_key)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_image_bytes = encryptor.update(image_bytes) + encryptor.finalize()
        encrypted_image = iv + encrypted_image_bytes

        noisy_image = Image.frombytes('L', (image_file.width, image_file.height), encrypted_image_bytes[:image_file.width * image_file.height])
        noisy_image_io = io.BytesIO()
        noisy_image.save(noisy_image_io, format='PNG')
        noisy_image_base64 = base64.b64encode(noisy_image_io.getvalue()).decode()
        
        return render(request, "encrypt_image.html", {"encrypted_image": noisy_image_base64})
    
    return render(request, "encrypt_image.html")'''
import os
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.http import HttpResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .models import UserKeys

def logistic_map(seed, length):
    """Generate a chaotic sequence using the Logistic Map."""
    x = seed
    sequence = []
    r = 3.99  # Chaos parameter (near the edge of chaos)
    
    for _ in range(length):
        x = r * x * (1 - x)  # Logistic map equation
        sequence.append(int(x * 256) % 256)  # Convert to byte range (0-255)
    
    return bytes(sequence)

def encrypt_video(request):
    if request.method == "POST" and request.FILES.get("video"):
        receiver_username = request.POST.get("receiver_username")
        video_file = request.FILES["video"]

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

        # Generate a Chaos-Based Key
        chaos_seed = derived_key[0] / 255.0  # Use first byte of key as chaos seed
        chaos_key = logistic_map(chaos_seed, 32)  # Generate 32-byte chaotic key

        # Generate a random IV
        iv = os.urandom(16)

        # Encrypt the video in chunks
        cipher = Cipher(algorithms.AES(chaos_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Save the encrypted video to a temporary file
        encrypted_file_path = "encrypted_video.bin"
        with open(encrypted_file_path, "wb") as encrypted_file:
            # Write the IV first
            encrypted_file.write(iv)

            # Encrypt and write the video in chunks
            for chunk in video_file.chunks():
                encrypted_chunk = encryptor.update(chunk)
                encrypted_file.write(encrypted_chunk)
            encrypted_file.write(encryptor.finalize())

        # Serve the encrypted file for download
        with open(encrypted_file_path, "rb") as f:
            response = HttpResponse(f.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = 'attachment; filename="encrypted_video.bin"'
            return response

    return render(request, "encrypt_video.html")

def decrypt_video(request):
    if request.method == "POST" and request.FILES.get("encrypted_video"):
        sender_username = request.POST.get("sender_username")
        encrypted_video_file = request.FILES["encrypted_video"]

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

            # Generate the same Chaos-Based Key
            chaos_seed = derived_key[0] / 255.0
            chaos_key = logistic_map(chaos_seed, 32)

            # Read the IV and encrypted data from the uploaded file
            encrypted_data = encrypted_video_file.read()
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]

            # Decrypt the video in chunks
            cipher = Cipher(algorithms.AES(chaos_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Save the decrypted video to a file
            decrypted_file_path = "decrypted_video.mp4"
            with open(decrypted_file_path, "wb") as decrypted_file:
                # Process the encrypted data in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                for i in range(0, len(encrypted_data), chunk_size):
                    chunk = encrypted_data[i:i + chunk_size]
                    decrypted_chunk = decryptor.update(chunk)
                    decrypted_file.write(decrypted_chunk)
                decrypted_file.write(decryptor.finalize())

            # Serve the decrypted file for download
            with open(decrypted_file_path, "rb") as f:
                response = HttpResponse(f.read(), content_type="video/mp4")
                response['Content-Disposition'] = 'attachment; filename="decrypted_video.mp4"'
                return response

        except Exception as e:
            print("Decryption Error:", str(e))
            return render(request, "encrypt_video.html", {"error": "Decryption failed. Please check the input data and try again."})

    return render(request, "encrypt_video.html")