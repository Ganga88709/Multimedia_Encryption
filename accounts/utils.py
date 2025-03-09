

# import os
# from django.shortcuts import render, get_object_or_404
# from django.contrib.auth.models import User
# from django.http import HttpResponse
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from .models import UserKeys

# def logistic_map(seed, length):
#     """Generate a chaotic sequence using the Logistic Map."""
#     x = seed
#     sequence = []
#     r = 3.99  # Chaos parameter (near the edge of chaos)
    
#     for _ in range(length):
#         x = r * x * (1 - x)  # Logistic map equation
#         sequence.append(int(x * 256) % 256)  # Convert to byte range (0-255)
    
#     return bytes(sequence)

# def encrypt_video(request):
#     if request.method == "POST" and request.FILES.get("video"):
#         receiver_username = request.POST.get("receiver_username")
#         video_file = request.FILES["video"]

#         # Fetch current user's private key
#         current_user = request.user
#         current_user_keys = get_object_or_404(UserKeys, user=current_user)
#         private_key = serialization.load_pem_private_key(
#             current_user_keys.private_key.encode(),
#             password=None,
#             backend=default_backend()
#         )

#         # Fetch receiver's public key
#         receiver = get_object_or_404(User, username=receiver_username)
#         receiver_keys = get_object_or_404(UserKeys, user=receiver)
#         public_key = serialization.load_pem_public_key(
#             receiver_keys.public_key.encode(),
#             backend=default_backend()
#         )

#         # Derive shared key using ECDH
#         shared_key = private_key.exchange(ec.ECDH(), public_key)
#         derived_key = HKDF(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=None,
#             info=b'handshake data',
#             backend=default_backend()
#         ).derive(shared_key)

#         # Generate a Chaos-Based Key
#         chaos_seed = derived_key[0] / 255.0  # Use first byte of key as chaos seed
#         chaos_key = logistic_map(chaos_seed, 32)  # Generate 32-byte chaotic key

#         # Generate a random IV
#         iv = os.urandom(16)

#         # Encrypt the video in chunks
#         cipher = Cipher(algorithms.AES(chaos_key), modes.CFB(iv), backend=default_backend())
#         encryptor = cipher.encryptor()

#         # Save the encrypted video to a temporary file
#         encrypted_file_path = "encrypted_video.bin"
#         with open(encrypted_file_path, "wb") as encrypted_file:
#             # Write the IV first
#             encrypted_file.write(iv)

#             # Encrypt and write the video in chunks
#             for chunk in video_file.chunks():
#                 encrypted_chunk = encryptor.update(chunk)
#                 encrypted_file.write(encrypted_chunk)
#             encrypted_file.write(encryptor.finalize())

#         # Serve the encrypted file for download
#         with open(encrypted_file_path, "rb") as f:
#             response = HttpResponse(f.read(), content_type="application/octet-stream")
#             response['Content-Disposition'] = 'attachment; filename="encrypted_video.bin"'
#             return response

#     return render(request, "encrypt_video.html")

# def decrypt_video(request):
#     if request.method == "POST" and request.FILES.get("encrypted_video"):
#         sender_username = request.POST.get("sender_username")
#         encrypted_video_file = request.FILES["encrypted_video"]

#         try:
#             # Fetch current user's private key
#             current_user = request.user
#             current_user_keys = get_object_or_404(UserKeys, user=current_user)
#             private_key = serialization.load_pem_private_key(
#                 current_user_keys.private_key.encode(),
#                 password=None,
#                 backend=default_backend()
#             )

#             # Fetch sender's public key
#             sender = get_object_or_404(User, username=sender_username)
#             sender_keys = get_object_or_404(UserKeys, user=sender)
#             public_key = serialization.load_pem_public_key(
#                 sender_keys.public_key.encode(),
#                 backend=default_backend()
#             )

#             # Derive shared key using ECDH
#             shared_key = private_key.exchange(ec.ECDH(), public_key)
#             derived_key = HKDF(
#                 algorithm=hashes.SHA256(),
#                 length=32,
#                 salt=None,
#                 info=b'handshake data',
#                 backend=default_backend()
#             ).derive(shared_key)

#             # Generate the same Chaos-Based Key
#             chaos_seed = derived_key[0] / 255.0
#             chaos_key = logistic_map(chaos_seed, 32)

#             # Read the IV and encrypted data from the uploaded file
#             encrypted_data = encrypted_video_file.read()
#             iv = encrypted_data[:16]
#             encrypted_data = encrypted_data[16:]

#             # Decrypt the video in chunks
#             cipher = Cipher(algorithms.AES(chaos_key), modes.CFB(iv), backend=default_backend())
#             decryptor = cipher.decryptor()

#             # Save the decrypted video to a file
#             decrypted_file_path = "decrypted_video.mp4"
#             with open(decrypted_file_path, "wb") as decrypted_file:
#                 # Process the encrypted data in chunks
#                 chunk_size = 1024 * 1024  # 1MB chunks
#                 for i in range(0, len(encrypted_data), chunk_size):
#                     chunk = encrypted_data[i:i + chunk_size]
#                     decrypted_chunk = decryptor.update(chunk)
#                     decrypted_file.write(decrypted_chunk)
#                 decrypted_file.write(decryptor.finalize())

#             # Serve the decrypted file for download
#             with open(decrypted_file_path, "rb") as f:
#                 response = HttpResponse(f.read(), content_type="video/mp4")
#                 response['Content-Disposition'] = 'attachment; filename="decrypted_video.mp4"'
#                 return response

#         except Exception as e:
#             print("Decryption Error:", str(e))
#             return render(request, "encrypt_video.html", {"error": "Decryption failed. Please check the input data and try again."})

#     return render(request, "encrypt_video.html")



# import os
# from django.shortcuts import render, get_object_or_404
# from django.http import HttpResponse
# from django.contrib.auth.models import User
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from .models import UserKeys
# from PIL import Image
# import io
# import base64

# def encrypt_image(request):
#     if request.method == "POST" and request.FILES.get("image"):
#         receiver_username = request.POST.get("receiver_username")
#         image_file = request.FILES["image"]

#         try:
#             # Convert image to bytes
#             image = Image.open(image_file)
#             if image.mode != 'RGB':
#                 image = image.convert('RGB')
#             width, height = image.size
#             image_bytes = image.tobytes()

#             # Fetch current user's private key
#             current_user = request.user
#             current_user_keys = get_object_or_404(UserKeys, user=current_user)
#             private_key = serialization.load_pem_private_key(
#                 current_user_keys.private_key.encode(),
#                 password=None,
#                 backend=default_backend()
#             )

#             # Fetch receiver's public key
#             receiver = get_object_or_404(User, username=receiver_username)
#             receiver_keys = get_object_or_404(UserKeys, user=receiver)
#             public_key = serialization.load_pem_public_key(
#                 receiver_keys.public_key.encode(),
#                 backend=default_backend()
#             )

#             # Derive shared key using ECDH
#             shared_key = private_key.exchange(ec.ECDH(), public_key)
#             derived_key = HKDF(
#                 algorithm=hashes.SHA256(),
#                 length=32,
#                 salt=None,
#                 info=b'handshake data',
#                 backend=default_backend()
#             ).derive(shared_key)

#             # Generate IV
#             iv = os.urandom(16)

#             # Encrypt the image using AES
#             cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
#             encryptor = cipher.encryptor()
#             encrypted_data = encryptor.update(image_bytes) + encryptor.finalize()

#             # Create encrypted image
#             encrypted_image = Image.frombytes('RGB', (width, height), encrypted_data[:width*height*3])

#             # Encode IV as base64 and embed it in the filename
#             iv_base64 = base64.b64encode(iv).decode('utf-8')
            
#             # Save to BytesIO object
#             img_io = io.BytesIO()
#             encrypted_image.save(img_io, 'PNG')
#             img_io.seek(0)

#             # Return the encrypted image with IV in filename
#             response = HttpResponse(img_io.getvalue(), content_type='image/png')
#             response['Content-Disposition'] = f'attachment; filename="encrypted_{iv_base64}_{width}_{height}.png"'
#             return response

#         except Exception as e:
#             print("Encryption Error:", str(e))
#             return render(request, "encrypt_image.html", 
#                         {"error": f"Encryption failed: {str(e)}"})

#     return render(request, "encrypt_image.html")

# def decrypt_image(request):
#     if request.method == "POST" and request.FILES.get("encrypted_image"):
#         sender_username = request.POST.get("sender_username")
#         encrypted_image_file = request.FILES["encrypted_image"]

#         try:
#             # Extract IV and dimensions from filename
#             filename = encrypted_image_file.name
#             parts = filename.split('_')
#             if len(parts) < 4:
#                 raise ValueError("Invalid encrypted image filename format")
            
#             iv_base64 = parts[1]
#             width = int(parts[2])
#             height = int(parts[3].split('.')[0])
            
#             # Decode IV from base64
#             iv = base64.b64decode(iv_base64)

#             # Read the encrypted image
#             encrypted_image = Image.open(encrypted_image_file)
#             if encrypted_image.mode != 'RGB':
#                 encrypted_image = encrypted_image.convert('RGB')
#             encrypted_bytes = encrypted_image.tobytes()

#             # Fetch current user's private key
#             current_user = request.user
#             current_user_keys = get_object_or_404(UserKeys, user=current_user)
#             private_key = serialization.load_pem_private_key(
#                 current_user_keys.private_key.encode(),
#                 password=None,
#                 backend=default_backend()
#             )

#             # Fetch sender's public key
#             sender = get_object_or_404(User, username=sender_username)
#             sender_keys = get_object_or_404(UserKeys, user=sender)
#             public_key = serialization.load_pem_public_key(
#                 sender_keys.public_key.encode(),
#                 backend=default_backend()
#             )

#             # Derive the same shared key
#             shared_key = private_key.exchange(ec.ECDH(), public_key)
#             derived_key = HKDF(
#                 algorithm=hashes.SHA256(),
#                 length=32,
#                 salt=None,
#                 info=b'handshake data',
#                 backend=default_backend()
#             ).derive(shared_key)

#             # Decrypt the image
#             cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
#             decryptor = cipher.decryptor()
#             decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()

#             # Create decrypted image
#             decrypted_image = Image.frombytes('RGB', (width, height), decrypted_data[:width*height*3])

#             # Save to BytesIO object
#             img_io = io.BytesIO()
#             decrypted_image.save(img_io, 'PNG')
#             img_io.seek(0)

#             # Return the decrypted image
#             response = HttpResponse(img_io.getvalue(), content_type='image/png')
#             response['Content-Disposition'] = f'attachment; filename="decrypted_image.png"'
#             return response

#         except Exception as e:
#             print("Decryption Error:", str(e))
#             return render(request, "encrypt_image.html", 
#                         {"error": f"Decryption failed: {str(e)}"})

#     return render(request, "encrypt_image.html")