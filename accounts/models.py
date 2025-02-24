from django.db import models
from django.contrib.auth.models import User

class UserKeys(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="keys")
    public_key = models.TextField()
    private_key = models.TextField()

    def __str__(self):
        return self.user.username
'''
class ImageHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    sender_username = models.CharField(max_length=150, null=True, blank=True)
    receiver_username = models.CharField(max_length=150, null=True, blank=True)
    encrypted_image = models.TextField()  # Store Base64 encoded encrypted image
    decrypted_image = models.ImageField(upload_to="decrypted_images/", null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"History for {self.user.username} at {self.timestamp}"'''
