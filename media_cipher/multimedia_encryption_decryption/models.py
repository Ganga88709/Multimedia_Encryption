from django.db import models
from django.contrib.auth.models import User

class UserKeys(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="keys")
    public_key = models.TextField()
    private_key = models.TextField()

    def __str__(self):
        return self.user.username
