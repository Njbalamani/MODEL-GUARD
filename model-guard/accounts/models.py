from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Platform Administrator"
        RESEARCHER = "RESEARCHER", "ML Researcher"
        ANALYST = "ANALYST", "Security Analyst"
        VIEWER = "VIEWER", "Viewer"

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.RESEARCHER)
    organization = models.CharField(max_length=160, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["role"])]

    def can_manage(self) -> bool:
        return self.role in {self.Role.ADMIN, self.Role.RESEARCHER}
