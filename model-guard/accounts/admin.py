from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from accounts.models import User


@admin.register(User)
class ModelGuardUserAdmin(UserAdmin):
    list_display = ("username", "email", "role", "organization", "is_staff")
    list_filter = ("role", "is_staff", "is_superuser")
    fieldsets = UserAdmin.fieldsets + (("ModelGuard", {"fields": ("role", "organization")}),)
