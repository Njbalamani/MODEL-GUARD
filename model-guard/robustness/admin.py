from django.contrib import admin

from robustness.models import RobustnessTest


@admin.register(RobustnessTest)
class RobustnessTestAdmin(admin.ModelAdmin):
    list_display = ("assessment", "attack", "status", "accuracy_drop", "created_at")
    list_filter = ("attack", "status")
