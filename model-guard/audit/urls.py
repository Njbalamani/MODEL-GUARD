from django.urls import path

from audit.views import (
    audit_export_csv, audit_export_page, webhook_create, webhook_delete,
    webhook_deliveries, webhook_edit, webhook_list,
)

app_name = "audit"

urlpatterns = [
    path("", audit_export_page, name="export-page"),
    path("export.csv", audit_export_csv, name="export-csv"),
    path("webhooks/", webhook_list, name="webhook-list"),
    path("webhooks/create/", webhook_create, name="webhook-create"),
    path("webhooks/<int:pk>/edit/", webhook_edit, name="webhook-edit"),
    path("webhooks/<int:pk>/delete/", webhook_delete, name="webhook-delete"),
    path("webhooks/<int:pk>/deliveries/", webhook_deliveries, name="deliveries"),
]
