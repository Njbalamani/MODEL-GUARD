from django.urls import path

from modelregistry.views import (
    ModelDetailView, ModelListView, ModelUploadView, VersionDetailView,
    compare_versions, start_assessment,
)

app_name = "models"

urlpatterns = [
    path("", ModelListView.as_view(), name="list"),
    path("upload/", ModelUploadView.as_view(), name="upload"),
    path("<int:pk>/", ModelDetailView.as_view(), name="detail"),
    path("<int:pk>/compare/", compare_versions, name="compare"),
    path("versions/<int:pk>/", VersionDetailView.as_view(), name="version"),
    path("versions/<int:version_id>/assess/", start_assessment, name="assess"),
]
