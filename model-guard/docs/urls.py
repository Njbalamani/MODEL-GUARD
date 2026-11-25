from django.urls import path

from docs.views import APIDocsView, ArchitectureView, DocsHomeView, ERDiagramView

app_name = "docs"

urlpatterns = [
    path("", DocsHomeView.as_view(), name="home"),
    path("architecture/", ArchitectureView.as_view(), name="architecture"),
    path("er-diagram/", ERDiagramView.as_view(), name="er"),
    path("api/", APIDocsView.as_view(), name="api"),
]
