from django.urls import path

from projects.views import (
    PolicyListView, ProjectCreateView, ProjectDetailView, ProjectListView,
    ReferenceDatasetListView, create_policy, evaluate_policy_view,
    policy_detail, upload_reference,
)

app_name = "projects"

urlpatterns = [
    path("", ProjectListView.as_view(), name="list"),
    path("create/", ProjectCreateView.as_view(), name="create"),
    path("<int:pk>/", ProjectDetailView.as_view(), name="detail"),
    path("policies/", PolicyListView.as_view(), name="policy-list"),
    path("policies/<int:project_id>/create/", create_policy, name="policy-create"),
    path("policies/<int:pk>/detail/", policy_detail, name="policy-detail"),
    path("policies/<int:pk>/evaluate/", evaluate_policy_view, name="policy-evaluate"),
    path("references/", ReferenceDatasetListView.as_view(), name="reference-list"),
    path("references/<int:project_id>/upload/", upload_reference, name="reference-upload"),
]
