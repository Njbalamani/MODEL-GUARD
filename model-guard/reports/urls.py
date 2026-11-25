from django.urls import path

from reports.views import detail, download, generate, report_list, verify_signature

app_name = "reports"

urlpatterns = [
    path("", report_list, name="list"),
    path("generate/<int:assessment_id>/", generate, name="generate"),
    path("<int:pk>/", detail, name="detail"),
    path("<int:pk>/download/", download, name="download"),
    path("<int:pk>/verify/", verify_signature, name="verify"),
]
