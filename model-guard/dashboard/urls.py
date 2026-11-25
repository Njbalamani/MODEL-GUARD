from django.urls import path

from dashboard.views import ChartDataView, HomeView

app_name = "dashboard"

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("api/chart-data/", ChartDataView.as_view(), name="chart-data"),
]
