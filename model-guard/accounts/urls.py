from django.urls import path

from accounts.views import ModelGuardLoginView, ProfileView, SignUpView, modelguard_logout

app_name = "accounts"

urlpatterns = [
    path("login/", ModelGuardLoginView.as_view(), name="login"),
    path("signup/", SignUpView.as_view(), name="signup"),
    path("logout/", modelguard_logout, name="logout"),
    path("profile/", ProfileView.as_view(), name="profile"),
]
