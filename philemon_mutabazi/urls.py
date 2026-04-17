from django.urls import path

from . import views

app_name = "philemon_mutabazi"

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.UserLoginView.as_view(), name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    path("privileged/", views.PrivilegedDashboardView.as_view(), name="privileged_dashboard"),
    path("profile/", views.ProfileRedirectView.as_view(), name="profile"),
    path("profile/<str:username>/", views.ProfileDetailView.as_view(), name="profile_detail"),
    path(
        "profile/<str:username>/files/<str:file_kind>/",
        views.ProfileFileDownloadView.as_view(),
        name="profile_file_download",
    ),
    path("password-change/", views.UserPasswordChangeView.as_view(), name="password_change"),
    path("password-reset/", views.UserPasswordResetView.as_view(), name="password_reset"),
    path("password-reset/done/", views.UserPasswordResetDoneView.as_view(), name="password_reset_done"),
    path("password-reset/<uidb64>-<token>/", views.UserPasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("password-reset/complete/", views.UserPasswordResetCompleteView.as_view(), name="password_reset_complete"),
]
