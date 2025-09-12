from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.google_oauth_callback, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),  # Use the new clean login template
    path('login/enhanced/', views.enhanced_login_view, name='enhanced_login'),
    path('login/google-test/', views.google_test_view, name='google_test'),
    path('login/google-onetap/', views.google_onetap_view, name='google_onetap'),
    path('login/google-success/', views.google_success_view, name='google_success'),
    path('test/', views.simple_test_view, name='simple_test'),
    path('login/google-diagnostic/', views.google_diagnostic_view, name='google_diagnostic'),
    path('logout/', views.logout_view, name='logout'),
    # Add auth callback for Google OAuth
    path('auth/google/callback/', views.google_oauth_callback, name='google_oauth_callback'),
]
