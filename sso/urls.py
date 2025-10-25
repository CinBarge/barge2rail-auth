from django.urls import path
from . import views, auth_views, oauth_views

urlpatterns = [
    # ==========================================
    # OAuth 2.0 AUTHORIZATION SERVER
    # (For PrimeTrade and other client applications)
    # ==========================================
    path('authorize/', oauth_views.authorize, name='oauth_authorize'),
    path('token/', oauth_views.token_exchange, name='oauth_token'),

    # ==========================================
    # UTILITY & HEALTH CHECK
    # ==========================================
    path('health/', views.health_check, name='health_check'),
    path('status/', views.auth_status, name='auth_status'),
    path('me/', views.user_profile, name='user_profile'),

    # ==========================================
    # GOOGLE OAUTH CALLBACK (Internal Flow)
    # ==========================================
    path('google/callback/', auth_views.google_auth_callback, name='google_auth_callback'),

    # ==========================================
    # TOKEN MANAGEMENT
    # ==========================================
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),

    # ==========================================
    # ADMIN ENDPOINTS (If you use them)
    # Uncomment if these views actually exist
    # ==========================================
    # path('applications/', views.ApplicationListCreateView.as_view(), name='application-list'),
    # path('applications/<uuid:pk>/', views.ApplicationDetailView.as_view(), name='application-detail'),
    # path('roles/', views.UserRoleListCreateView.as_view(), name='role-list'),
    # path('roles/<uuid:pk>/', views.UserRoleDetailView.as_view(), name='role-detail'),
]