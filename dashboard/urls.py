from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('login/enhanced/', views.enhanced_login_view, name='enhanced_login'),
    path('login/google-test/', views.google_test_view, name='google_test'),
    path('login/google-onetap/', views.google_onetap_view, name='google_onetap'),
    path('test/', views.simple_test_view, name='simple_test'),
    path('logout/', views.logout_view, name='logout'),
]