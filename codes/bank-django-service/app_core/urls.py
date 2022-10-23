from django.urls import path

from . import views

# 網址連接到View
urlpatterns = [
    # 網站頁面
    path('', views.index, name='index'),
    path('home', views.home, name='home'),
    path('login', views.login, name='login'),

    # API
    path('api/login', views.login_api),
    path('api/check_login', views.check_login),
]