from django.shortcuts import render
from django.http import HttpResponse
from .models import Login

# 前端頁面

def index(request):
    # return HttpResponse("index")
    return render(request, 'index/index.html')

def login(request):
    # return HttpResponse("login")
    return render(request, 'login/index.html')

# API 與反饋

# 登入 API
def login_api(request):
    login =Login()
    result = login.login(request)
    return HttpResponse(result)

# 檢查登入 API
def check_login(request):
    login =Login()
    result = login.check_login(request)
    return HttpResponse(result)