from django.shortcuts import render
from django.http import HttpResponse
from .models import Login

"""
前端頁面

請先在templates資料夾中建立HTML
然後依照以下方式建立一個連接到頁面的view:

def 頁面名稱(request):
    return render(request, '頁面名稱/index.html')

之後到 urls.py 來將網址聯繫到這個view
"""
def index(request):
    return render(request, 'index/index.html')

def login(request):
    return render(request, 'login/index.html')

"""
API

使用方法如下:

def 此API的名稱(request):
    自己建立的model實例 = 自己建立的model()
    回傳結果 = 自己建立的model實例.方法(request)
    return HttpResponse(回傳結果)

之後到 urls.py 來將網址聯繫到這個view
"""
def login_api(request):
    login =Login()
    result = login.login(request)
    return HttpResponse(result)

# 檢查登入 API
def check_login(request):
    login =Login()
    result = login.check_login(request)
    return HttpResponse(result)