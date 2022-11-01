from django.shortcuts import redirect
from app_core.models.Login import Login
from app_core.urls import none_login_pages
from django.http import HttpResponse
import json

class LoginMiddleware:
    """登入驗證中間層
    該中間層管制需要登入的頁面，
    請將不需要登入的頁面，
    撰寫到下方self.none_login_pages中。
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.login = Login()
        
        # 把不用登入的頁面與API寫到這裡
        self.none_login_pages = none_login_pages

    def check_prefix_in_list(self,path:str):
        for path_in_list in self.none_login_pages:
            if path.startswith(path_in_list):
                return True
        return False

    def is_api(self,path:str):
        if path.startswith("/api"):
            return True
        else:   
            return False

    def __call__(self, request):
        verify_login_result =self.login.check_login_from_request(request)
        if not self.check_prefix_in_list(request.path) :
            if not verify_login_result and not self.is_api(request.path):
                return redirect("/login")
            elif not verify_login_result and self.is_api(request.path):
                result = {"code":0,"message":"Required login token"}
                return HttpResponse(json.dumps(result))
        else:
            if verify_login_result and not self.is_api(request.path) and request.path.startswith("/login"):
                return redirect("/")
        response = self.get_response(request)
        return response