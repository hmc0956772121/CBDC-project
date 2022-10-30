from django.shortcuts import redirect
from app_core.models.Login import Login
from app_core.urls import none_login_pages

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

    def __call__(self, request):
        verify_login_result =self.login.check_login_from_request(request)
        if request.path not in self.none_login_pages and "api" not in request.path:
            if not verify_login_result:
                return redirect("/login")
        else:
            if verify_login_result and "api" not in request.path:
                return redirect("/")
        response = self.get_response(request)
        return response