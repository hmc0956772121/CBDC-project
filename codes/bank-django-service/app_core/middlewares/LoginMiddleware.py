from django.shortcuts import redirect
from app_core.models.Login import Login

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
        self.none_login_pages = [
            "/login",
            "/api/check_login",
        ]

    def __call__(self, request):
        if request.path not in self.none_login_pages :
            if self.login.check_login_from_request(request):
                pass
            else:
                return redirect("/login")
        response = self.get_response(request)
        return response