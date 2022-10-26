from .User import User
import hashlib
import json 
import redis
import os
import uuid

class Login():
    """登入類別
    撰寫: 蕭維均
    """
    def check_account(self, account:str):
        user_exist =  User.objects.filter(account__contains=account).count()
        return True if user_exist == 1 else False

    def check_password(self,account:str ,password:str):
        password = password.encode('utf-8')
        password_hash = hashlib.sha256(password).hexdigest()
        result = User.objects.filter(account = account, password_hash = password_hash).count()
        return True if result == 1 else False

    def setUserToken(self,account:str):
        # 生成Token 
        token = uuid.uuid4().hex
        json_data = json.dumps({'account':account})
        
        # Redis 連線物件
        redis_connection_token_index = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=0, password=os.environ['REDIS_PASSWORD'])
        redis_connection_user_index = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=1, password=os.environ['REDIS_PASSWORD'])

        # 檢查使用者是否在已經登入的用戶表中，終止後續程序，回傳Token
        if redis_connection_user_index.exists(account):
            return redis_connection_user_index.get(account).decode("utf-8") 

        # 將使用者加入已經登入的使用者表單
        redis_connection_user_index.set(account,token)
        redis_connection_user_index.expire(account,300)

        # 用 uuid 作為使用者的Token
        redis_connection_token_index.set(token,json_data)
        redis_connection_token_index.expire(token,300) # 300 秒，5分鐘超時。

        return token

    # 登入方法
    def login(self, request):
        data = None
        result =dict()

        # 無論GET或者POST都接收，之後依照需求修改
        if request.method == 'GET':
            data = request.GET
        elif request.method == 'POST':
            data = request.POST

        # 檢查 Requests 參數是否正確
        try:
            account = data['account']
            password = data["password"]
        except:
            result = {'code':0, 'message':'Login format wrong.'}
            result = json.dumps(result)
            return result

        # 檢查帳號密碼是否存在 
        if self.check_account(account):
            if self.check_password(account, password):
                result = {'code':1, 'message':'Login success.'}
                uuid_token = self.setUserToken(account)
                result["token"] = uuid_token
            else:
                result = {'code':0, 'message':'Login fail.'}
        else:
            result = {'code':0, 'message':'Login fail.'}

        result = json.dumps(result)
        return result

    # 檢查是否登入
    def check_login(self, request):
        data = None
        result =dict()
        token = None
        redis_connection = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=0, password=os.environ['REDIS_PASSWORD'])

        # 無論GET或者POST都接收，之後依照需求修改
        if request.method == 'GET':
            data = request.GET
        elif request.method == 'POST':
            data = request.POST

        # 檢查Token 是否正確，同時相容token存在於cookie或者request中。
        if "token" in data:
            token = data["token"]
        elif "token" in request.COOKIES:
            token = request.COOKIES["token"]

        # 檢查 Redis 中是否存在該Token
        if redis_connection.exists(token):
            result = {'code':1,'message':'Login success.'}
        else:
            result = {'code':0,'message':'Login fail.'}

        result = json.dumps(result)
        return result