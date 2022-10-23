from .User import User
import hashlib
import json 
import redis
import os
import uuid

class Login():
    """
    登入類別
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
        redis_connection = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=0, password=os.environ['REDIS_PASSWORD'])
        # 檢查使用者是否在已經登入的用戶表中，終止後續程序
        if redis_connection.exists('login_user_list'):
            user_list = json.loads(redis_connection.get('login_user_list'))
            if account in user_list:
                if redis_connection.exists(user_list[account]):
                    redis_connection.expire(user_list[account],300)
                    return user_list[account]
                else:
                    redis_connection.delete(user_list[account])                    

        # 用 uuid 作為使用者的Token
        uuid_str = uuid.uuid4().hex
        json_data = json.dumps({'account':account})
        redis_connection.set(uuid_str,json_data)
        redis_connection.expire(uuid_str,300)

        # 將使用者加入已經登入的使用者表單
        user_list = dict()
        if redis_connection.exists('login_user_list'):
            user_list = json.loads(redis_connection.get('login_user_list'))
        user_list[account] = uuid_str
        redis_connection.set('login_user_list',json.dumps(user_list))
        return uuid_str

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

        # 無論GET或者POST都接收，之後依照需求修改
        if request.method == 'GET':
            data = request.GET
        elif request.method == 'POST':
            data = request.POST

        # 檢查 Requests 參數是否正確
        try:
            token = data["token"]
        except:
            result = {'code':0, 'message':'Parameters format wrong.'}
            result = json.dumps(result)
            return result

        redis_connection = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=0, password=os.environ['REDIS_PASSWORD'])

        if redis_connection.exists(token):
            result = {'code':1,'message':'Login success.'}
        else:
            result = {'code':0,'message':'Login fail.'}

        result = json.dumps(result)
        return result