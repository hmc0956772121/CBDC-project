from django.db import models

# 使用者資料表
class User(models.Model):
    """使用者資料表
    未完成
    撰寫: 蕭維均
    """
    account = models.CharField(max_length=100)
    password_hash = models.CharField(max_length=100)