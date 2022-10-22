from django.db import models

# 使用者資料表
class User(models.Model):
    account = models.CharField(max_length=100)
    password_hash = models.CharField(max_length=100)