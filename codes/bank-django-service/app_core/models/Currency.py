from django.db import models

# 使用者資料表
class Currency(models.Model):
    user_id = models.IntegerField()
    balance = models.IntegerField()