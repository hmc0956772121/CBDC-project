from django.db import models

# 使用者資料表
class Currency(models.Model):
    """貨幣資料表
    尚未完成
    撰寫: 蕭維均
    """
    user_id = models.IntegerField()
    balance = models.IntegerField()