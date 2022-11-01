
#test word
# 啟動專案Docker容器群 2022/10/25
=======
# CBDC 數位貨幣

該計畫目前屬於開發原型階段，尚未發布。

---
# Notes

## 啟動專案Docker容器群

```
docker-compose up -d --build --force-recreate
```

## 銀行 Django 伺服器

### 命令行登入docker容器

```
docker compose exec bank-django-service bash 
```

不過也可以輸入以下自製指令直接連入。

```
bank-django.bat
```

或者直接點擊檔案 `bank-django.bat`

### 啟動資料庫遷移

我們可以在Django當中撰寫資料庫的原型，可已用這行指令建構所有撰寫好的資料庫原型。

建立遷移腳本

```
python manage.py makemigrations
```

建立啟動遷移腳本

```
python manage.py migrate
```
### 手動建立管理員使用者

```
python manage.py createsuperuser
```

預設的管理員帳號密碼(建議採用)

帳號: root

密碼: dev

### 手動啟動伺服器

```
python manage.py runserver 0.0.0.0:8000
```

### 手動載入測試資料庫資料

```
python manage.py loaddata app_core/fixtures/data.json
```

## Git 添加Fork 上游的方法

將Fork上游pull 到本地端的方法。

1. 添加專案原始版本的儲存庫做為上游。

```
git remote add upstream git@github.com:AlexTrinityBlock/CBDC-project.git
```

2. 將上游拉取，並且解決衝突。

```
git pull upstream master
```

3. 推送上傳到自己的Fork

```
git push origin master
```

4. 到Github頁面發送Pull Request