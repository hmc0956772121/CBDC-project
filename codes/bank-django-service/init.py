# 啟動腳本
import subprocess
import time

def main():
    for i in range(20):
        # 嘗試進行資料庫操作，如果操作失敗則嘗試重新連線，因為MySQL的啟動時間較長，所以重試直到連上。
        try:
            subprocess.run(['python','/code/manage.py','migrate'], check = True)
            subprocess.run(['python','/code/manage.py','loaddata','app_core/fixtures/data.json'], check = True)
            subprocess.run(['python','/code/manage.py','runserver','0.0.0.0:8000'], check = True)
            subprocess.run(['chmod','+x','Test'], check = True)
            break
        except subprocess.CalledProcessError:
            print("資料庫連線重試...")
        # 等待2秒重試
        time.sleep(2)
    # 嘗試20次後接受失敗，調整資料庫配置或者Django程式。
    raise Exception("資料庫連線失敗，或者面對其他Django啟動失敗問題，請檢修資料庫與Django主程式。")

if __name__ == '__main__':
    main()