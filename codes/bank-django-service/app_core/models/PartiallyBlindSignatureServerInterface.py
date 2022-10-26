import hashlib
import pprint
import json
import os
import redis
import ellipticcurve
from ellipticcurve.privateKey import PrivateKey, PublicKey
import gmpy2
import random
from .YiModifiedPaillierEncryptionPy import YiModifiedPaillierEncryptionPy
"""
Note
=================
signer寄送-1

K1x: int，ECDSA 公鑰
K1y: int，ECDSA 公鑰
b_list: 一串0/1，20個。
=================
user寄送-2

C1: int:加密的訊息。
C2: int:加密的ECDSA鑰匙簽章。

ZeroKnowledgeProofC1List: List，20個C1'的零知識證明參數與(x,r')或者(x',r'')兩種混合成的序列。
ZeroKnowledgeProofC2List: List，20個C2'的零知識證明參數(x,r')或者(x',r'')兩種混合成的序列。

N: Yi的公鑰1
g: Yi的公鑰2
=================
signer寄送-3

i_list: 20個，1~40之間的數字。
C: int，簽章。
=================
user寄送-4

L: List，被選擇的l list，除了l_j
=================
signer寄送-5

C: int，簽章。
=================
"""
class PartiallyBlindSignatureServerInterface:
    def __init__(self, token:str):
        # 逾期時間(秒)
        self.expiretime = 300
        # 從環境變數取得ECDSA鑰匙
        self.ECDSA_PUBLICKEY = os.environ['ECDSA_PUBLICKEY']
        self.ECDSA_PRIVATEKEY = os.environ['ECDSA_PRIVATEKEY']
        # 從ECDSA PUBLICKEY取得X,Y軸
        publicKey = PublicKey.fromPem(self.ECDSA_PUBLICKEY)
        self.K1x = publicKey.point.x
        self.K1y = publicKey.point.y
        # 零知識證明次數
        self.NumberOfZeroKnowledgeProofRound = 20
        # User端的L長度
        self.LengthOfL = 40
        self.LengthOfi = 20
        # Redis 連線
        self.redis_connection = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=2, password=os.environ['REDIS_PASSWORD'])
        # 檢查使用者當前進行到的步驟
        self.status = dict()
        self.create_or_load_status(token)

    # 生成隨機二進位序列
    def generate_b_list(self):
        b_list = [ random.randrange(2) for i in range(self.NumberOfZeroKnowledgeProofRound) ]
        return b_list

    # 生成隨機選擇0-40之間的數值不重複
    def generate_i_list(self):
        i_list = []
        for i in range(self.LengthOfi):
            temp_number = random.randrange(self.LengthOfL+1)
            if temp_number not in i_list:
                i_list.append(temp_number)
        i_list.sort()
        return i_list

    # 創建新的認證狀態，或者載入舊的
    def create_or_load_status(self,token):
        status = dict()
        if self.redis_connection.exists(token):
            self.status = json.loads(self.redis_connection.get(token))
        else:
            status['step'] = 1
            status['i_list'] = self.generate_i_list()
            status['b_list'] = self.generate_b_list()
            self.redis_connection.set(token, json.dumps(status))
            self.redis_connection.expire(token, self.expiretime)
            self.status = status

    # 儲存並且前進到下個步驟
    def save_and_next_step(self,token):
        self.status['step'] += 1
        self.redis_connection.set(token,json.dumps(self.status))
        self.redis_connection.expire(token, self.expiretime)

    # 取得使用者輸入
    def input(self,input):
        if self.status["step"] == 2:
            input = json.loads(input)
            self.status["C1"] = input["C1"]
            self.status["C2"] = input["C2"]
            self.status["N"] = input["N"]
            self.status["g"] = input["g"]
            self.zero_knowledge_proof_vefify(input)

    # 取得輸出
    def output(self):
        if self.status["step"] == 1:
            return json.dumps({"K1x":self.K1x, "K1y":self.K1y, "b_list":self.status["b_list"]})

    # 零知識證明驗證
    def zero_knowledge_proof_vefify(self, input:dict):
        for i in range(self.NumberOfZeroKnowledgeProofRound):
            ZeroKnowledgeProofC1List = input["ZeroKnowledgeProofC1List"]
            print(ZeroKnowledgeProofC1List[i]['Cp'])