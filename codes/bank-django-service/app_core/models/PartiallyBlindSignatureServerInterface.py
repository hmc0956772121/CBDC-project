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
user寄送-1

C1: int:加密的訊息。
C2: int:加密的ECDSA鑰匙簽章。

Zero­KnowledgeProof_C1p_list: List，20個C1'的
Zero­KnowledgeProof_C2p_list: List，20個C2'的

Zero­KnowledgeProofParameters: List，儲存著(x,r')或者(x',r'')兩種混合成的序列。
=================
signer寄送-2

i_list: 20個，1~40之間的數字。
C: int，簽章。
=================
user寄送-2

L: List，被選擇的l list，除了l_j
=================
signer寄送-3

C: int，簽章。
=================
"""
class PartiallyBlindSignatureServerInterface:
    def __init__(self, token:str):
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
    def create_or_load_status(self, token:str):
        status = dict()
        if self.redis_connection.exists(token):
            self.status = json.loads(self.redis_connection.get(token))
        else:
            status['zero_knowledge_proof_step'] = 1
            status['i_list'] = self.generate_i_list()
            status['b_list'] = self.generate_b_list()
            self.redis_connection.set(token, json.dumps(status))
            self.status = status
