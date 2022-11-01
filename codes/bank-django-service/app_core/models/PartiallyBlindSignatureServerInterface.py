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

F1 ~ Fn: 加密的公開訊息Hash
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
        self.q = publicKey.curve.N
        # 零知識證明次數
        self.NumberOfZeroKnowledgeProofRound = 20
        # User端的L長度
        self.LengthOfL = 40
        self.LengthOfi = 20
        # Redis 連線
        self.redis_connection = redis.Redis(host=os.environ['REDIS_IP'], port=6379, db=0, password=os.environ['REDIS_PASSWORD'])
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
        status = json.loads(self.redis_connection.get(token))
        if 'step' in status:
            self.status = status
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
        if self.status["step"] == 1:
            raise Exception("第一步驟，從簽署者輸出公鑰，不需要輸入任何東西。")
        elif self.status["step"] == 2:
            input = json.loads(input)
            self.status["C1"] = input["C1"]
            self.status["C2"] = input["C2"]
            self.status["N"] = input["N"]
            self.status["g"] = input["g"]
            self.zero_knowledge_proof_vefify(input)
        elif self.status["step"] == 3:
            pass
        elif self.status["step"] == 4:
            pass

    # 取得輸出
    def output(self):
        if self.status["step"] == 1:
            return json.dumps({"K1x":self.K1x, "K1y":self.K1y, "b_list":self.status["b_list"]})

    # 零知識證明驗證
    def zero_knowledge_proof_vefify(self, input:dict):
        result = True
        Yi = YiModifiedPaillierEncryptionPy()
        # 零知識證明，重複驗證40次
        for i in range(self.NumberOfZeroKnowledgeProofRound):
            b = self.status["b_list"][i]
            ZeroKnowledgeProofC1List = input["ZeroKnowledgeProofC1List"]
            ZeroKnowledgeProofC2List = input["ZeroKnowledgeProofC2List"]
            C1p = ZeroKnowledgeProofC1List[i]['Cp']
            C2p = ZeroKnowledgeProofC2List[i]['Cp']
            # 若該次的詢問內容為0 
            if b == 0:
                C1_x = ZeroKnowledgeProofC1List[i]['x']
                C1_rp = ZeroKnowledgeProofC1List[i]['rp']
                C1p_test = Yi.encrypt(C1_x, self.status["N"], self.status["g"],C1_rp,self.q)

                C2_x = ZeroKnowledgeProofC2List[i]['x']
                C2_rp = ZeroKnowledgeProofC2List[i]['rp']
                C2p_test = Yi.encrypt(C2_x, self.status["N"], self.status["g"],C2_rp,self.q)

                if C1p_test != C1p:
                    result = False
                    break

                if C2p_test != C2p:
                    result = False
                    break
            # 若該次的詢問內容為1
            elif b == 1:
                C1_xp = ZeroKnowledgeProofC1List[i]['xp']
                C1_rpp = ZeroKnowledgeProofC1List[i]['rpp']
                C1C1p_mod_q = gmpy2.mod(gmpy2.mul(self.status['C1'], C1p), pow(self.status['N'],2))
                C1C1p_test = Yi.encrypt(C1_xp, self.status["N"],self.status["g"],C1_rpp,self.q)
                
                C2_xp = ZeroKnowledgeProofC2List[i]['xp']
                C2_rpp = ZeroKnowledgeProofC2List[i]['rpp']
                C2C2p_mod_q = gmpy2.mod(gmpy2.mul(self.status['C2'], C2p), pow(self.status['N'],2))
                C2C2p_test = Yi.encrypt(C2_xp, self.status["N"],self.status["g"],C2_rpp,self.q)

                if C1C1p_mod_q != C1C1p_test:
                    result = False
                    break
            
                if C2C2p_mod_q != C2C2p_test:
                    result = False
                    break
        return result

