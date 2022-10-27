import hashlib
from operator import ge
from pprint import pprint
import json
import os
from unittest import result
import redis
import ellipticcurve
from ellipticcurve.privateKey import PrivateKey, PublicKey
import gmpy2
import random
from math import gcd
from copy import deepcopy
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
class PartiallyBlindSignatureClientInterface:
    def __init__(self):
        self.n = 40 # 決定隨機數l_list的數字數量
        
        # Yi的公私鑰匙
        # 私鑰
        self.p = None
        self.k = None
        # 公鑰
        self.N = None
        self.g = None

        # 二進位序列
        self.b_list = None

        # 訊息相關與Hash
        self.message_hash = None # 訊息的SHA256轉換成整數
        self.I = None # 雙方共識訊息info的hash

        # 簽章
        self.t = None # 用來簽署簽署者的公鑰的數值
        
        # 加密混淆用隨機數
        self.r1 = None
        self.r2 = None

        # 私鑰
        self.k2 = None

        # 密文
        self.C1 = None
        self.C2 = None

        # ECDSA曲線參數 - secp256k1
        self.curve_A = 0
        self.curve_B = 7
        self.curve_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337 #等同該演算法中的q
        self.curve_P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        self.curve_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        self.curve_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        self.q = self.curve_N

        # ECDSA 點
        self.K = None # 使用者 ECDSA 的公鑰x,y座標，可以用 self.K.x, self.K.y
        self.K1 = None # 簽署者 ECDSA 的公鑰x,y座標，self.K1.x, self.K1.y

        # 零知識證明次數
        self.NumberOfZeroKnowledgeProofRound = 20

        # 列表
        self.l_list = None # 由n個小於phi(N^2)並且與N互質的整數組成。
        self.LengthOfL = 40 # L 列表長度

    def set_K1(self, K1_x, K1_y):
        """設置點K1

        K1是個由 x, y 兩座標組成的橢圓曲線上的點，也就是簽署者 ECDSA 的公鑰。
        """
        self.K1 = ellipticcurve.point.Point(K1_x, K1_y) # 使用ECDSA函數庫的點物件

    def hash_H(self, message:str):
        """Hash函數H()

        使用SHA256，Hash算法
        """
        bytes_string = bytes(message, 'utf-8')
        h = hashlib.new('sha256')
        h.update(bytes(message, 'utf-8'))
        hex_string = h.hexdigest()
        message_hash = int(hex_string, 16)
        return message_hash

    def generate_message_hash(self, message:str):
        """設置訊息的Hash值

        輸入訊息後，自動生成Hash值
        """
        self.message_hash = self.hash_H(message) 
        return self.message_hash

    def generate_I(self, info:str):
        self.I = self.hash_H(info)
        return self.I

    def generate_r(self):
        N = self.N
        r = 0
        r = self.find_random_co_prime(pow(N,2))
        self.r = gmpy2.mpz(r)
        return r

    def generate_t(self):
        Kx = gmpy2.mpz(self.K1.x)
        self.t = gmpy2.mod(Kx, self.q)
        return int(self.t)

    def find_random_co_prime(self, n:int):
        result = random.randrange(deepcopy(n)) #尋找極限以下的隨機數
        while gcd(n,result) != 1: # 當與n不互質時
            result += 1 # 往下個數值進行線性搜索。
            if result > n : # 若結果不小心大於目標
                result = random.randrange(deepcopy(n)) #重新尋找隨機數
        return result

    def generate_l_list(self):
        phi_N_square = pow(gmpy2.mul(gmpy2.mul(self.p-1, self.q-1), self.k-1), 2) # phi(N^2)，N平方的歐拉函數
        l_list = []
        for i in range(self.LengthOfL):
            l_list.append(self.find_random_co_prime(phi_N_square))
        return l_list

    def encrypt(self, m:int, N:int, g:int ,r:int, q:int):
        N, g, r, m= gmpy2.mpz(N), gmpy2.mpz(g), gmpy2.mpz(r), gmpy2.mpz(m)
        N_power_2 = pow(N,2)
        # 此處將算式改為 C = [(g^m mod N^2) * (r^N mod N^2)] mod N^2 ，防止數值過大導致的記憶體占滿，或者速度緩慢。
        C = gmpy2.mod(gmpy2.powmod(g, m, N_power_2) * gmpy2.powmod(r, N, N_power_2), N_power_2)
        return int(C)

    def step1_input(self, input:str):
        input_object = json.loads(input)
        self.set_K1(input_object["K1x"], input_object["K1y"])
        self.b_list = input_object["b_list"]

    def generate_keypairs_parameters(self):
        # 生成Yi的公私鑰
        Yi = YiModifiedPaillierEncryptionPy()
        Yi.generate_keypairs(self.q)
        self.p = Yi.p 
        self.k = Yi.k
        self.N = Yi.N
        self.g = Yi.g
        self.r1 = self.generate_r()
        self.r2 = self.generate_r()
        self.k2 = self.find_random_co_prime(self.q)
        self.t = self.generate_t()
        self.K = ellipticcurve.math.Math.multiply(self.K1, int(self.k2), self.curve_N, self.curve_A, self.curve_P)
        self.C1 = self.encrypt(self.message_hash, self.N, self.g, self.r1, self.q)
        self.C2 = self.encrypt(self.t, self.N, self.g, self.r2, self.q)
        self.l_list = self.generate_l_list()

    def generate_zero_know_proof_parameter_set(self,info:int,r:int,b:int)->dict:
        """
        生成零知識證明參數
        如果是C1的話info 就是 Hash(m)
        如果是C2的話info就是Hash(info)
        """
        result = dict()
        temp = dict()
        temp['x'] = random.randrange(self.q)
        temp['rp'] = self.generate_r()
        temp['xp'] = gmpy2.mod(gmpy2.add(info, temp['x']), self.q)
        temp['rpp'] = self.rpp = gmpy2.mod(gmpy2.mul(r, temp['rp'] ), pow(self.N,2))

        if b == 0:
            result['x'] = int(temp['x'])
            result['rp'] = int(temp['rp'])
        elif b == 1:
            result['xp'] = int(temp['xp'])
            result['rpp'] = int(temp['rpp'])

        result['Cp'] = self.encrypt(temp['x'], self.N, self.g, temp['rp'], self.q)

        return result

    def generate_zero_know_proof_parameter_sets(self):
        """
        生成多組C1,C2的零知識證明參數
        """
        result = dict()

        C1_zero_know_proof_parameter_sets = []
        C2_zero_know_proof_parameter_sets = []

        for i in range(self.NumberOfZeroKnowledgeProofRound):
            b = self.b_list[i]
            C1_zero_know_proof_parameter_sets.append(self.generate_zero_know_proof_parameter_set(self.message_hash,self.r1,b))
            C2_zero_know_proof_parameter_sets.append(self.generate_zero_know_proof_parameter_set(self.t,self.r2,b))

        result['ZeroKnowledgeProofC1List'] = C1_zero_know_proof_parameter_sets
        result['ZeroKnowledgeProofC2List'] = C2_zero_know_proof_parameter_sets

        return result

    def step1_output(self):
        result = self.generate_zero_know_proof_parameter_sets()
        result['N'] = int(self.N)
        result['g'] = int(self.g)
        result['C1'] = int(self.C1)
        result['C2'] = int(self.C2)
        return json.dumps(result)
