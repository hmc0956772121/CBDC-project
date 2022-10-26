import hashlib
import pprint
import json
import ellipticcurve
from ellipticcurve.privateKey import PrivateKey, PublicKey
import gmpy2
import random
from .YiModifiedPaillierEncryptionPy import YiModifiedPaillierEncryptionPy

class PartiallyBlindSignatureServer(YiModifiedPaillierEncryptionPy):
    """
    部分盲簽章Server端算法類別
    撰寫: 蕭維均
    演算法引用自
    H. Huang, Z. -Y. Liu and R. Tso, "Partially Blind ECDSA Scheme and Its Application to Bitcoin," 2021 IEEE Conference on Dependable and Secure Computing (DSC), 2021, pp. 1-8.
    """
    def __init__(self):
        self.C1 = None
        self.C1p = None
        self.C2 = None
        self.C2p = None
        self.x = None
        self.xp = None
        self.rp = None
        self.rpp = None
        self.b = None

        # 使用者 Yi 同態加密公鑰
        self.N = None
        self.g = None

        # 簽署者 ECDSA 公鑰匙
        self.K1x = None
        self.K1y = None

        # ECDSA曲線參數 - secp256k1
        self.curve_A = 0
        self.curve_B = 7
        self.curve_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337 #等同該演算法中的q
        self.curve_P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        self.curve_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        self.curve_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        self.q = self.curve_N

    def set_K1(self, K1x:int, K1y:int):
        """設置K1
        K1 是簽署者的 ECDSA 公鑰
        """
        self.K1x = K1x
        self.K1y = K1y

    def set_K1_from_pem(self, ECDSA_publickey_string:str):
        """從Pem檔案設置 ECDSA 公鑰點
        從Pem檔案設置 ECDSA 公鑰點
        """
        pass

    def set_user_publickey(self, N:int, g:int):
        """設置使用者公鑰
        設置使用者公鑰，如果沒有使用者公鑰，就沒有辦法進行，後續的驗證運算。
        """
        self.N = N
        self.g = g

    def set_C1(self, C1:int):
        """設置C1，使用者祕密訊息Hash的密文
        """
        self.C1 = C1

    def set_C1p(self, C1p:int):
        """設置C1p，使用者隨機數值生成的密文
        設置C1p，使用者隨機數值生成的密文，內部不含有意義訊息，但可以用來證明使用者以正確的方式生成C1訊息密文。        
        """
        self.C1p = C1p

    def set_C2(self, C2:int):
        """設置C2，可以看做類似使用者 ECDSA 公鑰計算出的結果。
        """
        self.C2 = C2

    def set_C2p(self, C2p:int):
        """設置C2p，使用者隨機數值生成的密文
        設置C2p，使用者隨機數值生成的密文，內部不含有意義訊息，但可以用來證明使用者以正確的方式生成C2訊息密文。        
        """
        self.C1p = C1p

    def generate_b(self):
        self.b = random.randrange(2)
        return self.b

    # 從json字串獲取使用者公鑰
    def set_user_publickey_json(self, user_publickey):
        user_parameters = json.loads(user_publickey)
        self.N = user_parameters["PublicKey_N"]
        self.g = user_parameters["PublicKey_g"]

    # 從json字串獲得零知識證明初始參數
    def set_zero_know_proof_init_parameters_C1_json(self,init_parameters_C1:str):
        user_parameters = json.loads(init_parameters_C1)
        self.C1 = user_parameters["Ciphertext_C1"]
        self.C1p = user_parameters["ZeroKnowledgeProof_C1p"]

    # 從json字串獲得零知識證明初始參數
    def set_zero_know_proof_init_parameters_C2_json(self,init_parameters_C2:str):
        user_parameters = json.loads(init_parameters_C2)
        self.C2 = user_parameters["Ciphertext_C2"]
        self.C2p = user_parameters["ZeroKnowledgeProof_C2p"]

    # 從json字串獲得零知識證明驗證參數
    def set_zero_know_proof_parameters_C1_json(self,parameters_C1:str):
        user_parameters = json.loads(parameters_C1)
        if self.b is 0:
            self.x = user_parameters["ZeroKnowledgeProof_x"]
            self.rp = user_parameters["ZeroKnowledgeProof_rp"]
        elif self.b is 1:
            self.xp = user_parameters["ZeroKnowledgeProof_xp"]
            self.rpp = user_parameters["ZeroKnowledgeProof_rpp"]

    # 從json字串獲得零知識證明驗證參數
    def set_zero_know_proof_parameters_C2_json(self,parameters_C2:str):
        user_parameters = json.loads(parameters_C2)
        if self.b is 0:
            self.x = user_parameters["ZeroKnowledgeProof_x"]
            self.rp = user_parameters["ZeroKnowledgeProof_rp"]
        elif self.b is 1:
            self.xp = user_parameters["ZeroKnowledgeProof_xp"]
            self.rpp = user_parameters["ZeroKnowledgeProof_rpp"]

    # 驗證C1於b=0的時候
    def verify_C1_b0(self):
        C1p_be_verified = self.encrypt(self.x, self.N, self.g, self.rp, self.q)
        if  C1p_be_verified == self.C1p:
            print("驗證成功")
            return True
        else:
            hint = """
                C1' 驗證失敗，這代表使用者並未依照正確算法生成 C1'，或者使用者生成的隨機數範圍不正確。
                """
            raise Exception(hint)

    # 驗證C2於b=0的時候
    def verify_C2_b0(self):
        C2p_be_verified = self.encrypt(self.x, self.N, self.g, self.rp, self.q)
        if  C2p_be_verified == self.C2p:
            print("驗證成功")
            return True
        else:
            hint = """
                C2' 驗證失敗，這代表使用者並未依照正確算法生成 C2'，或者使用者生成的隨機數範圍不正確。
                """
            raise Exception(hint)

    # 驗證C1於b=1的時候
    def verify_C1_b1(self):
        C1_mul_C1p_mod_q = gmpy2.mod(gmpy2.mul(self.C1, self.C1p), pow(self.N,2))
        Number_be_verified = self.encrypt(self.xp, self.N, self.g, self.rpp, self.q)

        if  C1_mul_C1p_mod_q == Number_be_verified:
            print("驗證成功")
            return True
        else:
            hint = """
                C1 驗證失敗，這代表使用者並未依照正確算法生成 C1'，或者使用者生成的隨機數範圍不正確。
                """
            raise Exception(hint)

    # 驗證C2於b=1的時候
    def verify_C2_b1(self):
        C2_mul_C2p_mod_q = gmpy2.mod(gmpy2.mul(self.C2, self.C2p), pow(self.N,2))
        Number_be_verified = self.encrypt(self.xp, self.N, self.g, self.rpp, self.q)

        if  C2_mul_C2p_mod_q == Number_be_verified:
            print("驗證成功")
            return True
        else:
            hint = """
                C2 驗證失敗，這代表使用者並未依照正確算法生成 C2'，或者使用者生成的隨機數範圍不正確。
                """
            raise Exception(hint)

    # 驗證C1
    def verify_C1(self):
        if self.b == 0:
            self.verify_C1_b0()
        elif self.b == 1:
            self.verify_C1_b1()

    # 驗證C2
    def verify_C2(self):
        if self.b == 0:
            self.verify_C2_b0()
        elif self.b == 1:
            self.verify_C2_b1()