import hashlib
import pprint
import json
import ellipticcurve
import gmpy2
import random
from .YiModifiedPaillierEncryptionPy import YiModifiedPaillierEncryptionPy

class PartiallyBlindSignatureClient(YiModifiedPaillierEncryptionPy):
    """
    部分盲簽章Client端算法類別
    撰寫: 蕭維均
    演算法引用自
    H. Huang, Z. -Y. Liu and R. Tso, "Partially Blind ECDSA Scheme and Its Application to Bitcoin," 2021 IEEE Conference on Dependable and Secure Computing (DSC), 2021, pp. 1-8.
    """
    def __init__(self):
        self.n = 40 # 決定隨機數list_l的數字數量
        
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

        # 零知識證明隨機動態參數
        """
        這些參數會隨著每一輪證明，隨機生成的一組
        """
        self.x = None
        self.xp = None #論文中的x'
        self.rp = None #論文中的r'
        self.rpp = None #論文中的r''
        self.C1p = None #論文中的C1'
        self.C2p = None #論文中的C2'

        # 預運算參數
        self.N_power_2 = None

        # 列表
        self.list_l = None # 由n個小於phi(N^2)並且與N互質的整數組成。

        # 狀態
        self.isKeysGenerated = False # 是否設定好鑰匙與公開參數。

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

    def generate_keypairs_parameters(self, q:int=0):
        """生成鑰匙與參數

        生成客戶端的鑰匙與公共參數。
        """
        # 提示
        if q == 0:
            q = self.q
        if self.isKeysGenerated == True:
            hint = """
                 鑰匙已經被設置，避免覆蓋原本鑰匙，中止程序。"""
            raise Exception(hint)
        if self.K1 is None:
            hint = """
                 K1是個由 x, y 兩座標組成的橢圓曲線上的點，也就是簽署者 ECDSA 的公鑰。
                 請先從簽署者取得該公鑰點，以下列方式設置:
                 PBC = HongxunHuangPartallyBlindSignatureClient()
                 PBC.set_K1(K1x, K1y)
                 """
            raise Exception(hint)
        if self.message_hash is None:
            hint = """
                 請先將與簽署者共識的訊息輸入，然後該類別將會自動生成此訊息的Hash，方法如下:
                 PBC = HongxunHuangPartallyBlindSignatureClient()
                 PBC.generate_message_hash("天氣好")
                 """
            raise Exception(hint)
        if self.I is None:
            hint = """
                 請先將與簽署者的共識訊息輸入，然後該類別將會自動生成此訊息的Hash，方法如下:
                 PBC = HongxunHuangPartallyBlindSignatureClient()
                 PBC.generate_I("使用者:123")
                 """
            raise Exception(hint)
        # 生成參數
        super().generate_keypairs(q)
        self.r1 = self.generate_r(self.N)
        self.r2 = self.generate_r(self.N)
        self.k2 = self.generate_k2()
        self.t = self.generate_t()
        self.K = ellipticcurve.math.Math.multiply(self.K1, int(self.k2), self.curve_N, self.curve_A, self.curve_P)
        self.generate_C1()
        self.generate_C2()
        self.generate_list_l()
        self.isKeysGenerated = True
        self.N_power_2 = pow(self.N,2)
        return self.get_keypairs_parameters()

    def generate_list_l(self):
        """生成由數個l組成的l列表

        每個l元素都是從小於phi(N平方)並且與N互質的數值中隨機挑選的。(phi此指歐拉函數)
        N = p*q*k 而p,q,k是質數，質數的歐拉函數為'該質數減一'
        phi(N) = phi(p) * phi(q) *phi(k)
        phi(N) = (p-1) * (q-1) * (k-1)
        """
        phi_N_square = pow(gmpy2.mul(gmpy2.mul(self.p-1, self.q-1), self.k-1), 2) # phi(N^2)，N平方的歐拉函數
        self.list_l = []
        for i in range(self.n):
            self.list_l.append(self.find_random_co_prime(phi_N_square))
        return self.list_l

    def generate_t(self):
        if self.K1 is None:
            raise Exception("K1也就是來自簽署者的ECDSA公鑰點，尚未被設置，設置後才可生成t")
        Kx = gmpy2.mpz(self.K1.x)
        self.t = gmpy2.mod(Kx, self.q)
        return int(self.t)

    def generate_k2(self):
        """生成私鑰k2

        在該算法中用來簽屬者寄送過來的一個橢圓曲線上的點 K1 ，將跳躍 k2 次到達另外一個點，也就是使用者公鑰 K 。
        """
        self.k2 = self.find_random_co_prime(self.q)
        return self.k2

    # 密文
    def generate_C1(self):
        self.C1 = self.encrypt(self.message_hash, self.N, self.g, self.r1, self.q)
        return self.C1

    def generate_C2(self):
        self.C2 = self.encrypt(self.t, self.N, self.g, self.r2, self.q)
        return self.C2

    # 零知識證明
    def generate_x(self):
        """生成零知識證明臨時參數x

        零知識證明臨時參數x，從0到(q-1)之間隨機選擇。
        """
        self.x = random.randrange(self.q)
        return self.x

    def generate_rp(self):
        """生成零知識證明臨時參數r'

        零知識證明臨時參數r'，小於N^2並且與N^2互質的隨機數。
        """
        self.rp = self.generate_r(self.N)
        return self.rp

    def generate_xp_for_C1(self):
        """生成零知識證明臨時參數x'

        零知識證明臨時參數x'，H()是hash函數，m是訊息，
        (H(m) + x) % q
        """
        self.xp = gmpy2.mod(gmpy2.add(self.message_hash, self.x), self.q)
        return self.xp

    def generate_xp_for_C2(self):
        """生成零知識證明臨時參數x'

        零知識證明臨時參數x'，H()是hash函數，m是訊息，
        (H(m) + x) % q
        """
        self.xp = gmpy2.mod(gmpy2.add(self.t, self.x), self.q)
        return self.xp

    def generate_rpp_for_C1(self):
        """生成零知識證明臨時參數r''，用於C1

        零知識證明臨時參數r''，(r1*r') % (N^2)
        """
        self.rpp = gmpy2.mod(gmpy2.mul(self.r1, self.rp), self.N_power_2)
        return self.rpp

    def generate_rpp_for_C2(self):
        """生成零知識證明臨時參數r''，用於C2

        零知識證明臨時參數r''，(r2*r') % (N^2)
        """
        self.rpp = gmpy2.mod(gmpy2.mul(self.r2, self.rp), self.N_power_2)
        return self.rpp

    def generate_C1p(self):
        self.C1p = self.encrypt(self.x, self.N, self.g, self.rp, self.q)
        return self.C1p

    def generate_C2p(self):
        self.C2p = self.encrypt(self.x, self.N, self.g, self.rp, self.q)
        return self.C2p

    def generate_zero_know_proof_parameters_C1(self):
        self.generate_x()
        self.generate_rp()
        self.generate_C1p()
        self.generate_xp_for_C1()
        self.generate_rpp_for_C1()

    def generate_zero_know_proof_parameters_C2(self):
        self.generate_x()
        self.generate_rp()
        self.generate_C2p()
        self.generate_xp_for_C2()
        self.generate_rpp_for_C2()

    def zero_know_proof_parameters_vefify_C1(self):
        A = gmpy2.mod(gmpy2.mul(self.C1, self.C1p), self.N_power_2)
        B = self.encrypt(self.xp, self.N, self.g, self.rpp, self.q)
        if A == B:
            print("C1 驗證成功")
        else:
            print("C1 驗證失敗")
            print("A: ",A)
            print("B: ",B)

    def zero_know_proof_parameters_vefify_C2(self):
        A = gmpy2.mod(gmpy2.mul(self.C2, self.C2p), self.N_power_2)
        B = self.encrypt(self.xp, self.N, self.g, self.rpp, self.q)
        if A == B:
            print("C2 驗證成功")
        else:
            print("C2 驗證失敗")
            print("A: ",A)
            print("B: ",B)

    # 取得鑰匙
    def get_keypairs_parameters(self):
        """取得鑰匙與公共參數

        取得客戶端的鑰匙與公共參數。
        """
        return {
                "PrivateKey_p":int(self.p),
                "PrivateKey_k":int(self.k),
                "PrivateKey_k2":int(self.k2), 
                "PublicKey_N":int(self.N), 
                "PublicKey_g":int(self.g), 
                "RandomNumber_r1":int(self.r1), 
                "RandomNumber_r2":int(self.r2),
                "Value_t":int(self.t),
                "MessageHash_H(m)":int(self.message_hash),
                "InfoHash_I":int(self.I),
                "Ciphertext_C1":int(self.C1),
                "Ciphertext_C2":int(self.C2),
                "List_l":self.list_l,
            }

    # 取得公鑰
    def get_publickey(self):
        """取得公鑰
        
        取得公鑰
        """
        return {
                "PublicKey_N":int(self.N), 
                "PublicKey_g":int(self.g), 
            }

    # 取得公鑰json
    def get_publickey_json(self):
        """取得公鑰
        
        取得公鑰
        """
        return json.dumps(self.get_publickey())
    
    # 打印鑰匙
    def show_keypairs_parameters(self):
        pprint.pprint(self.get_keypairs_parameters())

    # 取得C1零知識證明起始參數
    def get_zero_know_proof_init_parameters_C1(self):
        result = dict()
        result = {
                    "Ciphertext_C1":int(self.C1),
                    "ZeroKnowledgeProof_C1p":int(self.C1p),
        }
        return result

    # 取得C1零知識證明起始參數json字串
    def get_zero_know_proof_init_parameters_C1_json(self):
        return json.dumps(self.get_zero_know_proof_init_parameters_C1())

    # 取得C1零知識證明參數
    def get_zero_know_proof_parameters_C1(self, b=None):
        result = dict()
        if b is None:
            hint = """
                b是零知識證明中，由簽署者提供的參數，
                隨著b的不同必須回應不同的參數，所以請輸入b。
                """
            raise Exception(hint)               
        if b is 0 :
            result["ZeroKnowledgeProof_x"] = int(self.x)
            result["ZeroKnowledgeProof_rp"] = int(self.rp)
            return result
        elif b is 1 :
            result["ZeroKnowledgeProof_xp"] = int(self.xp)
            result["ZeroKnowledgeProof_rpp"] = int(self.rpp)
            return result
        else:
            hint = """
                b必須為0或者1的整數值。
                """
            raise Exception(hint)  

    # 取得C1零知識證明參數json字串
    def get_zero_know_proof_parameters_C1_json(self, b=None):
        return json.dumps(self.get_zero_know_proof_parameters_C1(b))

    # 取得C2零知識證明起始參數
    def get_zero_know_proof_init_parameters_C2(self):
        result = dict()
        result = {
                    "Ciphertext_C2":int(self.C2),
                    "ZeroKnowledgeProof_C2p":int(self.C2p),
        }
        return result

    # 取得C2零知識證明起始參數json字串
    def get_zero_know_proof_init_parameters_C2_json(self):
        return json.dumps(self.get_zero_know_proof_init_parameters_C2())

    # 取得C2零知識證明參數
    def get_zero_know_proof_parameters_C2(self, b=None):
        result = dict()
        if b is None:
            hint = """
                b是零知識證明中，由簽署者提供的參數，
                隨著b的不同必須回應不同的參數，所以請輸入b。
                """
            raise Exception(hint)               
        if b is 0 :
            result["ZeroKnowledgeProof_x"] = int(self.x)
            result["ZeroKnowledgeProof_rp"] = int(self.rp)
            return result
        elif b is 1 :
            result["ZeroKnowledgeProof_xp"] = int(self.xp)
            result["ZeroKnowledgeProof_rpp"] = int(self.rpp)
            return result
        else:
            hint = """
                b必須為0或者1的整數值。
                """
            raise Exception(hint)  

    # 取得C2零知識證明參數json字串
    def get_zero_know_proof_parameters_C2_json(self, b=None):
        return json.dumps(self.get_zero_know_proof_parameters_C2(b))