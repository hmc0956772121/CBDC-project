import gmpy2
import random
import time
from math import gcd
import json
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from copy import deepcopy

class YiModifiedPaillierEncryptionPy:
    """Yi's modified paillier encryptionPy

    This algorithm reference from 'Xun Yi and Kwok-Yan Lam. 2019. A New Blind ECDSA Scheme for Bitcoin Transaction Anonymity'.
    Implemented by NCYU ISlab.
    
    該演算法參考自論文: 'Xun Yi and Kwok-Yan Lam. 2019. A New Blind ECDSA Scheme for Bitcoin Transaction Anonymity'。
    由嘉義大學資訊安全實驗室與政治大學實作。

    撰寫: 蕭維均

    Attributes:
        q(gmpy2.mpz): q 在該算法中裡頭屬於ECDSA中橢圓曲線的Order，用於測試加解密有效性。
        p: int，私鑰的一部分。
        k: int，私鑰的一部分。
        N: int，公鑰的一部分。
        g: int，公鑰的一部分。
        r: int，一個混淆用的隨機數值，若該數值密文改變，但仍可以用同一組私鑰解開。
    """
    def __init__(self):
        gmpy2.get_context().precision = 10**5 #浮點數精度設置，當q值與要加密的數值過大時，若出現運算尾數不精確，請調大該數值分配更多記憶體用於儲存浮點數。
        self.q = gmpy2.mpz(0)
        self.p = gmpy2.mpz(0)
        self.k = gmpy2.mpz(0)
        self.N = gmpy2.mpz(0)
        self.g = gmpy2.mpz(0)
        self.r = gmpy2.mpz(0)

    def random_prime_in_range(self, min:int, max:int) ->int:
        """生成一定範圍的一個質數

        生成一定範圍的質數，使用gmpy2進行加速。

        Args:
            min: int，質數的最小值。
            max: int，質數的最大值。

        Returns:
            random_prime: 一個質數。

        Raises:
            (無錯誤回傳)
        """
        random_prime = 0
        while not (random_prime < max) or not (min < random_prime):
            random_number = random.randrange(min,max)
            random_prime = int(gmpy2.next_prime(random_number))
        return random_prime

    def generate_q(self, min:int, max:int) ->int:
        """生成臨時的q

        q 在該算法中裡頭屬於ECDSA中橢圓曲線的Order，用於測試加解密有效性。

        Args:
            min: int，質數的最小值。
            max: int，質數的最大值。

        Returns:
            q: 一個質數。

        Raises:
            (無錯誤回傳)
        """
        q = gmpy2.mpz(self.random_prime_in_range(min,max))
        return int(q)

    def generate_p_k(self, q:int = 0) ->tuple:
        """生成p與k

        p與k為該算法中的私鑰。

        Args:
            q: int，一個質數

        Returns:
            (p,k): tuple，可以採取以下方式接收回傳值:
                p, k = find_p_k(q, min, max)

        Raises:
            (無錯誤回傳)
        """
        if q == 0 :
            raise Exception("必須輸入來自 ECDSA 的 Order q")
        # 限制p,k的最大最小值 
        min:int = 0
        max:int = q*2
        
        p:int = 0
        k:int = 0
        while (p == 0) or (k == 0) or (p == k):
            var:int = self.random_prime_in_range(min,max)
            while gcd(var-1,q) != 1:
                var = self.random_prime_in_range(min,max)
            if p is 0:
                p = var
            else:
                k = var
        self.q = gmpy2.mpz(q)
        self.p = gmpy2.mpz(p)
        self.k = gmpy2.mpz(k)
        return (p,k)

    def generate_N_g(self, p:int=0, q:int=0, k:int=0):
        """生成作為公鑰的N,g

        N與g為該算法中的公鑰。

        Args:
            p: int，私鑰的一部分。
            q: int，質數。
            k: int，私鑰的一部分。

        Returns:
            (N,g): tuple，可以採取以下方式接收回傳值:
            N, g = generate_N_g(p, q, k)

        Raises:
            (無錯誤回傳)
        """
        if (p == 0) or (q == 0) or (k == 0):
            p = self.p
            q = self.q
            k = self.k
        self.N = gmpy2.mul(gmpy2.mul(p, q), k)
        self.g = gmpy2.powmod(1+self.N,p*k,pow(self.N,2))

        return (int(self.N),int(self.g))

    def generate_r(self, N:int = 0):
        """生成隨機數r

        r 是個特定的隨機數。

        Args:
            N: int，N公鑰的一部分。

        Returns:
            r: int，隨機質數。

        Raises:
            (無錯誤回傳)
        """
        if N == 0:
            N = self.N
        r = 0
        r = self.find_random_co_prime(pow(N,2))
        self.r = gmpy2.mpz(r)
        return r

    def find_random_co_prime(self, n:int):
        """生成小於數值n的隨機數，該數與n互質數值

        生成小於數值n的隨機數，該數與n互質數值。
        群論意義上，屬於n的乘法群整數。

        Args:
            n: int

        Returns:
            result: int，小於數值n的隨機數，該數與n互質數值。

        Raises:
            (無錯誤回傳)
        """
        result = random.randrange(deepcopy(n)) #尋找極限以下的隨機數
        while gcd(n,result) != 1: # 當與n不互質時
            result += 1 # 往下個數值進行線性搜索。
            if result > n : # 若結果不小心大於目標
                result = random.randrange(deepcopy(n)) #重新尋找隨機數
        return result


    def encrypt(self, m:int=0, N:int=0, g:int=0 ,r:int=0, q:int=0):
        """Yi的同態加密

        進行同態加密。

        Args:
            m: int，要加密的訊息。
            N: int，公鑰的一部分。
            g: int，公鑰的一部分。
            r: int，是個特定的隨機數。

        Returns:
            C: int，密文。

        Raises:
            (無錯誤回傳)
        """
        if (N == 0) or (g == 0) or (r == 0):
            raise Exception("請輸入正確的公鑰對與隨機數。")
        if m == 0:
            raise Exception("必須輸入密文")
        if q == 0:
            raise Exception("輸入q值才可對於密文是否過長進行驗證。")
        if m > q:
            raise Exception("加密失敗，因為密文過長，可以嘗試加大q值，以容納更長的密文。")
        N, g, r, m= gmpy2.mpz(N), gmpy2.mpz(g), gmpy2.mpz(r), gmpy2.mpz(m)
        N_power_2 = pow(N,2)
        # 此處將算式改為 C = [(g^m mod N^2) * (r^N mod N^2)] mod N^2 ，防止數值過大導致的記憶體占滿，或者速度緩慢。
        C = gmpy2.mod(gmpy2.powmod(g, m, N_power_2) * gmpy2.powmod(r, N, N_power_2), N_power_2)
        return int(C)

    def encrypt_string(self, m:str=0, N:int=0, g:int=0 ,r:int=0, q:int=0):
        """Yi的同態加密字串

        將字串轉換成整數後，進行同態加密。

        Args:
            m: str，要加密的訊息，字串型別。
            N: int，公鑰的一部分。
            g: int，公鑰的一部分。
            r: int，是個特定的隨機數。

        Returns:
            C: int，密文。

        Raises:
            (無錯誤回傳)
        """
        bytes_string = bytes(m, 'utf-8')
        hex_string = hexlify(bytes_string)
        m = int(hex_string, 16)
        C = self.encrypt(m, N, g, r, q)
        return C

    def decrypt(self, C:int=0, p:int = 0, k:int = 0, q:int = 0, N:int=0):
        """Yi的同態解密

        進行同態加密的解密。

        Args:
            p: int，私鑰的一部分。
            k: int，私鑰的一部分。
            q: int，隨機質數。
            C: int，密文
            N: int，公鑰

        Returns:
            m: int，明文。

        Raises:
            (無錯誤回傳)
        """
        if (p == 0) or (k == 0) or (q == 0) or (N == 0):
            raise Exception("請輸入正確的私鑰對與隨機數。")
        if C == 0:
            raise Exception("必須輸入密文")
        p, k, q, C, N= gmpy2.mpz(p), gmpy2.mpz(k), gmpy2.mpz(q), gmpy2.mpz(C), gmpy2.mpz(N)
        N_power_2 = pow(N,2)
        temp_numner1 = gmpy2.mul(gmpy2.mul(p-1, q-1), k-1)
        D = gmpy2.powmod(C, temp_numner1, N_power_2)
        temp_numner2 = (D-1)//(gmpy2.mul(gmpy2.mul(N,p), k))
        m = gmpy2.mod(gmpy2.mul(temp_numner2 ,gmpy2.invert(temp_numner1, q)) , q)
        return int(m)

    def decrypt_string(self, C:int=0, p:int = 0, k:int = 0, q:int = 0, N:int=0):
        m = self.decrypt(C, p, k, q, N)
        hex_int = "{0:x}".format(m)
        if len(hex_int) % 2 == 1:
            hex_int = "0" + hex_int
        bytes_string = unhexlify(hex_int)
        m = bytes_string.decode("utf-8")
        return m

    def generate_keypairs(self, q:int=0):
        """生成鑰匙對與隨機值

        進行同態加密的解密。

        Args:
            q: int，質數屬於ECDSA中橢圓曲線的Order。

        Returns:
            dict，回傳一個dictionary型別{"PrivateKey_p":p, "PrivateKey_k":k, "PublicKey_N":N, "PublicKey_g":g, "RandomNumber_r":r}。

        Raises:
            (無錯誤回傳)
        """
        if q == 0:
            raise Exception("必須輸入來自 ECDSA 的 Order q")
        p, k = self.generate_p_k(q)
        N, g = self.generate_N_g()
        r = self.generate_r()
        return self.get_keypairs()

    def test(self):
        """自檢方法
        用於自檢加解密函數是否撰寫正確"""
        q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        # 自檢數值加解密
        m1 = 1234567890123456789012345678901234567890123456789012345678901234567890
        start_time = time.time()
        keys = self.generate_keypairs(q)
        C1 = self.encrypt(m1, keys["PublicKey_N"], keys["PublicKey_g"], keys["RandomNumber_r"], q)
        D1 = self.decrypt(C1, keys["PrivateKey_p"], keys["PrivateKey_k"], q, keys["PublicKey_N"])
        if C1 == D1:
            raise Exception("加密後的數字密文無法順利解密回數字明文，請重新調整該類別。")
        cost_time = time.time() - start_time
        # 自檢字串加解密
        m2 = "<小王子>"
        keys = self.generate_keypairs(q)
        C2 = self.encrypt_string(m2, keys["PublicKey_N"], keys["PublicKey_g"], keys["RandomNumber_r"], q)
        D2 = self.decrypt_string(C2, keys["PrivateKey_p"], keys["PrivateKey_k"], q, keys["PublicKey_N"])
        if C2 == D2:
            raise Exception("加密後的文字密文無法順利解密回文字明文，請重新調整該類別。")
        print("類別自我測試完成，加密後仍能順利解密。")
        print("生成鑰匙與加解密耗時%f 秒"%(cost_time))

    def get_keypairs(self):
        return {"PrivateKey_p":int(self.p), "PrivateKey_k":int(self.k), "PublicKey_N":int(self.N), "PublicKey_g":int(self.g), "RandomNumber_r":int(self.r)}