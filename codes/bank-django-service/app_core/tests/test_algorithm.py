from django.test import TestCase
import os
import json
from pprint import pprint
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey, PublicKey
from ..models import YiModifiedPaillierEncryptionPy
from ..models import PartiallyBlindSignatureClient
from ..models import PartiallyBlindSignatureServer

class TestAlgorithm(TestCase):
    
    def setUp(self):
        self.ECDSA_PUBLICKEY = os.environ['ECDSA_PUBLICKEY']
        self.ECDSA_PRIVATEKEY = os.environ['ECDSA_PRIVATEKEY']
        pass

    # 測試Yi算法
    def test_YiModifiedPaillierEncryptionPy(self):
        print("[算法測試] 測試Yi同態加密")
        yiModifiedPaillierEncryptionPy = YiModifiedPaillierEncryptionPy()
        yiModifiedPaillierEncryptionPy.test()

    # 測試ECDSA模塊
    def test_ECDSA(self):
        print("[算法測試] ECDSA模塊")
        privateKey = PrivateKey.fromPem(self.ECDSA_PRIVATEKEY)
        publicKey = PublicKey.fromPem(self.ECDSA_PUBLICKEY)
        message = json.dumps({"data": "123"})
        signature = Ecdsa.sign(message, privateKey)
        result = Ecdsa.verify(message, signature, publicKey)
        self.assertTrue(result, "\n\n ECDSA模塊測試失敗，有可能是模塊損壞或者ECDSA鑰匙錯誤")

    # 測試盲簽章
    def test_Paillier(self):
        print("[算法測試] 盲簽章驗證")
        publicKey = PublicKey.fromPem(self.ECDSA_PUBLICKEY)
        
        # [使用者與簽署者]實例化
        user = PartiallyBlindSignatureClient()
        signer = PartiallyBlindSignatureServer()

        # [使用者與簽署者]設置 ECDSA 公鑰
        signer.set_K1(publicKey.point.x, publicKey.point.y) #設置signer ECDSA 公鑰
        user.set_K1(publicKey.point.x, publicKey.point.y) #設置user ECDSA 公鑰

        # [使用者]生成密文Hash
        user.generate_message_hash("coin: 123456789")
        # [使用者]設置公開參數的Hash
        user.generate_I("使用者:123")
        # [使用者]生成鑰匙參數
        user.generate_keypairs_parameters()
        # [使用者]取得使用者公鑰
        user_publickey = user.get_publickey_json()
        # [使用者]生成零知識證明參數
        user.generate_zero_know_proof_parameters_C1()
        # [使用者]取得零知識證明初始參數
        zero_know_proof_init_parameters_C1 = user.get_zero_know_proof_init_parameters_C1_json()

        # [簽署者]接收使用者公鑰
        signer.set_user_publickey_json(user_publickey)
        # [簽署者]設置零知識證明初始參數
        signer.set_zero_know_proof_init_parameters_C1_json(zero_know_proof_init_parameters_C1)
        # [簽署者]生成二進制數值
        b = signer.generate_b()
        
        # [使用者]依照b值回傳不同的的內容給簽署者。
        send_to_signer = user.get_zero_know_proof_parameters_C1_json(b)

        # [簽署者]設置零知識證明參數C1
        signer.set_zero_know_proof_parameters_C1_json(send_to_signer)
        signer.verify_C1()


        
