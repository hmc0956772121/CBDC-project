from django.test import TestCase
import os
import json
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey, PublicKey
from ..models import YiModifiedPaillierEncryptionPy

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

    def test_ECDSA(self):
        privateKey = PrivateKey.fromPem(self.ECDSA_PRIVATEKEY)
        publicKey = PublicKey.fromPem(self.ECDSA_PUBLICKEY)
        message = json.dumps({"data": "123"})
        signature = Ecdsa.sign(message, privateKey)
        print(Ecdsa.verify(message, signature, publicKey))
