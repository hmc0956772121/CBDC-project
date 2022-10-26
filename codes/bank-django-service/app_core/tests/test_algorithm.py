from django.test import TestCase
from ..models import YiModifiedPaillierEncryptionPy

class TestAlgorithm(TestCase):
    
    def setUp(self):
        pass

    # 測試Yi算法
    def test_YiModifiedPaillierEncryptionPy(self):
        print("[算法測試]測試Yi同態加密")
        yiModifiedPaillierEncryptionPy = YiModifiedPaillierEncryptionPy()
        yiModifiedPaillierEncryptionPy.test()