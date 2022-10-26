"""
Note
=================
signer寄送-1

K1x: int，ECDSA 公鑰
K1y: int，ECDSA 公鑰
b_list: 一串0/1，20個。
i_list: 20個，1~40之間的數字。
=================
user寄送-1

C1: int:加密的訊息。
C2: int:加密的ECDSA鑰匙簽章。

Zero­KnowledgeProof_C1p_list: List，20個C1'的
Zero­KnowledgeProof_C2p_list: List，20個C2'的

Zero­KnowledgeProofParameters: List，儲存著(x,r')或者(x',r'')兩種混合成的序列。

L: List，被選擇的l list，除了l_j
=================
signer寄送-2

C: int，簽章。
=================
"""
class PartiallyBlindSignatureClientInterface:
    pass