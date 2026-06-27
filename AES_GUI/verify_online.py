"""
实训验证：DLL加密 → devglan在线解密

用法: python verify_online.py
"""

import aesdll
import base64

KEY = bytes(range(32))
PLAIN = "Hello AES!"

cipher = aesdll.encrypt_string(PLAIN, KEY)
iv_hex = cipher[:32]
ct_hex = cipher[32:]

# devglan 密文输入框默认 Base64
ct_bytes = bytes.fromhex(ct_hex)
ct_b64 = base64.b64encode(ct_bytes).decode()
iv_bytes = bytes.fromhex(iv_hex)

dec = aesdll.decrypt_string(cipher, KEY)

print("=" * 60)
print("  AES-256-CBC DLL 正确性验证")
print("=" * 60)

print(f"""
密钥(hex):  {KEY.hex()}
原文:       {PLAIN}
IV(hex):    {iv_hex}
密体(hex):  {ct_hex}
密体(b64):  {ct_b64}

DLL解密:    {dec}
正确:       {'✓' if dec == PLAIN else '✗'}
""")

print("=" * 60)
print("  devglan 解密步骤（一图流）")
print("=" * 60)

print(f"""
https://www.devglan.com/online-tools/aes-encryption-decryption

点 "Decrypt" 标签，填入:

  AES Encrypted Text:      {ct_b64}

  Enter Secret Key:        {KEY.hex()}
  Secret Key Format:       Hex
  Cipher Mode:             CBC
  Padding:                 PKCS5Padding

  Enter IV:                {iv_hex}
  IV Format:               Hex
  Key Size:                256 Bit
  Output Text Format:      Text

点 Decrypt → 输出 "{PLAIN}" → 截图 ✓
""")
