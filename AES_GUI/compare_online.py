"""
AES 在线平台对比脚本

这个脚本加密一个文件/字符串，同时告诉你去哪个网站、填什么参数、
对比什么结果。
"""
import aesdll
import os

# ── 固定的测试参数，方便在线复现 ──
# 使用固定密钥和固定内容，这样在线平台也能用同样参数
KEY = bytes(range(32))  # 00 01 02 ... 1F

print("=" * 65)
print("  AES DLL × 在线平台对比测试")
print("=" * 65)

# ── 1. 字符串对比 ──
print("\n" + "─" * 65)
print("  测试 A: 字符串加密 → 在线对比")
print("─" * 65)

plain_text = "Hello AES_DLL!"
print(f"\n  明文:   {plain_text}")
print(f"  密钥:   {KEY.hex()}")

# 加密
cipher_hex = aesdll.encrypt_string(plain_text, KEY)
iv_hex = cipher_hex[:32]
ct_hex = cipher_hex[32:]

print(f"\n  DLL 输出 (全部): {cipher_hex}")
print(f"  ├─ IV (前32hex):   {iv_hex}")
print(f"  └─ 密体 (后部分):  {ct_hex}")

# 解密验证
decrypted = aesdll.decrypt_string(cipher_hex, KEY)
print(f"\n  解密还原: {decrypted}")
print(f"  往返正确: {'是 ✓' if decrypted == plain_text else '否 ✗'}")

print(f"""
  ╔══════════════════════════════════════════════════════╗
  ║  在线验证步骤                                       ║
  ╠══════════════════════════════════════════════════════╣
  ║  1. 打开 https://the-x.cn/cryptography/Aes.aspx     ║
  ║  2. 算法: AES     模式: CBC                        ║
  ║  3. 密钥长度: 256-bit                               ║
  ║  4. 填充: PKCS7Padding                              ║
  ║  5. 明文格式选 Hex，填入:                            ║
  ║     {plain_text.encode().hex():<44s} ║
  ║  6. 密钥填:                                        ║
  ║     {KEY.hex()} ║
  ║  7. IV 填:                                          ║
  ║     {iv_hex} ║
  ║  8. 点"加密"，得到密文                              ║
  ║  9. 对比: 网站密文 == DLL密体({ct_hex[:16]}...) ║
  ╚══════════════════════════════════════════════════════╝
""")

# ── 2. 文件对比 (使用你提供的 test.txt) ──
print("─" * 65)
print("  测试 B: 文件加密 — test.txt")
print("─" * 65)

test_dir = r"D:\Desktop\实训开发"
test_file = os.path.join(test_dir, "test.txt")
enc_file  = os.path.join(test_dir, "test_encrypted.bin")
dec_file  = os.path.join(test_dir, "test_decrypted.txt")

# 读取原文
with open(test_file, "r", encoding="utf-8") as f:
    file_content = f.read()

print(f"\n  原文文件: {test_file}")
print(f"  原文内容: {file_content.strip()}")

aesdll.encrypt_file(test_file, enc_file, KEY)
aesdll.decrypt_file(enc_file, dec_file, KEY)

with open(dec_file, "r", encoding="utf-8") as f:
    dec_content = f.read()

# 读取密文
with open(enc_file, "rb") as f:
    enc_data = f.read()

file_iv = enc_data[:16]
file_ct = enc_data[16:]

print(f"  密文文件: {enc_file}")
print(f"  解密文件: {dec_file}")
print(f"  原文大小: {os.path.getsize(test_file)} bytes")
print(f"  密文大小: {os.path.getsize(enc_file)} bytes")
print(f"  解密内容: {dec_content.strip()}")
print(f"  文件解密一致: {'是 ✓' if dec_content == file_content else '否 ✗'}")

print(f"""
  ╔══════════════════════════════════════════════════════╗
  ║  文件加密在线验证                                   ║
  ╠══════════════════════════════════════════════════════╣
  ║  明文 (hex): {file_content.encode().hex():<40s} ║
  ║  密钥:        {KEY.hex()} ║
  ║  文件 IV:     {file_iv.hex()} ║
  ║  文件密体:    {file_ct.hex()} ║
  ╠══════════════════════════════════════════════════════╣
  ║  同网站填入相同 明文/密钥/IV → 加密 → 对比密体     ║
  ╚══════════════════════════════════════════════════════╝
""")

print("─" * 65)
print("  测试 C: 反向验证 (网站加密 → DLL解密)")
print("─" * 65)
print("""
  步骤:
  1. 在网站上用和测试A相同的参数加密 "Hello AES_DLL!"
  2. 得到网站输出的密文 (这是不一样的，因为网站用了自己的随机IV)
  3. 网站的输出格式也是 IV+密体

  来用一段已知的正确密文测试 DLL 解密:
""")

# 我们用 DLL 产出的密文，网站也能解密
print(f"  把这段复制到网站 → 选解密 → 看输出是否等于 '{plain_text}'")
print(f"  {cipher_hex}")

print(f"""
  ┌─────────────────────────────────────────────────────┐
  │  在线工具推荐                                       │
  ├─────────────────────────────────────────────────────┤
  │  1. https://the-x.cn/cryptography/Aes.aspx          │
  │     (最推荐，支持 Hex 输入，排列清晰)               │
  │                                                     │
  │  2. https://www.devglan.com/online-tools/           │
  │          aes-encryption-decryption                  │
  │     (备选，也支持 PKCS7)                            │
  │                                                     │
  │  3. https://www.javainuse.com/aesgenerator          │
  │     (简约，适合快速验证)                            │
  └─────────────────────────────────────────────────────┘
""")

print("=" * 65)
print("  脚本完成 — 请打开 https://the-x.cn/cryptography/Aes.aspx")
print("  对照上面的参数进行验证")
print("=" * 65)
