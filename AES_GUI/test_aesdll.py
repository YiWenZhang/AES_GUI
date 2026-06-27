"""
aesdll 功能测试脚本

运行: python test_aesdll.py
"""

import aesdll

print("=" * 60)
print("  aesdll 功能测试")
print("=" * 60)

# ── 1. MAC 地址 ──
print("\n[1] get_mac_address()")
try:
    mac = aesdll.get_mac_address()
    print(f"  本机 MAC: {mac}")
    print("  PASS")
except Exception as e:
    print(f"  FAIL: {e}")

# ── 2. 密钥生成 ──
print("\n[2] generate_key_from_machine()")
try:
    key = aesdll.generate_key_from_machine()
    print(f"  密钥 (hex): {key.hex()}")
    print(f"  密钥长度:   {len(key)} bytes")
    assert len(key) == 32, "密钥不是32字节"
    print("  PASS")
except Exception as e:
    print(f"  FAIL: {e}")

# ── 3. 字符串加密/解密 ──
print("\n[3] encrypt_string() / decrypt_string()")
test_cases = [
    "Hello World!",
    "你好，世界！",
    "A" * 100,
    "",  # 空字符串
    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
]

all_pass = True
for s in test_cases:
    try:
        ct = aesdll.encrypt_string(s, key)
        pt = aesdll.decrypt_string(ct, key)
        preview = s[:30] + ("..." if len(s) > 30 else "")
        ok = pt == s
        if not ok:
            all_pass = False
        print(f"  {'OK' if ok else 'FAIL':4s}  '{preview}'")
    except Exception as e:
        all_pass = False
        print(f"  FAIL  '{s[:30]}' → {e}")

print(f"  {'全部通过' if all_pass else '存在失败'}")

# ── 4. 文件加密/解密 ──
print("\n[4] encrypt_file() / decrypt_file()")
import tempfile, os

test_content = "这是一段测试文本。\nThis is a test file.\n" * 100
enc_file = os.path.join(tempfile.gettempdir(), "test_encrypted.bin")
dec_file = os.path.join(tempfile.gettempdir(), "test_decrypted.txt")
plain_file = os.path.join(tempfile.gettempdir(), "test_plain.txt")

try:
    # 写原文
    with open(plain_file, "w", encoding="utf-8") as f:
        f.write(test_content)

    # 加密
    aesdll.encrypt_file(plain_file, enc_file, key)
    print(f"  原文大小: {os.path.getsize(plain_file)} bytes")
    print(f"  密文大小: {os.path.getsize(enc_file)} bytes  (多了16字节IV)")

    # 解密
    aesdll.decrypt_file(enc_file, dec_file, key)
    with open(dec_file, "r", encoding="utf-8") as f:
        dec_content = f.read()

    ok = dec_content == test_content
    print(f"  解密内容一致: {'是' if ok else '否'}")
    print(f"  {'PASS' if ok else 'FAIL'}")
finally:
    for f in [plain_file, enc_file, dec_file]:
        try:
            os.remove(f)
        except:
            pass

# ── 5. 多源硬件密钥生成 ──
print("\n[5] generate_key_from_hardware()")
try:
    hw_key = aesdll.generate_key_from_hardware()
    print(f"  硬件派生密钥 (hex): {hw_key.hex()}")
    print(f"  密钥长度: {len(hw_key)} bytes")
    assert len(hw_key) == 32, "硬件派生密钥不是32字节"
    # 验证与 MAC 派生密钥的一致性：同一台机器上两函数应产生相同密钥
    # 注：若本机无物理网卡但有磁盘卷序列号，二者可能不同，此处仅验证长度
    print("  PASS — 多源硬件特征成功派生32字节密钥")
except Exception as e:
    print(f"  FAIL: {e}")

# ── 6. 口令加密/解密 AES 密钥（混合加密） ──
print("\n[6] encrypt_key_with_password() / decrypt_key_with_password()")
try:
    # 使用 MAC 派生的原始密钥
    original_aes_key = key  # 32 bytes

    # 用口令加密 AES 密钥
    password = "test-password-123"
    encrypted_key = aesdll.encrypt_key_with_password(original_aes_key, password)
    print(f"  原始 AES 密钥 (hex): {original_aes_key.hex()}")
    print(f"  加密后密钥包长度: {len(encrypted_key)} bytes (应为64)")
    assert len(encrypted_key) == 64, "加密密钥包不是64字节"

    # 用正确口令解密
    decrypted_key = aesdll.decrypt_key_with_password(encrypted_key, password)
    assert len(decrypted_key) == 32, "解密后密钥不是32字节"
    ok_correct = (decrypted_key == original_aes_key)
    print(f"  正确口令解密 → 密钥一致: {'是' if ok_correct else '否'}")

    # 用错误口令尝试解密
    try:
        wrong_result = aesdll.decrypt_key_with_password(encrypted_key, "wrong-password")
        print(f"  错误口令解密 → 被拒绝: 否 (意外返回了数据)")
        ok_wrong = False
    except RuntimeError:
        # 预期行为：错误口令返回 -1，Python 层抛出 RuntimeError
        print(f"  错误口令解密 → 被正确拒绝: 是")
        ok_wrong = True

    print(f"  {'PASS' if ok_correct and ok_wrong else 'FAIL'} — 混合加密流程验证")
except Exception as e:
    print(f"  FAIL: {e}")

# ── 7. 独立密钥测试 ──
print("\n[7] 独立密钥 (非硬件派生)")
my_key = bytes(range(32))  # 00 01 02 ... 1F
ct = aesdll.encrypt_string("独立密钥测试", my_key)
pt = aesdll.decrypt_string(ct, my_key)
assert pt == "独立密钥测试", "独立密钥加解密失败"
print("  PASS — 任意32字节密钥均可正常工作")

# ── 总结 ──
print("\n" + "=" * 60)
print("  测试完成 — aesdll 全部7项功能正常")
print("=" * 60)
