import zlib
import hashlib

def calculate_crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()

def secure_data_integrity(original_data):
    crc32_value = calculate_crc32(original_data)
    sha256_value = calculate_sha256(original_data)
    print(f"Dữ liệu gốc: {original_data.decode()}")
    print(f"CRC32: {hex(crc32_value)}")
    print(f"SHA256: {sha256_value}")
    return crc32_value, sha256_value

def verify_integrity(data, expected_crc32, expected_sha256):
    new_crc32 = calculate_crc32(data)
    new_sha256 = calculate_sha256(data)
    return new_crc32 == expected_crc32 and new_sha256 == expected_sha256


original_data = b"payment=100"
crc32_orig, sha256_orig = secure_data_integrity(original_data)

extended_data = b"payment=100\x00, bonus=900"
is_valid = verify_integrity(extended_data, crc32_orig, sha256_orig)
print(f"Dữ liệu sau tấn công: {extended_data.decode()}")
print(f"Kết quả kiểm tra: {is_valid}")  