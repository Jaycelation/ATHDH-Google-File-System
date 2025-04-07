import zlib

def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

original_data = b"payment=100"
original_crc = crc32(original_data)
print(f"Dữ liệu gốc: {original_data.decode()}, CRC32: {hex(original_crc)}")

target_data = b"payment=999"

if len(original_data) != len(target_data):
    raise ValueError("Độ dài phải khớp để đơn giản hóa demo")
delta = bytes(a ^ b for a, b in zip(original_data, target_data))

forged_data = bytes(a ^ b for a, b in zip(original_data, delta))
forged_crc = crc32(forged_data)

print(f"Dữ liệu giả mạo: {forged_data.decode()}, CRC32: {hex(forged_crc)}")

if forged_crc == original_crc:
    print("Tấn công thành công: CRC32 khớp!")