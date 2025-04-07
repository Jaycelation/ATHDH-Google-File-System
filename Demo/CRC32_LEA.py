import zlib

def calculate_crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def extend_crc32(original_data, extension_data, padding=b''):
    full_data = original_data + padding + extension_data
    new_crc = calculate_crc32(full_data)
    return full_data, new_crc

def length_extension_attack():
    original_data = b"payment=100"
    original_crc = calculate_crc32(original_data)
    print(f"Dữ liệu gốc: {original_data.decode()}")
    print(f"CRC32 gốc: {hex(original_crc)}")

    extension_data = b", bonus=900"
    padding = b"\x00"

    extended_data, new_crc = extend_crc32(original_data, extension_data, padding)
    print(f"Dữ liệu sau khi nối: {extended_data.decode()}")
    print(f"CRC32 mới: {hex(new_crc)}")

if __name__ == "__main__":
    length_extension_attack()
