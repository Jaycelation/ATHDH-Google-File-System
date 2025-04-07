import re

VALID_PATTERN = r"^[a-zA-Z]{1,20}=[0-9]{1,10}$"

BLACKLIST_PATTERN = (
    r"[<>'\";,%/.]"
    r"|\s+"
    r"|--"
    r"|\b(?:OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE|EXEC|EXECUTE|CREATE|ALTER|TRUNCATE|SLEEP|BENCHMARK|LIKE|WHERE)\b"
    r"|!=|=--|#|/\*|\*/"
    r"|%3C|%3E|%22|%27|%2F" 
)
def check_semantics(data):
    print("  -> Kiểm tra ngữ nghĩa (theo OWASP C5):")
    print("    -> Kiểm tra độ dài:")
    if len(data) > 30:
        print(f"      -> Dữ liệu '{data}' vượt quá độ dài tối đa (30 ký tự)")
        return False
    print("      -> Độ dài hợp lệ")
    
    print("    -> Kiểm tra blacklist:")
    blacklist_match = re.search(BLACKLIST_PATTERN, data, re.IGNORECASE)
    if blacklist_match:
        print(f"      -> Tìm thấy mẫu không mong muốn hoặc nguy hiểm: '{blacklist_match.group()}'")
        return False
    print("      -> Không tìm thấy mẫu trong blacklist")
    
    print("    -> Kiểm tra whitelist:")
    if not re.fullmatch(VALID_PATTERN, data):
        print(f"      -> Dữ liệu '{data}' không khớp định dạng hợp lệ (key=[a-zA-Z]{{1,20}}, value=[0-9]{{1,10}})")
        return False
    print(f"      -> Dữ liệu '{data}' hợp lệ theo whitelist")
    
    return True

def test_semantics():
    test_cases = [
        "payment=100",
        "payment=abc",
        "payment=100, bonus=900",
        "pay ment=100",
        "payment=100; DROP",
        "pay<ment=100",
        "a=" + "1" * 11,
        "a" * 21 + "=100"
    ]
    
    for data in test_cases:
        print(f"\nKiểm tra dữ liệu: '{data}'")
        result = check_semantics(data)
        print(f"  -> Kết quả: {'Hợp lệ' if result else 'Không hợp lệ'}")

if __name__ == "__main__":
    test_semantics()