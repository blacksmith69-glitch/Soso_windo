import requests
import base64
import mail
import time
import os
import random
import string
import subprocess
import hashlib
import platform
import uuid
import sys

# -------------------- DEVICE ID --------------------
def get_device_id():
    try:
        def prop(name):
            try:
                return subprocess.check_output(f"getprop {name}", shell=True).decode().strip()
            except:
                return ""
        android_props = [
            prop("ro.product.brand"),
            prop("ro.product.model"),
            prop("ro.product.device"),
            prop("ro.build.display.id"),
            prop("ro.build.version.release"),
            prop("ro.hardware"),
            prop("ro.serialno"),
        ]
        android_data = "".join(android_props)
        try:
            uname = subprocess.check_output("uname -a", shell=True).decode().strip()
            android_data += uname
        except:
            pass
        if android_data.strip():
            return hashlib.md5(android_data.encode()).hexdigest()
    except:
        pass
    raw = platform.node() + platform.system() + platform.machine() + str(uuid.getnode()) + os.path.expanduser("~")
    return hashlib.md5(raw.encode()).hexdigest()

# -------------------- REPORT TO FLASK SERVER --------------------
def send_report(mode, refcode, success_count):
    try:
        requests.post(
            "https://BBlacksmith.pythonanywhere.com/ref_update",
            json={
                "mode": mode,
                "refcode": refcode,
                "success": success_count
            },
            timeout=5
        )
    except:
        print("\033[1;31mFailed to send report to server\033[0m")


success_count = 0
kid_count = 0

# -------------------- LOGO --------------------
logo = f"""
\033[1;34m█████╗ ██████╗  █████╗ ███████╗ █████╗ ████████╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
███████║██████╔╝███████║█████╗  ███████║   ██║
██╔══██║██╔══██╗██╔══██║╚══██║   ██║
██║  ██║██║  ██║██║  ██║██║     ██║  ██║   ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝
----------------------------------------------------
> TG CHANNEL :  @cryptowitharyanog
> YouTube    :  @cryptowitharyan
------------------------------------------\033[0m
"""

os.system("clear")
print(logo)

# -------------------- LICENSE --------------------
DEVICE_ID = get_device_id()
KEY_FILE = "saved_key.txt"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "r") as f:
        LICENSE_KEY = f.read().strip()
else:
    LICENSE_KEY = input("> Enter your license key: ").strip()

# -------------------- LICENSE CHECK FUNCTION --------------------
def check_license():
    try:
        resp = requests.get(f"https://BBlacksmith.pythonanywhere.com/check?key={LICENSE_KEY}&device={DEVICE_ID}").json()
        if resp["status"] != "VALID":
            print(f"\033[1;31mLicense Error: {resp.get('message','Invalid')}\033[0m")
            sys.exit()
        if resp.get("daily_left", 0) <= 0:
            print("\033[1;31mDaily limit reached for this license. Try again tomorrow.\033[0m")
            sys.exit()
        return True
    except Exception as e:
        print(f"\033[1;31mLicense server error: {e}\033[0m")
        sys.exit()

check_license()
with open(KEY_FILE, "w") as f:
    f.write(LICENSE_KEY)
print("\033[1;32mLicense Valid ✅\033[0m")

# -------------------- INPUT --------------------
base_url = input("\033[1;36m> Input base URL : \033[0m").strip()
refcode = input("\033[1;36m> Referral code : \033[0m").strip()
print("\033[1;34m------------------------------------------\033[0m")

mode = input("Choose mode:\n1. V0 (simple)\n2. V1 (1 main + 20 kids)\n> ").strip()
if mode == "1":
    mode = "V0"
    count = int(input("\033[1;36mHow many accounts to create? > \033[0m"))
else:
    mode = "V1"
    count = int(input("\033[1;36mHow many main accounts to create? > \033[0m"))

# -------------------- PASSWORD --------------------
def generate_password(length=8):
    if length < 8: length = 8
    upper = random.choice(string.ascii_uppercase)
    lower = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice("@#$&")
    remaining = ''.join(random.choices(string.ascii_letters + string.digits + "@#$&", k=length-4))
    password = upper + lower + digit + special + remaining
    return base64.b64encode(password.encode()).decode()

# -------------------- PROXY --------------------
used_proxies = []
def get_random_proxy():
    global used_proxies
    try:
        with open("proxy.txt", "r") as file:
            proxies = [p.strip() for p in file if p.strip()]
    except:
        return None

    available_proxies = list(set(proxies) - set(used_proxies))
    if not available_proxies:
        used_proxies = []
        available_proxies = proxies
    proxy = random.choice(available_proxies)
    used_proxies.append(proxy)
    return {"http": proxy, "https": proxy}

# -------------------- ACCOUNT FUNCTIONS --------------------
def create_account(captcha_token, password, email, proxy):
    headers = {
        'Host': 'm.sosovalue.com',
        'sec-ch-ua-platform': 'Android',
        'user-device': 'Chrome/131.0.6778.260#Android/15',
        'accept-language': 'en',
        'sec-ch-ua': 'Android',
        'sec-ch-ua-mobile': '?1',
        'user-agent': 'Mozilla/5.0 (Linux; Android 15)',
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://m.sosovalue.com',
    }
    json_data = {'password': password,'rePassword': password,'username': 'NEW_USER_NAME_02','email': email}
    params = {'cf-turnstile-response': captcha_token}
    try:
        requests.post('https://gw.sosovalue.com/usercenter/email/anno/sendRegisterVerifyCode/V2',
            params=params, headers=headers, json=json_data, proxies=proxy, timeout=10)
        return {"status":"any"}
    except Exception as e:
        print(f"\033[1;31mFailed to create account {email}: {e}\033[0m")
        return {"status":"dead"}

def verify_email(password, email, code, refcode, proxy):
    headers = {
        'Host': 'gw.sosovalue.com',
        'sec-ch-ua-platform': 'Android',
        'user-device': 'Chrome/131.0.6778.260#Android/15',
        'user-agent': 'Mozilla/5.0 (Linux; Android 15)',
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://m.sosovalue.com',
    }
    json_data = {'password': password,'rePassword': password,'username': 'NEW_USER_NAME_02',
                 'email': email,'verifyCode': code,'invitationCode': refcode,'invitationFrom':'null'}
    try:
        requests.post('https://gw.sosovalue.com/usercenter/user/anno/v3/register',
                      headers=headers,json=json_data,proxies=proxy,timeout=10)
        return {"status":"any"}
    except Exception as e:
        print(f"\033[1;31mFailed to verify email {email}: {e}\033[0m")
        return {"status":"dead"}

def get_captcha():
    while True:
        try:
            token = requests.get(f"{base_url}/get").text
            if token != "No tokens available":
                return token
        except Exception as e:
            print(f"\033[1;31mCaptcha fetch failed: {e}\033[0m")
        time.sleep(0.3)

# -------------------- MAIN LOOP WITH RETRIES --------------------
def attempt_account_creation(is_main=True, kid_idx=None):
    global success_count, kid_count
    retries = 3
    while retries > 0:
        check_license()
        email = mail.getmails()
        password = generate_password()
        decpass = base64.b64decode(password).decode()
        captcha_token = get_captcha()
        proxy = get_random_proxy()

        if is_main:
            print(f"\033[1;33m👨 Creating main account...\033[0m\n> {email}")
        else:
            print(f"\033[1;33m👶 Creating kid account {kid_idx+1}/20...\033[0m\n> {email}")

        res1 = create_account(captcha_token, password, email, proxy)
        if res1["status"] == "dead":
            print(f"\033[1;31mAccount {email} creation failed, retrying...\033[0m")
            retries -= 1
            continue

        code = mail.get_verification_link(email, email.split("@")[1])
        res2 = verify_email(password, email, code, refcode, proxy)
        if res2["status"] == "dead":
            print(f"\033[1;31mAccount {email} verification failed, retrying...\033[0m")
            retries -= 1
            continue

        if is_main:
            success_count += 1
            print(f"\033[1;32m✔ Main account created ✅\033[0m")
        else:
            kid_count += 1
            print(f"\033[1;32m✔ Kid account created ✅\033[0m")

        try:
            requests.post("https://BBlacksmith.pythonanywhere.com/update_limits",
                          json={"key":LICENSE_KEY})
        except:
            print("\033[1;31mFailed to update daily limit on server\033[0m")

        with open("accounts.txt","a") as f:
            f.write(f"Email: {email}\nPassword: {decpass}\n--------------------\n")

        if is_main:
            send_report(mode, refcode, success_count)
        else:
            send_report(mode, refcode, kid_count)

        return True

    print(f"\033[1;31mFailed all 3 retries for account {email}\033[0m")
    return False

try:
    for main_idx in range(count):
        attempt_account_creation(is_main=True)
        if mode=="V1":
            for kid_idx in range(20):
                attempt_account_creation(is_main=False, kid_idx=kid_idx)

except KeyboardInterrupt:
    print("\n\033[1;33mUser interrupted. Exiting...\033[0m")
    sys.exit()
except Exception as e:
    print(f"\033[1;31mError: {e}\033[0m")
    time.sleep(1)

print("\033[1;34mAll tasks finished!\033[0m")
