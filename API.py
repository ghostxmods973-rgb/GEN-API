import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import codecs
import time
from datetime import datetime
import urllib3
import os
import sys
import base64
import re
from flask import Flask, request, jsonify
import threading

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Flask app
app = Flask(__name__)

class AccountGeneratorAPI:
    def __init__(self):
        self.REGION_LANG = {
            "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", 
            "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", "BR": "pt"
        }
        self.REGION_URLS = {
            "IND": "https://client.ind.freefiremobile.com/",
            "ID": "https://clientbp.ggblueshark.com/",
            "BR": "https://client.us.freefiremobile.com/",
            "ME": "https://clientbp.common.ggbluefox.com/",
            "VN": "https://clientbp.ggblueshark.com/",
            "TH": "https://clientbp.common.ggbluefox.com/",
            "CIS": "https://clientbp.ggblueshark.com/",
            "BD": "https://clientbp.ggblueshark.com/",
            "PK": "https://clientbp.ggblueshark.com/",
            "SG": "https://clientbp.ggblueshark.com/",
            "SAC": "https://client.us.freefiremobile.com/",
            "TW": "https://clientbp.ggblueshark.com/"
        }
        
        hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
        self.key = bytes.fromhex(hex_key)
        
        # Create storage directories
        self.BASE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NILAY-ERA")
        self.ACCOUNTS_FOLDER = os.path.join(self.BASE_FOLDER, "ACCOUNTS")
        os.makedirs(self.ACCOUNTS_FOLDER, exist_ok=True)

    def get_region(self, language_code: str) -> str:
        return self.REGION_LANG.get(language_code)

    def get_region_url(self, region_code: str) -> str:
        return self.REGION_URLS.get(region_code, "https://clientbp.ggblueshark.com/")

    def generate_exponent_number(self):
        exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
        number = random.randint(1, 99999)
        number_str = f"{number:05d}"
        exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
        return exponent_str

    def generate_random_name(self, base_name):
        exponent_part = self.generate_exponent_number()
        return f"{base_name[:7]}{exponent_part}"

    def generate_custom_password(self, prefix):
        characters = string.ascii_uppercase + string.digits
        random_part = ''.join(random.choice(characters) for _ in range(11))
        return f"{prefix}_{random_part}"

    def EnC_Vr(self, N):
        if N < 0: 
            return b''
        H = []
        while True:
            BesTo = N & 0x7F 
            N >>= 7
            if N: 
                BesTo |= 0x80
            H.append(BesTo)
            if not N: 
                break
        return bytes(H)

    def CrEaTe_VarianT(self, field_number, value):
        field_header = (field_number << 3) | 0
        return self.EnC_Vr(field_header) + self.EnC_Vr(value)

    def CrEaTe_LenGTh(self, field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return self.EnC_Vr(field_header) + self.EnC_Vr(len(encoded_value)) + encoded_value

    def CrEaTe_ProTo(self, fields):
        packet = bytearray()    
        for field, value in fields.items():
            if isinstance(value, dict):
                nested_packet = self.CrEaTe_ProTo(value)
                packet.extend(self.CrEaTe_LenGTh(field, nested_packet))
            elif isinstance(value, int):
                packet.extend(self.CrEaTe_VarianT(field, value))           
            elif isinstance(value, str) or isinstance(value, bytes):
                packet.extend(self.CrEaTe_LenGTh(field, value))           
        return packet

    def E_AEs(self, Pc):
        Z = bytes.fromhex(Pc)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        K = AES.new(key , AES.MODE_CBC , iv)
        R = K.encrypt(pad(Z , AES.block_size))
        return R

    def encrypt_api(self, plain_text):
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()

    def save_account(self, account_data, region):
        try:
            account_filename = os.path.join(self.ACCOUNTS_FOLDER, f"accounts-{region}.json")
            
            account_entry = {
                'uid': account_data["uid"],
                'password': account_data["password"],
                'account_id': account_data.get("account_id", "N/A"),
                'name': account_data["name"],
                'region': region,
                'date_created': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            accounts_list = []
            if os.path.exists(account_filename):
                try:
                    with open(account_filename, 'r', encoding='utf-8') as f:
                        accounts_list = json.load(f)
                except (json.JSONDecodeError, IOError):
                    accounts_list = []
            
            # Check if UID already exists
            existing_uids = [acc.get('uid') for acc in accounts_list]
            if account_data["uid"] not in existing_uids:
                accounts_list.append(account_entry)
                
                with open(account_filename, 'w', encoding='utf-8') as f:
                    json.dump(accounts_list, f, indent=2, ensure_ascii=False)
                
                return True
            else:
                return False
            
        except Exception as e:
            print(f"Error saving account: {e}")
            return False

    def create_acc(self, region, account_name, password_prefix):
        try:
            password = self.generate_custom_password(password_prefix)
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(self.key, message, hashlib.sha256).hexdigest()
            
            url = "https://100067.connect.garena.com/oauth/guest/register"
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'uid' in response.json():
                uid = response.json()['uid']
                print(f"Guest account created: {uid}")
                time.sleep(1)  # Small delay
                return self.token(uid, password, region, account_name, password_prefix)
            return None
        except Exception as e:
            print(f"Create account failed: {e}")
            time.sleep(1)
            return None

    def token(self, uid, password, region, account_name, password_prefix):
        try:
            url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "100067.connect.garena.com",
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            }
            body = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": self.key,
                "client_id": "100067"
            }
            
            response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'open_id' in response.json():
                open_id = response.json()['open_id']
                access_token = response.json()["access_token"]
                refresh_token = response.json()['refresh_token']
                
                result = self.encode_string(open_id)
                field = self.to_unicode_escaped(result['field_14'])
                field = codecs.decode(field, 'unicode_escape').encode('latin1')
                print(f"Token granted for: {uid}")
                time.sleep(1)
                return self.Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix)
            return None
        except Exception as e:
            print(f"Token grant failed: {e}")
            time.sleep(1)
            return None

    def encode_string(self, original):
        keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                     0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
        encoded = ""
        for i in range(len(original)):
            orig_byte = ord(original[i])
            key_byte = keystream[i % len(keystream)]
            result_byte = orig_byte ^ key_byte
            encoded += chr(result_byte)
        return {"open_id": original, "field_14": encoded}

    def to_unicode_escaped(self, s):
        return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

    def Major_Regsiter(self, access_token, open_id, field, uid, password, region, account_name, password_prefix):
        try:
            if region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            else:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            
            name = self.generate_random_name(account_name)
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",   
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }

            lang_code = self.REGION_LANG.get(region.upper(), "en")
            payload = {
                1: name,
                2: access_token,
                3: open_id,
                5: 102000007,
                6: 4,
                7: 1,
                13: 1,
                14: field,
                15: lang_code,
                16: 1,
                17: 1
            }

            payload_bytes = self.CrEaTe_ProTo(payload)
            encrypted_payload = self.E_AEs(payload_bytes.hex())
            
            response = requests.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=30)
            
            if response.status_code == 200:
                print(f"MajorRegister successful: {name}")
                
                login_result = self.perform_major_login(uid, password, access_token, open_id, region)
                account_id = login_result.get("account_id", "N/A")
                token = login_result.get("token", "")
                
                if token and account_id != "N/A" and region.upper() != "BR":
                    region_bound = self.force_region_binding(region, token)
                    if region_bound:
                        print(f"Region {region} bound successfully!")
                    else:
                        print(f"Region binding failed for {region}")
                
                account_data = {
                    "uid": uid, 
                    "password": password, 
                    "name": name, 
                    "region": region, 
                    "status": "success",
                    "account_id": account_id,
                    "token": token
                }
                
                return account_data
            else:
                print(f"MajorRegister returned status: {response.status_code}")
                return None
        except Exception as e:
            print(f"Major_Regsiter error: {str(e)}")
            time.sleep(1)
            return None

    def perform_major_login(self, uid, password, access_token, open_id, region):
        try:
            lang = self.REGION_LANG.get(region.upper(), "en")
            
            payload_parts = [
                b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
                lang.encode("ascii"),
                b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
            ]
            
            payload = b''.join(payload_parts)
            
            if region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorLogin"
            else:
                url = "https://loginbp.ggblueshark.com/MajorLogin"
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4.11f1"
            }

            data = payload
            data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            
            d = self.encrypt_api(data.hex())
            final_payload = bytes.fromhex(d)

            response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
            
            if response.status_code == 200 and len(response.text) > 10:
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    token = response.text[jwt_start:]
                    second_dot = token.find(".", token.find(".") + 1)
                    if second_dot != -1:
                        token = token[:second_dot + 44]
                        
                        account_id = self.decode_token(token)
                        return {"account_id": account_id, "token": token}
            
            return {"account_id": "N/A", "token": ""}
        except Exception as e:
            print(f"MajorLogin failed: {e}")
            return {"account_id": "N/A", "token": ""}

    def decode_token(self, token):
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                payload_part = parts[1]
                padding = 4 - len(payload_part) % 4
                if padding != 4:
                    payload_part += '=' * padding
                decoded = base64.urlsafe_b64decode(payload_part)
                data = json.loads(decoded)
                account_id = data.get('account_id') or data.get('external_id')
                if account_id:
                    return str(account_id)
        except Exception as e:
            print(f"JWT decode failed: {e}")
        return "N/A"

    def force_region_binding(self, region, token):
        try:
            if region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/ChooseRegion"
            else:
                url = "https://loginbp.ggblueshark.com/ChooseRegion"
            
            if region.upper() == "CIS":
                region_code = "RU"
            else:
                region_code = region.upper()
                
            fields = {1: region_code}
            proto_data = self.CrEaTe_ProTo(fields)
            encrypted_data = self.encrypt_api(proto_data.hex())
            payload = bytes.fromhex(encrypted_data)
            
            headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
                'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip",
                'Content-Type': "application/x-www-form-urlencoded",
                'Expect': "100-continue",
                'Authorization': f"Bearer {token}",
                'X-Unity-Version': "2018.4.11f1",
                'X-GA': "v1 1",
                'ReleaseVersion': "OB51"
            }
            
            response = requests.post(url, data=payload, headers=headers, verify=False, timeout=30)
            return response.status_code == 200
        except Exception as e:
            print(f"Region binding failed: {e}")
            return False

    def generate_account(self, region, account_name, password_prefix):
        """Main method to generate a single account"""
        account_result = self.create_acc(region, account_name, password_prefix)
        if not account_result:
            return None

        # Save account to file
        save_success = self.save_account(account_result, region)
        
        return {
            "status": "success" if account_result else "failed",
            "uid": account_result["uid"] if account_result else "N/A",
            "password": account_result["password"] if account_result else "N/A", 
            "name": account_result["name"] if account_result else "N/A",
            "region": region,
            "account_id": account_result.get("account_id", "N/A") if account_result else "N/A",
            "saved": save_success
        }

# Initialize the account generator
generator = AccountGeneratorAPI()

@app.route('/create', methods=['GET'])
def create_account():
    """API endpoint to create Free Fire account"""
    
    # Get parameters from query string
    region = request.args.get('region', 'IND').upper()
    name = request.args.get('name', 'GhostUser')
    password = request.args.get('password', 'MySecret123')
    
    # Validate region
    valid_regions = list(generator.REGION_LANG.keys())
    if region not in valid_regions:
        return jsonify({
            "status": "error",
            "message": f"Invalid region. Valid regions: {', '.join(valid_regions)}"
        }), 400
    
    try:
        # Generate account
        result = generator.generate_account(region, name, password)
        
        if result and result["status"] == "success":
            return jsonify({
                "status": "ok",
                "uid": result["uid"],
                "password": result["password"],
                "name": result["name"],
                "region": region,
                "account_id": result["account_id"],
                "saved": result["saved"]
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Account creation failed"
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500

@app.route('/regions', methods=['GET'])
def get_regions():
    """API endpoint to get available regions"""
    return jsonify({
        "status": "ok",
        "regions": generator.REGION_LANG
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "message": "Free Fire Account Generator API is running",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/')
def home():
    """Home page with API documentation"""
    docs = {
        "message": "Free Fire Account Generator API",
        "endpoints": {
            "/create": {
                "method": "GET",
                "parameters": {
                    "region": "Region code (e.g., IND, ID, BR, etc.)",
                    "name": "Account name prefix",
                    "password": "Password prefix"
                },
                "example": "http://127.0.0.1:5000/create?region=IND&name=GhostUser&password=MySecret123"
            },
            "/regions": {
                "method": "GET", 
                "description": "Get available regions"
            },
            "/health": {
                "method": "GET",
                "description": "Health check"
            }
        }
    }
    return jsonify(docs)

if __name__ == '__main__':
    print("🚀 Starting Free Fire Account Generator API...")
    print("📚 Available endpoints:")
    print("   • GET /create?region=IND&name=GhostUser&password=MySecret123")
    print("   • GET /regions") 
    print("   • GET /health")
    print("   • GET / (documentation)")
    print("\n🔗 API running at: http://127.0.0.1:5000")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)