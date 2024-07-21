
import hashlib
import requests
import json
import base64
import random
import string
import base64
import json
import os
import hashlib
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from datetime import datetime

class VTB:
    def __init__(self, username, password, account_number):
                # Public key in PEM format
        self.public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz1zqQHtHvKczHh58ePiRNgOyi
HEx6lZDPlvwBTaHmkNlQyyJ06SIlMU1pmGKxILjT7n06nxG7LlFVUN5MkW/jwF39
/+drkHM5B0kh+hPQygFjRq81yxvLwolt+Vq7h+CTU0Z1wkFABcTeQQldZkJlTpyx
0c3+jq0o47wIFjq5fwIDAQAB
-----END PUBLIC KEY-----
"""

        # Load the public key
        self.public_key = serialization.load_pem_public_key(self.public_key_pem.encode())
        self.authToken = ""
        self.clientIp = ""
        self.session = requests.Session()
        self.guid = ""
        self.uuid = ""
        self.is_login = False
        self.key_captcha = "CAP-6C2884061D70C08F10D6257F2CA9518C"
        self.file = f"data/{username}.txt"
        self.url = {
    "getCaptcha": "https://ebank.vtb.com.vn/IBS-API-Gateway/corporate/captcha?guid=",
    "login": "https://efast.vietinbank.vn/api/v1/account/login",
    "getHistories": "https://efast.vietinbank.vn/api/v1/account/history",
    "getlistAccount": "https://efast.vietinbank.vn/api/v1/account/getUserInfo",
}
        self.lang =  "vi"
        self.request_id = None
        self._timeout = 60
        self.appVersion = ""
        self.clientOsVersion = "WINDOWS"
        self.browserVersion = "126.0.0.0"
        self.browserName = "Edge"
        self.deviceCode = ""
        self.deviceName = "" 
        self.screenResolution = "469x825"
        self.app_version = "1.0"
        self.challenge = ""
        self.defaultPublicKey = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAikqQrIzZJkUvHisjfu5Z\n\
CN+TLy//43CIc5hJE709TIK3HbcC9vuc2+PPEtI6peSUGqOnFoYOwl3i8rRdSaK1\n\
7G2RZN01MIqRIJ/6ac9H4L11dtfQtR7KHqF7KD0fj6vU4kb5+0cwR3RumBvDeMlB\n\
OaYEpKwuEY9EGqy9bcb5EhNGbxxNfbUaogutVwG5C1eKYItzaYd6tao3gq7swNH7\n\
p6UdltrCpxSwFEvc7douE2sKrPDp807ZG2dFslKxxmR4WHDHWfH0OpzrB5KKWQNy\n\
zXxTBXelqrWZECLRypNq7P+1CyfgTSdQ35fdO7M1MniSBT1V33LdhXo73/9qD5e5\n\
VQIDAQAB\n\
-----END PUBLIC KEY-----"
        self.clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCg+aN5HEhfrHXCI/pLcv2Mg01gNzuAlqNhL8ojO8KwzrnEIEuqmrobjMFFPkrMXUnmY5cWsm0jxaflAtoqTf9dy1+LL5ddqNOvaPsNhSEMmIUsrppvh1ZbUZGGW6OUNeXBEDXhEF8tAjl3KuBiQFLEECUmCDiusnFoZ2w/1iOZJwIDAQAB"
        self.clientPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQCg+aN5HEhfrHXCI/pLcv2Mg01gNzuAlqNhL8ojO8KwzrnEIEuq\n\
mrobjMFFPkrMXUnmY5cWsm0jxaflAtoqTf9dy1+LL5ddqNOvaPsNhSEMmIUsrppv\n\
h1ZbUZGGW6OUNeXBEDXhEF8tAjl3KuBiQFLEECUmCDiusnFoZ2w/1iOZJwIDAQAB\n\
AoGAEGDV7SCfjHxzjskyUjLk8UL6wGteNnsdLGo8WtFdwbeG1xmiGT2c6eisUWtB\n\
GQH03ugLG1gUGqulpXtgzyUYcj0spHPiUiPDAPY24DleR7lGZHMfsnu20dyu6Llp\n\
Xup07OZdlqDGUm9u2uC0/I8RET0XWCbtOSr4VgdHFpMN+MECQQDbN5JOAIr+px7w\n\
uhBqOnWJbnL+VZjcq39XQ6zJQK01MWkbz0f9IKfMepMiYrldaOwYwVxoeb67uz/4\n\
fau4aCR5AkEAu/xLydU/dyUqTKV7owVDEtjFTTYIwLs7DmRe247207b6nJ3/kZhj\n\
gsm0mNnoAFYZJoNgCONUY/7CBHcvI4wCnwJBAIADmLViTcjd0QykqzdNghvKWu65\n\
D7Y1k/xiscEour0oaIfr6M8hxbt8DPX0jujEf7MJH6yHA+HfPEEhKila74kCQE/9\n\
oIZG3pWlU+V/eSe6QntPkE01k+3m/c82+II2yGL4dpWUSb67eISbreRovOb/u/3+\n\
YywFB9DxA8AAsydOGYMCQQDYDDLAlytyG7EefQtDPRlGbFOOJrNRyQG+2KMEl/ti\n\
Yr4ZPChxNrik1CFLxfkesoReXN8kU/8918D0GLNeVt/C\n\
-----END RSA PRIVATE KEY-----"
        self.init_guid()
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.sessionId = ""
            self.mobileId = ""
            self.clientId = ""
            self.cif = ""
            self.res = ""
            self.browserToken = ""
            self.browserId = ""
            self.E = ""
            self.tranId = ""
            self.cifNo = ""
            self.browserId = hashlib.md5(self.username.encode()).hexdigest()
            self.save_data()
            
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': getattr(self, 'sessionId', ''),
            'mobileId': getattr(self, 'mobileId', ''),
            'clientId': self.clientId,
            'cif': getattr(self, 'cif', ''),
            'E': getattr(self, 'E', ''),
            'res': getattr(self, 'res', ''),
            'tranId': getattr(self, 'tranId', ''),
            'browserToken': getattr(self, 'browserToken', ''),
            'browserId': self.browserId,
            'cifNo': self.cifNo,
        }
        with open(self.file, 'w') as f:
            json.dump(data, f)

    def parse_data(self):
        with open(self.file, 'r') as f:
            data = json.load(f)
        self.username = data.get('username', '')
        self.password = data.get('password', '')
        self.account_number = data.get('account_number', '')
        self.sessionId = data.get('sessionId', '')
        self.mobileId = data.get('mobileId', '')
        self.clientId = data.get('clientId', '')
        self.token = data.get('token', '')
        self.accessToken = data.get('accessToken', '')
        self.authToken = data.get('authToken', '')
        self.cif = data.get('cif', '')
        self.res = data.get('res', '')
        self.tranId = data.get('tranId', '')
        self.browserToken = data.get('browserToken', '')
        self.browserId = data.get('browserId', '')
        self.E = data.get('E', '')
        self.cifNo = data.get('cifNo', '')
    def init_guid(self):
        timestamp = str(int(time.time()))
        self.uuid = str(uuid.uuid4())
        combined_string = f"{timestamp}{self.uuid}"
        self.guid = hashlib.md5(combined_string.encode()).hexdigest()
        
    def encrypt_message(self,message):
        # Encrypt the message using the public key
        encrypted = self.public_key.encrypt(
            message.encode(),
            padding.PKCS1v15()  # Padding scheme must match the one used in JavaScript
        )
        # Encode the encrypted message in base64 for readability
        encrypted_base64 = base64.b64encode(encrypted).decode()
        return encrypted_base64


    def curlPost(self, url, data):
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://efast.vietinbank.vn',
        'Pragma': 'no-cache',
        'Referer': 'https://efast.vietinbank.vn/login',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        response = self.session.post(url, headers=headers, data=json.dumps(data))
        try:
            result = response.json()
        except:
            result = response.text
        return result

    def generate_request_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12)) + '|' + str(int(datetime.now().timestamp()))
    def doLogin(self):
        self.request_id = self.generate_request_id()
        param = {
            "channel": "eFAST",
            "cifno": False,
            "language": "vi",
            "newCore": "Y",
            "password": self.encrypt_message(self.password),
            "requestId": self.request_id,
            "screenResolution": self.screenResolution,
            "sessionId": None,
            "username":  self.encrypt_message(self.username),
            "version": self.app_version
        }
        result = self.curlPost(self.url['login'], param)
        if 'status' in result and 'message' in result['status'] and result['status']['message'] == "LOGON_SUCCESS":
            self.cifNo = result['cifNo']
            self.sessionId = result['sessionId']
            self.userInfo = result['corpUser']
            self.save_data()
            self.is_login = True
            return {
                'code': 200,
                'success': True,
                'message': "success",
                'sessionId': self.sessionId,
                'userInfo': self.userInfo,
                'data': result if result else ""
            }
        else:
            return {
                'code': 500,
                'success': False,
                'message': result['status']['message'],
                "param": param,
                'data': result if result else ""
            }

    def saveData(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': self.sessionId,
            'mobileId': self.mobileId,
            'clientId': self.clientId,
            'cif': self.cif,
            'E': self.E,
            'res': self.res,
            'tranId': self.tranId,
            'browserToken': self.browserToken,
            'browserId': self.browserId,
        }
        with open(f"data/{self.username}.txt", "w") as file:
            json.dump(data, file)

    def parseData(self):
        with open(f"data/{self.username}.txt", "r") as file:
            data = json.load(file)
            self.username = data["username"]
            self.password = data["password"]
            self.account_number = data.get("account_number", "")
            self.sessionId = data.get("sessionId", "")
            self.mobileId = data.get("mobileId", "")
            self.clientId = data.get("clientId", "")
            self.token = data.get("token", "")
            self.accessToken = data.get("accessToken", "")
            self.authToken = data.get("authToken", "")
            self.cif = data.get("cif", "")
            self.res = data.get("res", "")
            self.tranId = data.get("tranId", "")
            self.browserToken = data.get("browserToken", "")
            self.browserId = data.get("browserId", "")
            self.E = data.get("E", "")

    def getE(self):
        ahash = hashlib.md5(self.username.encode()).hexdigest()
        imei = '-'.join([ahash[i:i+4] for i in range(0, len(ahash), 4)])
        return imei.upper()

    def getCaptcha(self):
        captchaToken = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        url = self.url['getCaptcha'] + captchaToken
        response = requests.get(url)
        result = base64.b64encode(response.content).decode('utf-8')
        return result

    def getlistAccount(self):
        self.request_id = self.generate_request_id()
        if not self.is_login:
            login = self.doLogin()
            if not login['success']:
                return login
        param = {
            "channel": "eFAST",
            "cifno": self.encrypt_message(self.cifNo),
            "language": "vi",
            "newCore": "Y",
            "requestId": self.request_id,
            "roleId": "8",
            "screenResolution": self.screenResolution,
            "sessionId": self.sessionId,
            "username": self.encrypt_message(self.username),
            "version": self.app_version
        }
        result = self.curlPost(self.url['getlistAccount'], param)
        if 'status' in result and 'code' in result['status'] and result['status']['code'] == "1":
            for account in result['lsAccount']:
                if self.account_number == account['accountNo']:
                    if float(account['availableBalance']) < 0 :
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':float(account['availableBalance'])
                                }
                                }
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':self.account_number,
                                    'balance':float(account['availableBalance'])
                        }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else: 
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 


    def getHistories(self, fromDate="16/06/2023", toDate="16/06/2023", account_number='', page=0,limit = 100):
        self.request_id = self.generate_request_id()
        if not self.is_login:
                login = self.doLogin()
                if not login['success']:
                    return login
        param = {
            "acctNo": account_number if account_number else self.account_number,
            "fromDate": fromDate,
            "historyType": "CORE",
            "toDate": toDate,
            "page": page,
            "pageSize": limit
        }
        param = {
            "accountNo": account_number if account_number else self.account_number,
            "accountType": "D",
            "cardNo": "",
            "channel": "eFAST",
            "cifno": self.encrypt_message(self.cifNo),
            "currency": "VND",
            "dorcC": "Credit",
            "dorcD": "Debit",
            "endTime": "23:59:59",
            "fromAmount": 0,
            "fromDate": fromDate,
            "language": "vi",
            "lastRecord": "",
            "newCore": "",
            "pageIndex": page,
            "pageSize": limit,
            "queryType": "NORMAL",
            "requestId": self.request_id,
            "screenResolution": self.screenResolution,
            "searchKey": "",
            "sessionId": self.sessionId,
            "startTime": "00:00:00",
            "toAmount": 0,
            "toDate": toDate,
            "username": self.encrypt_message(self.username),
            "version": self.app_version
        }
        print(param)
        result = self.curlPost(self.url['getHistories'], param)
        print(result)
        if 'status' in result and 'code' in result['status'] and result['status']['code'] == "1":
            return {'code':200,'success': True, 'message': 'Thành công',
                            'data':{
                                'transactions':result['transactions'],
                    }}
        else:
            return  {
                    "success": False,
                    "code": 503,
                    "message": "Service Unavailable!"
                }

