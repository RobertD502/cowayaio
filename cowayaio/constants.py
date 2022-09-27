BASE_URI = 'https://iocareapp.coway.com/bizmob.iocare'
OAUTH_URL = "https://idp.coway.com/oauth2/v1/authorize"
SIGNIN_URL = "https://idp.coway.com/user/signin/"
REDIRECT_URL = "https://iocareapp.coway.com/bizmob.iocare/redirect/redirect.html"
CLIENT_ID = "UmVuZXdhbCBBcHA"
SERVICE_CODE = "com.coway.IOCareKor"
USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1"

DEVICE_LIST = 'CWIG0304'
TOKEN_REFRESH = 'CWIL0100'
STATUS = 'CWIG0602'
CONTROL = 'CWIG0603'
FILTERS = 'CWIA0120'
MCU_VERSION = "CWIG0615"

TIMEOUT = 5 * 60

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)