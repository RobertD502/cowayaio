"""Constants for CowayAIO"""

from .str_enum import StrEnum

class Endpoint(StrEnum):

    BASE_URI = 'https://iocareapp.coway.com/bizmob.iocare'
    OAUTH_URL = "https://id.coway.com/auth/realms/cw-account/protocol/openid-connect/auth"
    REDIRECT_URL = "https://iocareapp.coway.com/bizmob.iocare/redirect/redirect_bridge.html"


class Parameter(StrEnum):

    CLIENT_ID = "cwid-prd-iocare-20220930"
    SERVICE_CODE = "com.coway.IOCareKor"
    APP_VERSION = "2.3.22"

class Header(StrEnum):

    USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1 app"
    ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ACCEPT_LANG = "en-US,en;q=0.9"


class Endpoint_JSON(StrEnum):

    DEVICE_LIST = 'CWIG0304'
    TOKEN_REFRESH = 'CWIL0100'
    STATUS = 'CWIG0602'
    CONTROL = 'CWIG0603'
    FILTERS = 'CWIA0120'
    MCU_VERSION = "CWIG0615"

TIMEOUT = 5 * 60
