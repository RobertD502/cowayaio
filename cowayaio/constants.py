"""Constants for CowayAIO"""

from .str_enum import StrEnum

class Endpoint(StrEnum):

    BASE_URI = 'https://iocareapp.coway.com/bizmob.iocare'
    CLEAN_CYCLE = '/clean-cycle'
    COMMON_DEVICES = '/com/devices/'
    CONTROL = '/control'
    CONTROL_DEVICE = '/com/control-device'
    DEVICE_LIST = '/com/user-devices'
    FILTERS = '/air/devices/'
    GET_TOKEN = '/com/token'
    HOME = '/home'
    INITIAL_LOGIN = '/com/login-info'
    MCU_VERSION = '/com/ota'
    NEW_BASE_URI = 'https://iocareapi.iot.coway.com/api/v1'
    OAUTH_URL = "https://id.coway.com/auth/realms/cw-account/protocol/openid-connect/auth"
    PROD_SETTINGS = '/com/user-device-status'
    REDIRECT_URL = "https://iocare-redirect.iot.coway.com/redirect_bridge.html"
    TOKEN_REFRESH = "https://iocareapi.iot.coway.com/api/v1/com/refresh-token"


class Parameter(StrEnum):

    APP_VERSION = "2.3.36"
    CLIENT_ID = "cwid-prd-iocare-20240327"
    SERVICE_CODE = "com.coway.IOCareKor"
    CLIENT_NAME = "IOCARE"


class Header(StrEnum):

    ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ACCEPT_LANG = "en-US,en;q=0.9"
    USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Version/10.0 Safari/602.1"
    CONTENT_JSON = "application/json"


class EndpointJSON(StrEnum):

    CHANGE_PRE_FILTER = "CWIA0600"
    CONTROL = 'CWIG0603'
    DEVICE_LIST = 'CWIG0304'
    FILTERS = 'CWIA0120'
    GET_TOKEN = 'CWCC0009'
    INITIAL_LOGIN = 'CWIL0100'
    MCU_VERSION = "CWIG0615"
    PROD_SETTINGS = "CWIG0301"
    STATUS = 'CWIG0602'
    TOKEN_REFRESH = 'CWCC0010'


class ErrorMessages(StrEnum):

    BAD_TOKEN = 'Unauthenticated (Missing or malformed JWT)'
    EXPIRED_TOKEN = 'Unauthenticated (Token is expired)'
    INVALID_REFRESH_TOKEN = '통합회원 토큰 갱신 오류 (error: invalid_grant)(error_desc: Invalid refresh token)'


class LightMode(StrEnum):

    AQI_OFF = '1'
    OFF = '2'
    ON = '0'


TIMEOUT = 5 * 60
