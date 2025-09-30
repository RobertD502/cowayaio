"""Constants for CowayAIO"""

from .str_enum import StrEnum
from .__version__ import __version__ as version


class Endpoint(StrEnum):

    BASE_URI = 'https://iocare.iotsvc.coway.com/api/v1'
    GET_TOKEN = '/com/token'
    NOTICES = '/com/notices'
    OAUTH_URL = "https://id.coway.com/auth/realms/cw-account/protocol/openid-connect/auth"
    REDIRECT_URL = "https://iocare-redirect.iotsvc.coway.com/redirect_bridge_empty.html"
    TOKEN_REFRESH = "/com/refresh-token"
    USER_INFO = "/com/my-info"
    PLACES = "/com/places"
    AIR = "/air/devices"
    PURIFIER_HTML_BASE = "https://iocare2.coway.com/en"
    SECONDARY_BASE = "https://iocare2.coway.com/api/proxy/api/v1"


class Parameter(StrEnum):

    APP_VERSION = "2.15.0"
    CLIENT_ID = "cwid-prd-iocare-plus-25MJGcYX"
    CLIENT_NAME = "IOCARE"
    TIMEZONE = "America/Kentucky/Louisville"


class Header(StrEnum):

    ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ACCEPT_LANG = "en"
    CALLING_PAGE = 'product'
    CONTENT_JSON = "application/json"
    COWAY_LANGUAGE = "en-US,en;q=0.9"
    COWAY_USER_AGENT = f"CowayAIO/{version}"
    HTML_USER_AGENT = f"CowayAIO/{version}"
    SOURCE_PATH = 'iOS'
    THEME = 'light'
    USER_AGENT = f"CowayAIO/{version}"

class ErrorMessages(StrEnum):

    BAD_TOKEN = 'Unauthenticated (crypto/rsa: verification error)'
    EXPIRED_TOKEN = 'Unauthenticated (Token is expired)'
    INVALID_REFRESH_TOKEN = '통합회원 토큰 갱신 오류 (error: invalid_grant)(error_desc: Invalid refresh token)'
    INVALID_GRANT = '통합회원 토큰 발급 오류 (error: invalid_grant)(error_desc: Code not valid)'


class LightMode(StrEnum):

    AQI_OFF = '1'
    OFF = '2'
    HALF_OFF = '3'  # For IconS only
    ON = '0'


CATEGORY_NAME = '청정기'  # Translates to purifier
PREFILTER_CYCLE = {
    2: '112',
    3: '168',
    4: '224'
}
TIMEOUT = 5 * 60

