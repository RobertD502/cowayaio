"""Python API for Coway IoCare Purifiers"""
from __future__ import annotations

from typing import Any
import asyncio
from datetime import datetime, timedelta
import json
import logging
import re
from zoneinfo import ZoneInfo

from bs4 import BeautifulSoup
from aiohttp import ClientResponse, ClientSession
from http.cookies import SimpleCookie

from cowayaio.constants import (
    CATEGORY_NAME,
    Endpoint,
    ErrorMessages,
    Header,
    LightMode,
    Parameter,
    PREFILTER_CYCLE,
    TIMEOUT,
)
from cowayaio.exceptions import (
    AuthError,
    CowayError,
    PasswordExpired,
    RateLimited,
    ServerMaintenance
)
from cowayaio.purifier_model import PurifierData, CowayPurifier


LOGGER = logging.getLogger(__name__)


class CowayClient:
    """Coway client."""

    def __init__(
        self, username: str, password: str, session: ClientSession | None = None, timeout: int = TIMEOUT
    ) -> None:
        """Initialize Coway Client.

        username: Coway IoCare account e-mail or phone number
        password: Coway IoCare account password
        session: aiohttp.ClientSession or None to create a new session
        """

        self.username: str = username
        self.password: str = password
        self.skip_password_change: bool = False
        self._session: ClientSession = session if session else ClientSession()
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expiration: datetime | None = None
        self.country_code: str | None = None
        self.places: list[dict[str, Any]] | None = None
        self.check_token: bool = True
        self.timeout: int = timeout
        self.server_maintenance: dict[str, Any] | None = None

    async def login(self) -> None:

        login_url, cookies = await self._get_login_cookies()
        auth_code = await self._get_auth_code(login_url, cookies)
        self.access_token, self.refresh_token = await self._get_token(auth_code)
        # Token expires in 1 hour
        self.token_expiration = datetime.now() + timedelta(seconds=3600)
        LOGGER.debug(
            f'Token expiration set to {self.token_expiration}.'
        )
        self.country_code = await self._get_country_code()
        self.places = await self._get_places()

    async def _get_login_cookies(self) -> tuple[str, SimpleCookie]:
        """Get openid-connect login url and associated cookies."""

        LOGGER.debug(f'Getting Coway login cookies for {self.username}')
        response, html_page = await self._get(Endpoint.OAUTH_URL)
        LOGGER.debug(f'Login cookies response: {response}')
        if (status := response.status) != 200:
            error = response.reason
            if status == 503:
                raise ServerMaintenance(
                    f'Coway Servers are undergoing maintenance. Response: {error}'
                )
            raise CowayError(
                f'Coway API error while fetching login page. Status: {status}, Reason: {error}'
            )
        cookies = response.cookies
        soup = BeautifulSoup(html_page, 'html.parser')
        try:
            login_url = soup.find('form', id='kc-form-login').get('action')
            LOGGER.debug(f'Login URL obtained: {login_url}')
        except AttributeError:
            raise CowayError(f'Coway API error: Coway servers did not return a valid Login URL. Retrying now.')
        return login_url, cookies

    async def _get_auth_code(self, login_url: str, cookies: SimpleCookie) -> str:
        """Get auth code"""

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': Header.USER_AGENT
        }
        data = {
            'clientName': Parameter.CLIENT_NAME,
            'termAgreementStatus': '',
            'idp': '',
            'username': self.username,
            'password': self.password,
            'rememberMe': 'on'
        }

        password_skip_data = {
            'cmd': 'change_next_time',
            'checkPasswordNeededYn': 'Y',
            'current_password': '',
            'new_password': '',
            'new_password_confirm': ''
        }
        LOGGER.debug(f'Obtaining auth code for {self.username}')
        response, password_skip_init = await self._post(login_url, cookies, headers, data)
        LOGGER.debug(f'Auth code response: {response}')
        if password_skip_init:
            response, password_skip_init = await self._post(response, cookies, headers, password_skip_data)
            LOGGER.debug(f'Auth code skip password response: {response}')
        code = response.url.query_string.partition('code=')[-1]
        return code

    async def _get_token(self, auth_code: str) -> tuple[str, str]:
        """Get access token and refresh token."""

        data = {
            'authCode': auth_code,
            'redirectUrl': Endpoint.REDIRECT_URL,
        }

        LOGGER.debug(f'Obtaining access/refresh token for {self.username}')
        response = await self._post_endpoint(data)

        if 'error' in response:
            LOGGER.debug(
                f'Received error in response when obtaining access/refresh token for {self.username}. '
                f'Response: {response}'
            )
            if response['error'].get('message') == ErrorMessages.INVALID_GRANT:
                raise RateLimited(
                    f'Failed fetching Coway access token. The account has likely '
                    f'been rate-limited (blocked). Please wait 24 hours before trying again. '
                    f'If, after 24 hours, you\'re unable to log in even with the mobile IoCare+ app, '
                    f'please contact Coway support.'
                )
            else:
                raise CowayError(
                    f'Failed fetching Coway access token: {response["error"].get("message")}'
                )
        else:
            access_token: str | None = None
            refresh_token: str | None = None
            if 'data' in response:
                access_token = response['data'].get('accessToken')
                refresh_token = response['data'].get('refreshToken')
            if access_token is not None and refresh_token is not None:
                return access_token, refresh_token
            else:
                raise CowayError(
                    f'Failed fetching Coway access/refresh token for {self.username}. '
                    f'Response: {response}'
                )

    async def _check_token(self) -> None:
        """Checks to see if token has expired and needs to be refreshed."""

        if self.check_token:
            LOGGER.debug(f'Checking token for {self.username}')
            current_dt = datetime.now()
            if any(token_var is None for token_var in [self.access_token, self.refresh_token, self.token_expiration]):
                LOGGER.debug(
                    f'Coway token check determined one of access_token, refresh_token, or token_expiration is None. '
                    f'Logging in to fetch access/refresh token for {self.username}'
                )
                await self.login()
                return None
            # Refresh access token if it expires within 5 minutes
            elif (self.token_expiration-current_dt).total_seconds() < 300:
                LOGGER.debug(
                    f'Access token expires at {self.token_expiration}. '
                    f'Token expiration is within 5 minutes. Refreshing token for {self.username}'
                )
                LOGGER.debug('Calling _refresh_token function')
                await self._refresh_token()
                return None
            else:
                return None
        else:
            LOGGER.debug(
                f'Token check is set to False. Skipping token check for {self.username} '
            )
            return None

    async def _refresh_token(self) -> None:
        """Obtain new access token using refresh token."""

        headers = {
            'content-type': 'application/json',
            'accept': '*/*',
            'accept-language': Header.COWAY_LANGUAGE,
            'user-agent': Header.COWAY_USER_AGENT,
        }
        data = {
            'refreshToken': self.refresh_token,
        }

        url = f'{Endpoint.BASE_URI}{Endpoint.TOKEN_REFRESH}'
        LOGGER.debug(f'Refreshing tokens for {self.username} at {url}')
        async with self._session.post(url, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            response = await self._response(resp)
            if 'error' in response:
                LOGGER.debug(
                    f'Error received while refreshing tokens for {self.username}. '
                    f'Response: {response}'
                )
            self.access_token = response['data'].get('accessToken')
            self.refresh_token = response['data'].get('refreshToken')
            if self.access_token is None or self.refresh_token is None:
                raise CowayError(
                    f'Failed to refresh tokens for {self.username}. '
                    f'Response: {response}'
                )
            else:
                self.token_expiration = datetime.now() + timedelta(seconds=3600)
                LOGGER.debug(
                    f'Tokens have been refreshed for {self.username}. '
                    f'New token expiration: {self.token_expiration}'
                )

    async def _get_country_code(self) -> str:
        """Obtain country code associated with the account."""

        endpoint = f'{Endpoint.BASE_URI}{Endpoint.USER_INFO}'
        headers = await self._create_endpoint_header()
        LOGGER.debug(f'Getting country code for {self.username}')
        response = await self._get_endpoint(endpoint=endpoint, headers=headers, params=None)
        if 'data' in response:
            LOGGER.debug(
                f'Country code retrieval response for {self.username}: '
                f'{json.dumps(response["data"], indent=4)}'
            )
            if 'maintainInfos' in response['data']:
                raise ServerMaintenance(
                    f'Coway Servers are undergoing maintenance.'
                )
            if 'memberInfo' in response['data']:
                country_code = response['data']['memberInfo'].get('countryCode')
                if country_code is not None:
                    return country_code
                else:
                    raise CowayError(
                        f' Failed to get country code for {self.username}. '
                        f'Response: {response}'
                    )
        if 'error' in response:
            raise CowayError(f'Failed to get country code associated with account. {response["error"]}')

    async def _get_places(self) -> list[dict[str, Any]]:
        """Fetches all places(homes) associated with account."""

        endpoint = f'{Endpoint.BASE_URI}{Endpoint.PLACES}'
        params = {
            'countryCode': self.country_code,
            'langCd': Header.ACCEPT_LANG,
            'pageIndex': '1',
            'pageSize': '20',
            'timezoneId': Parameter.TIMEZONE
        }
        headers = await self._create_endpoint_header()
        LOGGER.debug(f'Getting places for {self.username}')
        response = await self._get_endpoint(endpoint=endpoint, headers=headers, params=params)
        if 'error' in response:
            raise CowayError(f'Failed to get places associated with account. {response["error"]}')
        if 'data' in response:
            places = response['data'].get('content')
            if places is not None:
                return places
            else:
                raise CowayError(
                    f'No places found associated with {self.username}. '
                    f'Response: {response}'
                )
        else:
            raise CowayError(
                f'No places found associated with {self.username}. '
                f'Response: {response}'
            )

    async def async_get_purifiers(self) -> list[dict[str, Any]]:
        """Gets all purifiers linked to Coway account."""

        params = {
            'pageIndex': '0',
            'pageSize': '100'
        }
        headers = await self._create_endpoint_header()
        purifiers: list[dict[str, Any]] = []
        for place in self.places:
            LOGGER.debug(
                f'Checking place for {self.username}. '
                f'Place ID: {place.get("placeId")}, Place Name: {place.get("placeName")}, '
                f'Place Device Count: {place.get("deviceCnt")}'
            )
            if place['deviceCnt'] != 0:
                url = f'{Endpoint.BASE_URI}{Endpoint.PLACES}/{place["placeId"]}/devices'
                LOGGER.debug(
                    f'Fetching devices for {self.username}. '
                    f'Place ID: {place.get("placeId")}, Place Name: {place.get("placeName")}, '
                    f'URL: {url}'
                )
                try:
                    response = await self._get_endpoint(url, headers, params)
                except AuthError:
                    LOGGER.debug(
                        'Coway IoCare access and refresh tokens are invalid. Attempting to fetch new tokens.'
                    )
                    await self.login()
                    headers = await self._create_endpoint_header()
                    response = await self._get_endpoint(url, headers, params)
                if 'error' in response:
                    raise CowayError(
                        f'Failed to get Coway devices for Place ID: {place.get("placeId")} '
                        f'Response: {response["error"]}'
                    )
                if 'data' in response:
                    devices = response['data'].get('content')
                    if devices is not None:
                        for device in response['data']['content']:
                            if device['categoryName'] == CATEGORY_NAME:
                                purifiers.append(device)
                    else:
                        LOGGER.debug(
                            f'No devices found for account {self.username} at '
                            f'Place ID: {place.get("placeId")}, Place Name: {place.get("placeName")}'
                        )
                else:
                    LOGGER.debug(
                        f'No devices found for account {self.username} at '
                        f'Place ID: {place.get("placeId")}, Place Name: {place.get("placeName")}'
                    )
        return purifiers

    async def async_get_purifiers_data(self) -> PurifierData:
        """Return dataclass with Purifier Devices."""

        LOGGER.debug(
            f'Get purifiers data function: Getting purifiers data for {self.username}'
        )
        if not self.places:
            LOGGER.debug(
                f'No places loaded. Doing initial login for {self.username}'
            )
            await self.login()
        LOGGER.debug(
            f'Get purifiers data function: Calling async_get_purifiers'
        )
        purifiers = await self.async_get_purifiers()
        LOGGER.debug(
            f'Purifiers found for {self.username}: {json.dumps(purifiers, indent=4)}'
        )
        #  Prevent checking access token for every purifier iteration after it has
        #  already been checked once.
        self.check_token = False
        LOGGER.debug(
            f'self.check_token set to False to prevent checking tokens multiple times '
            f'within get_purifiers_data function.'
        )
        LOGGER.debug(
            f'Get purifiers data function: Calling async_server_maintenance_notice'
        )
        await self.async_server_maintenance_notice()
        device_data: dict[str, CowayPurifier] = {}
        for dev in purifiers:
            LOGGER.debug(
                f'Starting construction of CowayPurifier object for device '
                f'{dev.get("dvcNick")} on account {self.username}'
            )
            LOGGER.debug(
                f'Fetching purifier HTML page for device {dev.get("dvcNick")}'
            )
            purifier_html = await self._get_purifier_html(
                dev['dvcNick'],
                dev['deviceSerial'],
                dev['modelCode'],
                dev['placeId']
            )
            soup = BeautifulSoup(purifier_html, 'html.parser')
            try:
                script_search = soup.select('script:-soup-contains("sensorInfo")')
                script_text = script_search[0].text
                start_index = script_text.find('{')
                end_index = script_text.rfind('}')
                extracted_string = script_text[start_index:end_index + 1].replace('\\', '')
                purifier_json = json.loads(extracted_string)
                LOGGER.debug(
                    f'Parsed the following purifier JSON info: {json.dumps(purifier_json, indent=4)}'
                )
                purifier_info: dict[str, Any] | None = {}
                if 'children' in purifier_json:
                    for data in purifier_json['children']:
                        if isinstance(data, dict):
                            purifier_info = data
                else:
                    LOGGER.debug(
                        f'No children key found for purifier {dev.get("dvcNick")}. '
                        f'Setting purifier info variable to None.'
                    )
                    purifier_info = None
            except (AttributeError, Exception) as purifier_error:
                raise CowayError(
                    f'Coway Error - Failed to parse purifier HTML page for info: {purifier_error}'
                )

            parsed_info: dict[str, Any] = {
                'device_info': {},
                'mcu_info': {},
                'network_info': {},
                'sensor_info': {},
                'status_info': {},
                'aq_grade': {},
                'filter_info': {},
                'timer_info': str | None,
            }
            LOGGER.debug(
                f'Purifier {dev["dvcNick"]} purifier_info variable: {json.dumps(purifier_info, indent=4)}'
            )
            for data in purifier_info.get('coreData'):
                if 'currentMcuVer' in data.get('data'):
                    parsed_info['mcu_info'] = data.get('data', {})
                if 'sensorInfo' in data.get('data'):
                    parsed_info['sensor_info'] = data['data']['sensorInfo'].get('attributes', {})
            if 'deviceStatusData' in purifier_info:
                parsed_info['status_info'] = purifier_info['deviceStatusData'].get('data', {}).get('statusInfo', {}).get('attributes', {})
            if 'baseInfoForModelCodeData' in purifier_info:
                parsed_info['device_info'] = purifier_info['baseInfoForModelCodeData'].get('deviceInfo', {})
            if 'deviceModule' in purifier_info:
                parsed_info['network_info'] = purifier_info['deviceModule'].get('data', {}).get('content', {}).get('deviceModuleDetailInfo', {})
                parsed_info['aq_grade'] = purifier_info['deviceModule'].get('data', {}).get('content', {}).get('deviceModuleDetailInfo', {}).get('airStatusInfo')

            LOGGER.debug(
                f'Fetching filter info endpoint for purifier {dev.get("dvcNick")}'
            )
            filter_info = await self.async_fetch_filter_status(
                dev['placeId'],
                dev['deviceSerial'],
                dev['dvcNick']
            )
            LOGGER.debug(
                f'{dev.get("dvcNick")} filters endpoint response: {filter_info}'
            )
            filter_dict: dict[str, Any]  = {}
            for dev_filter in filter_info:
                if dev_filter.get('supplyNm') == 'Pre-Filter':
                    filter_dict['pre-filter'] = dev_filter
                else:
                    filter_dict['max2'] = dev_filter
            parsed_info['filter_info'] = filter_dict
            LOGGER.debug(
                f'{dev.get("dvcNick")} filter dict constructed: {filter_dict}'
            )
            LOGGER.debug(
                f'Fetching timer endpoint for {dev.get("dvcNick")}'
            )
            timer = await self.async_fetch_timer(dev['deviceSerial'], dev['dvcNick'])
            parsed_info['timer_info'] = timer.get('offTimer')

            device_attr = {
                'device_id': dev.get('deviceSerial'),
                'model': parsed_info['device_info'].get('productName'),
                'model_code': dev.get('productModel'),
                'code': parsed_info['device_info'].get('modelCode'),
                'name': dev.get('dvcNick'),
                'product_name': parsed_info['device_info'].get('prodName'),
                'place_id': dev.get('placeId'),
            }
            network_status = parsed_info['network_info'].get('wifiConnected')
            if not network_status and network_status is not None:
                LOGGER.debug(
                    f'{device_attr["name"]} Purifier is not connected to WiFi.'
                )

            mcu_version = parsed_info['mcu_info'].get('currentMcuVer')
            is_on = parsed_info['status_info'].get('0001') == 1
            auto_mode = parsed_info['status_info'].get('0002') == 1
            auto_eco_mode = parsed_info['status_info'].get('0002') == 6
            eco_mode = parsed_info['status_info'].get('0002') == 6
            night_mode = parsed_info['status_info'].get('0002') == 2
            rapid_mode = parsed_info['status_info'].get('0002') == 5
            fan_speed = parsed_info['status_info'].get('0003')
            light_on = parsed_info['status_info'].get('0007') == 2
            # 250s/IconS purifier has more than just on and off
            light_mode = parsed_info['status_info'].get('0007')
            button_lock = parsed_info['status_info'].get('0024')
            timer = parsed_info['timer_info']
            timer_remaining = parsed_info['status_info'].get('0008')
            if filters := parsed_info['filter_info']:
                if 'pre-filter' in filters:
                    pre_filter_pct = parsed_info['filter_info']['pre-filter'].get('filterRemain')
                    pre_filter_change_frequency = parsed_info['filter_info']['pre-filter'].get('replaceCycle')
                else:
                    pre_filter_pct = 100 - parsed_info['sensor_info']['0011'] if '0011' in parsed_info['sensor_info'] else None
                    pre_filter_change_frequency = None
                if 'max2' in filters:
                    max2_pct = parsed_info['filter_info']['max2'].get('filterRemain')
                else:
                    max2_pct = 100 - parsed_info['sensor_info']['0012'] if '0012' in parsed_info['sensor_info'] else None

            else:
                # 250S filter endpoint is currently under development by Coway
                pre_filter_pct = 100 - parsed_info['sensor_info']['0011'] if '0011' in parsed_info['sensor_info'] else None
                max2_pct = 100 - parsed_info['sensor_info']['0012'] if '0012' in parsed_info['sensor_info'] else None
                pre_filter_change_frequency = None
            # Model codes UK (02FMG), Europe (02FMF, 02FWN)
            odor_filter = 100 - parsed_info['sensor_info']['0013'] if '0013' in parsed_info['sensor_info'] else None
            aq_grade = parsed_info['aq_grade'].get('iaqGrade')
            if '0001' in parsed_info['sensor_info']:
                particulate_matter_2_5 = parsed_info['sensor_info']['0001']
            else:
                particulate_matter_2_5 = parsed_info['sensor_info'].get('PM25_IDX')
            if '0002' in parsed_info['sensor_info']:
                particulate_matter_10 = parsed_info['sensor_info']['0002']
            else:
                particulate_matter_10 = parsed_info['sensor_info'].get('PM10_IDX')
            carbon_dioxide = parsed_info['sensor_info'].get('CO2_IDX')
            volatile_organic_compounds = parsed_info['sensor_info'].get('VOCs_IDX')
            air_quality_index = parsed_info['sensor_info'].get('IAQ')
            lux_sensor = parsed_info['sensor_info'].get('0007')  # raw value has units of lx. For 250S and 400S.
            smart_mode_sensitivity = parsed_info['status_info'].get('000A')
            device_data[device_attr['device_id']] = CowayPurifier(
                device_attr=device_attr,
                mcu_version=mcu_version,
                network_status=network_status,
                is_on=is_on,
                auto_mode=auto_mode,
                auto_eco_mode=auto_eco_mode,
                eco_mode=eco_mode,
                night_mode=night_mode,
                rapid_mode=rapid_mode,
                fan_speed=fan_speed,
                light_on=light_on,
                light_mode=light_mode,
                button_lock=button_lock,
                timer=timer,
                timer_remaining=timer_remaining,
                pre_filter_pct=pre_filter_pct,
                max2_pct=max2_pct,
                odor_filter_pct=odor_filter,
                aq_grade=aq_grade,
                particulate_matter_2_5=particulate_matter_2_5,
                particulate_matter_10=particulate_matter_10,
                carbon_dioxide=carbon_dioxide,
                volatile_organic_compounds=volatile_organic_compounds,
                air_quality_index=air_quality_index,
                lux_sensor=lux_sensor,
                pre_filter_change_frequency=pre_filter_change_frequency,
                smart_mode_sensitivity=smart_mode_sensitivity
            )
            LOGGER.debug(
                f'Finished constructing CowayPurifier object for {device_attr.get("name")}'
            )
        #  Make sure token is checked again during next poll / when control
        #  commands are sent
        LOGGER.debug(
            f' Setting self.check_token back to True'
        )
        self.check_token = True
        all_purifiers = PurifierData(purifiers=device_data)
        LOGGER.debug(
            f'Constructed final PurifierData object for {self.username}: '
            f'{json.dumps(all_purifiers, default=vars, indent=4)}'
        )
        return all_purifiers

    async def async_server_maintenance_notice(self) -> None:
        """Fetch latest notice regarding Coway server maintenance."""

        if self.check_token:
            await self._check_token()
        url = f'{Endpoint.BASE_URI}{Endpoint.NOTICES}'
        headers = {
            'accept': '*/*',
            'langCd': Header.ACCEPT_LANG,
            'ostype': Header.SOURCE_PATH,
            'appVersion': Parameter.APP_VERSION,
            'region': 'NUS',
            'user-agent': Header.COWAY_USER_AGENT,
            'authorization': f'Bearer {self.access_token}',
        }
        params = {
            'content': '',
            'langCd': Header.ACCEPT_LANG,
            'pageIndex': '1',
            'pageSize': '20',
            'title': '',
            'topPinnedYn': ''
        }
        LOGGER.debug(
            f'Fetching server maintenance notices from Coway server: {url}'
        )
        list_response = await self._get_endpoint(url, headers, params)
        notice_check: int | None = None
        if 'error' in list_response:
            raise CowayError(
                f'Failed to get Coway server maintenance notices: {list_response["error"]}'
            )
        if 'data' in list_response:
            if notices := list_response['data'].get('content'):
                LOGGER.debug(
                    f'Found the following Coway server maintenance notices: '
                    f'{notices}'
                )
                notice_check = notices[0]["noticeSeq"]
                LOGGER.debug(
                    f'Latest notice sequence is {notice_check}'
                )
            else:
                notice_check = None
        if not self.server_maintenance or notice_check != self.server_maintenance.get('sequence'):
            url = f'{Endpoint.BASE_URI}{Endpoint.NOTICES}/{list_response["data"]["content"][0]["noticeSeq"]}'
            LOGGER.debug(
                f'Server maintenance notice info not fetched before. Fetching now. '
                f'URL: {url}'
            )
            headers = {
                'region': 'NUS',
                'accept': 'application/json, text/plain, */*',
                'user-agent': Header.HTML_USER_AGENT,
                'authorization': f'Bearer {self.access_token}',
            }
            params = {
                'langCd': Header.ACCEPT_LANG
            }
            latest_notice = await self._get_endpoint(url, headers, params)
            if 'error' in latest_notice:
                raise CowayError(
                    f'Failed to get Coway server maintenance latest notice: {latest_notice["error"]}'
                )
            LOGGER.debug(
                f'Latest notice response content: {latest_notice}'
            )
            soup = BeautifulSoup(latest_notice['data']['content'], 'html.parser')
            notice_text = soup.find_all('p')
            LOGGER.debug(
                f'Parsed notice text: {notice_text}'
            )
            notice_lines: list[str] = []
            search_result: tuple[int, ...] | None = None
            for content in notice_text:
                if content.text != u'\xa0':
                    notice_lines.append(content.text)
                    if '[edt]' in (lower_text := content.text.lower()):
                        pattern = r'\[edt\].*(\d{4}-\d{2}-\d{2}).*(\d{2}:\d{2}).*(\d{4}-\d{2}-\d{2}).*(\d{2}:\d{2})'
                        search_result = re.search(pattern, lower_text).groups()

            notice_info: str = '\n'.join(notice_lines)
            LOGGER.debug(
                f'Joined notice info lines: {notice_info}'
            )
            if search_result and len(search_result) == 4:
                format_string = '%Y-%m-%d %H:%M'
                start_dt_string = f'{search_result[0]} {search_result[1]}'
                end_dt_string = f'{search_result[2]} {search_result[3]}'
                edt_tz = ZoneInfo('America/New_York')
                start_dt = datetime.strptime(
                    start_dt_string, format_string
                ).replace(tzinfo=edt_tz)
                end_dt = datetime.strptime(
                    end_dt_string, format_string
                ).replace(tzinfo=edt_tz)
                self.server_maintenance = {
                    'sequence': latest_notice['data']['noticeSeq'],
                    'start_date_time': start_dt,
                    'end_date_time': end_dt,
                    'description': notice_info
                }
                LOGGER.debug(
                    f'self.server_maintenance dict set to: {self.server_maintenance}'
                )
            else:
                self.server_maintenance = {
                    'sequence': None,
                    'start_date_time': None,
                    'end_date_time': None,
                    'description': notice_info
                }
                LOGGER.debug(
                    f' self.server_maintenance dict set to: {self.server_maintenance}'
                )
        else:
            LOGGER.debug(
                f'Latest server maintenance info matches already fetched info. '
                f'Skipping fetching it again.'
            )
            return

    async def async_fetch_filter_status(
            self,
            place_id: str,
            serial: str,
            name: str
    ) -> dict[str, Any]:
        """Fetch Pre-filter and MAX2 filter states."""

        if self.check_token:
            await self._check_token()
        url = f'{Endpoint.SECONDARY_BASE}{Endpoint.PLACES}/{place_id}/devices/{serial}/supplies'
        headers = {
            'region': 'NUS',
            'accept': 'application/json, text/plain, */*',
            'authorization': f'Bearer {self.access_token}',
            'accept-language': Header.COWAY_LANGUAGE,
            'user-agent': Header.HTML_USER_AGENT,
        }
        params = {
            'membershipYn': 'N',
            'membershipType': '',
            'langCd': Header.ACCEPT_LANG
        }

        response = await self._get_endpoint(url, headers, params)
        if 'error' in response:
            raise CowayError(f'Failed to get filter status for purifier {name}: {response["error"]}')
        return response.get('data', {}).get('suppliesList', {})

    async def async_fetch_timer(self, serial: str, name: str) -> dict[str, Any]:
        """Get current timer that has been set."""

        if self.check_token:
            await self._check_token()
        url = f'{Endpoint.SECONDARY_BASE}{Endpoint.AIR}/{serial}/timer'
        headers = {
            'region': 'NUS',
            'accept': 'application/json, text/plain, */*',
            'authorization': f'Bearer {self.access_token}',
            'accept-language': Header.COWAY_LANGUAGE,
            'user-agent': Header.HTML_USER_AGENT,
        }

        response = await self._get_endpoint(url, headers, None)
        if 'error' in response:
            raise CowayError(f'Failed to get timer for purifier {name}: {response["error"]}')
        return response.get('data', {})

    """
    **************************************************************************************************************************************************

                                                            Functions for controlling purifiers


    **************************************************************************************************************************************************
    """

    async def async_set_power(self, device_attr: dict[str, str], is_on: bool) -> None:
        """Provide is_on as True for On and False for Off."""

        response = await self.async_control_purifier(device_attr, '0001', '1' if is_on else '0')
        LOGGER.debug(
            f'{device_attr.get("name")} - Power command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute power command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute power command. Response: {response}'
            )

    async def async_set_auto_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Auto Mode."""

        response = await self.async_control_purifier(device_attr, '0002', '1')
        LOGGER.debug(
            f'{device_attr.get("name")} - Auto mode command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute auto mode command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute auto mode command. Response: {response}'
            )

    async def async_set_night_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Night Mode."""

        response = await self.async_control_purifier(device_attr, '0002', '2')
        LOGGER.debug(
            f'{device_attr.get("name")} - Night mode command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute night mode command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute night mode command. Response: {response}'
            )

    async def async_set_eco_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Eco Mode.
        Only applies to AIRMEGA AP-1512HHS models.
        """

        response = await self.async_control_purifier(device_attr, '0002', '6')
        LOGGER.debug(
            f'{device_attr.get("name")} - Eco mode command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute eco mode command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute eco mode command. Response: {response}'
            )

    async def async_set_rapid_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Rapid Mode.
        Only applies to AIRMEGA 250s.
        """

        response = await self.async_control_purifier(device_attr, '0002', '5')
        LOGGER.debug(
            f'{device_attr.get("name")} - Rapid mode command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute rapid mode command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute rapid mode command. Response: {response}'
            )

    async def async_set_fan_speed(self, device_attr: dict[str, str], speed: str) -> None:
        """Speed can be 1, 2, or 3 represented as a string."""

        response = await self.async_control_purifier(device_attr, '0003', speed)
        LOGGER.debug(
            f'{device_attr.get("name")} - Fan speed command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute fan speed command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute fan speed command. Response: {response}'
            )

    async def async_set_light(self, device_attr: dict[str, str], light_on: bool) -> None:
        """Provide light_on as True for On and False for Off.
        NOT used for 250s purifiers.
        """

        response = await self.async_control_purifier(device_attr, '0007', '2' if light_on else '0')
        LOGGER.debug(
            f'{device_attr.get("name")} - Light command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute light command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute light command. Response: {response}'
            )

    async def async_set_light_mode(self, device_attr: dict[str, str], light_mode: LightMode) -> None:
        """Sets light mode for purifiers, like the 250s,
        that support more than just On and Off. See LightMode
        constant for available options.
        """

        response = await self.async_control_purifier(device_attr, '0007', light_mode)
        LOGGER.debug(
            f'{device_attr.get("name")} - Light command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute light mode command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute light mode command. Response: {response}'
            )

    async def async_set_timer(self, device_attr: dict[str, str], time: str) -> None:
        """Time, in minutes, can be 0, 60, 120, 240, or 480 represented as a string. A time of 0 sets the timer to off."""

        response = await self.async_control_purifier(device_attr, '0008', time)
        LOGGER.debug(
            f'{device_attr.get("name")} - Timer command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute set timer command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute set timer command. Response: {response}'
            )

    async def async_set_smart_mode_sensitivity(self, device_attr: dict[str, str], sensitivity: str) -> None:
        """Sensitivity can be 1, 2, or 3. 1 = Sensitive, 2 = Moderate, 3 = Insensitive. """

        response = await self.async_control_purifier(device_attr, '000A', sensitivity)
        LOGGER.debug(
            f'{device_attr.get("name")} - Sensitivity command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute smart mode sensitivity command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute smart mode sensitivity command. Response: {response}'
            )

    async def async_set_button_lock(self, device_attr: dict[str, str], value: str) -> None:
        """Set button lock to ON (1) or OFF (0)."""

        response = await self.async_control_purifier(device_attr, '0024', value=value)
        LOGGER.debug(
            f'{device_attr.get("name")} - Button lock command sent. Response: {response}'
        )
        if isinstance(response, dict):
            if 'header' in response:
                if 'error_code' in response['header']:
                    raise CowayError(
                        f'Failed to execute button lock command. '
                        f'Error code: {response["header"]["error_code"]}, '
                        f'Error message: {response["header"]["error_text"]}'
                    )
        else:
            raise CowayError(
                f'Failed to execute button lock command. Response: {response}'
            )


#####################################################################################################################################################

    async def _get(self, url: str) -> tuple[ClientResponse, str]:
        """Make GET API call to Coway's servers."""

        headers = {
            'user-agent': Header.USER_AGENT,
            'accept': Header.ACCEPT,
            'accept-language': Header.ACCEPT_LANG
        }

        params = {
            'auth_type': 0,
            'response_type': 'code',
            'client_id': Parameter.CLIENT_ID,
            'redirect_uri': Endpoint.REDIRECT_URL,
            'ui_locales': 'en'
        }
        # Clear cookie jar in case login has already occurred once
        # in the current session. If not cleared, Coway will not return
        # the login form for subsequent login attempts.
        self._session.cookie_jar.clear()
        LOGGER.debug(
            f'Sending request to endpoint {url}'
        )
        async with self._session.get(url, headers=headers, params=params, timeout=self.timeout) as resp:
            html_page = await resp.text()
            return resp, html_page

    async def _post(self, url: str, cookies: SimpleCookie, headers: dict[str, Any], data: dict[str, Any]) -> tuple[str | ClientResponse, bool]:
        """Make POST API call to for authentication endpoint."""

        async with self._session.post(url, cookies=cookies, headers=headers, data=data, timeout=self.timeout) as resp:
            if resp.content_type == 'text/html':
                html_page = await resp.text()
                soup = BeautifulSoup(html_page, 'html.parser')
                page_title = soup.find('title').string
                if page_title is not None:
                    if page_title == 'Coway - Password change message':
                        if self.skip_password_change:
                            form_url = soup.find('form', id='kc-password-change-form').get('action')
                            password_skip_init = True
                            return form_url, password_skip_init
                        else:
                            raise PasswordExpired("Coway servers are requesting a password change as the password on this account hasn't been changed for 60 days or more.")
                    else:
                        error_message = soup.find('p', class_="member_error_msg")
                        if error_message and error_message.text == 'Your ID or password is incorrect.':
                            raise AuthError(
                                f'Coway API authentication error: Invalid username/password.'
                            )
                        else:
                            return resp, False
                else:
                    password_skip_init = False
                    return resp, password_skip_init
            else:
                password_skip_init = False
                return resp, password_skip_init

    async def _post_endpoint(self, data: dict[str, str]) -> dict[str, Any]:
        """Used exclusively by _get_token function."""

        url = f'{Endpoint.BASE_URI}{Endpoint.GET_TOKEN}'
        headers = {
            'content-type': Header.CONTENT_JSON,
            'user-agent': Header.COWAY_USER_AGENT,
            'accept-language': Header.COWAY_LANGUAGE,
        }

        async with self._session.post(url, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            return await self._response(resp)

    async def _get_endpoint(
            self,
            endpoint: str,
            headers: dict[str, str],
            params: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Get authorized endpoints."""

        async with self._session.get(endpoint, headers=headers, params=params, timeout=self.timeout) as resp:
            return await self._response(resp)

    async def _create_endpoint_header(self) -> dict[str, str]:
        """Creates common header used by _get_endpoint function."""

        if self.check_token:
            await self._check_token()
        headers = {
            'region': 'NUS',
            'content-type': 'application/json',
            'accept': '*/*',
            'authorization': f'Bearer {self.access_token}',
            'accept-language': Header.COWAY_LANGUAGE,
            'user-agent': Header.COWAY_USER_AGENT,
        }
        return headers

    async def _get_purifier_html(self, nick_name: str, serial: str, model_code: str, place_id: str):
        """Fetches HTML page presented in iOS app when viewing individual purifier."""

        url = f'{Endpoint.PURIFIER_HTML_BASE}/{place_id}/product/{model_code}'
        headers = {
            'theme': Header.THEME,
            'callingpage': Header.CALLING_PAGE,
            'accept': Header.ACCEPT,
            'dvcnick': nick_name,
            'timezoneid': Parameter.TIMEZONE,
            'appversion': Parameter.APP_VERSION,
            'accesstoken': self.access_token,
            'accept-language': Header.COWAY_LANGUAGE,
            'region': 'NUS',
            'user-agent': Header.HTML_USER_AGENT,
            'srcpath': Header.SOURCE_PATH,
            'deviceserial': serial
        }

        params = {
            'bottomSlide': 'false',
            'tab': '0',
            'temperatureUnit': 'F',
            'weightUnit': 'oz',
            'gravityUnit': 'lb'
        }
        LOGGER.debug(
            f'Fetching purifier HTML page at {url}'
        )
        async with self._session.get(url, headers=headers, params=params, timeout=self.timeout) as resp:
            html_page = await resp.text()
            return html_page

    async def async_control_purifier(self, device_attr: dict[str, str], command: str, value: Any) -> dict[str, Any] | str:
        """Main function to execute individual purifier control commands."""

        await self._check_token()
        url = f'{Endpoint.BASE_URI}{Endpoint.PLACES}/{device_attr["place_id"]}/devices/{device_attr["device_id"]}/control-status'
        headers = await self._construct_control_header()
        data = {
            'attributes': {
                command: value
            },
            'isMultiControl': False,
            'refreshFlag': False
        }

        async with self._session.post(url, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            response = await self._control_command_response(resp)
            return response

    async def async_change_prefilter_setting(self, device_attr: dict[str, str], value: int) -> None:
        """ Used to change the pre-filter wash frequency. Value can be 2, 3, or 4."""

        await self._check_token()
        url = f'{Endpoint.BASE_URI}{Endpoint.PLACES}/{device_attr["place_id"]}/devices/{device_attr["device_id"]}/control-param'
        headers = await self._construct_control_header()
        cycle = PREFILTER_CYCLE[value]
        data = {
            'attributes': {
                '0001': cycle
            },
            'deviceSerial': device_attr['device_id'],
            'placeId': str(device_attr['place_id']),
            'refreshFlag': False
        }

        async with self._session.post(url, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            response = await self._control_command_response(resp)
            LOGGER.debug(
                f'{device_attr.get("name")} - Prefilter command sent. Response: {response}'
            )
            if isinstance(response, dict):
                if 'header' in response:
                    if 'error_code' in response['header']:
                        raise CowayError(
                            f'Failed to execute Prefilter command. Error code: {response["header"]["error_code"]}, Error message: {response["header"]["error_text"]}'
                        )
            else:
                raise CowayError(
                    f'Failed to execute Prefilter command. Response: {response}'
                )

    async def _construct_control_header(self) -> dict[str, Any]:
        """Construct header used by control purifier function
        and prefilter control function
        """

        headers = {
            'Content-Type': Header.CONTENT_JSON,
            'Accept': '*/*',
            'accept-language': Header.COWAY_LANGUAGE,
            'User-Agent': Header.COWAY_USER_AGENT,
            'authorization': f'Bearer {self.access_token}',
            'region': 'NUS',
        }
        return headers

    @staticmethod
    async def _response(resp: ClientResponse) -> dict[str, Any]:
        """Return response from API call."""

        response: dict[str, Any] = {}
        if resp.status != 200:
            error = await resp.text()
            try:
                error_json = await resp.json()
            except Exception as resp_error:
                raise CowayError(f'Could not return json: {error}') from resp_error
            if 'error' in error_json:
                response['error'] = error_json
                return response
            if 'message' in error_json:
                if error_json['message'] == ErrorMessages.BAD_TOKEN:
                    raise AuthError(
                        f'Coway Auth error: Coway IoCare authentication failed; {ErrorMessages.BAD_TOKEN}'
                    )
                elif error_json['message'] == ErrorMessages.EXPIRED_TOKEN:
                    LOGGER.debug(
                        f'Current access token has expired. Error: {ErrorMessages.EXPIRED_TOKEN}'
                    )
                    response['error'] = ErrorMessages.EXPIRED_TOKEN
                    return response
                else:
                    response['error'] = error_json
                    return response
            else:
                response['error'] = error_json
                return response

        try:
            response = await resp.json()
        except Exception as resp_error:
            raise CowayError(f'Could not return json {resp_error}') from resp_error
        if 'data' in response:
            if 'maintainInfos' in response['data']:
                raise ServerMaintenance(
                    f'Coway Servers are undergoing maintenance.'
                )
        #  Sometimes an unauthorized message is returned with a 200 status,
        #  and we need to handle it separately.
        if 'error' in response:
            if response['error']['message'] == ErrorMessages.INVALID_REFRESH_TOKEN:
                raise AuthError(
                    f'Coway Auth error: Coway IoCare authentication failed: {ErrorMessages.INVALID_REFRESH_TOKEN}'
                )
            else:
                raise CowayError(f'Coway error message: {response["error"]["message"]}')
        return response

    @staticmethod
    async def _control_command_response(resp: ClientResponse) -> dict[str, Any] | str:
        """Handle response returned for purifier command functions."""

        try:
            response = await resp.json()
        except Exception:
            response = await resp.text()
            return response
        if resp.status != 200:
            response = await resp.text()
        if 'data' in response:
            if 'maintainInfos' in response['data']:
                raise ServerMaintenance(
                    f'Coway Servers are undergoing maintenance.'
                )

        return response
