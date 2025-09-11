"""Python API for Coway IoCare Purifiers"""
from __future__ import annotations

from typing import Any
import asyncio
from datetime import datetime, timedelta
import json
import logging

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
from cowayaio.exceptions import AuthError, CowayError, PasswordExpired
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
        self.check_token = True
        self.timeout: int = timeout

    async def login(self) -> None:
        login_url, cookies = await self._get_login_cookies()
        auth_code = await self._get_auth_code(login_url, cookies)
        self.access_token, self.refresh_token = await self._get_token(auth_code)
        # Token expires in 1 hour
        self.token_expiration = datetime.now() + timedelta(seconds=3600)
        self.country_code = await self._get_country_code()
        self.places = await self._get_places()

    async def _get_login_cookies(self) -> tuple[str, SimpleCookie]:
        """Get openid-connect login url and associated cookies."""

        response, html_page = await self._get(Endpoint.OAUTH_URL)
        if (status := response.status) != 200:
            error = response.reason
            raise CowayError(f'Coway API error while fetching login page. Status: {status}, Reason: {error}')
        cookies = response.cookies
        soup = BeautifulSoup(html_page, 'html.parser')
        try:
            login_url = soup.find('form', id='kc-form-login').get('action')
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

        response, password_skip_init = await self._post(login_url, cookies, headers, data)
        if password_skip_init:
            response, password_skip_init = await self._post(response, cookies, headers, password_skip_data)
        if not response.history:
            raise AuthError(f'Coway API authentication error: unable to retrieve auth code. Likely due to invalid username/password.')
        else:
            code = response.url.query_string.partition('code=')[-1]
            return code

    async def _get_token(self, auth_code: str) -> tuple[str, str]:
        """Get access token and refresh token."""

        data = {
            'authCode': auth_code,
            'redirectUrl': Endpoint.REDIRECT_URL,
        }

        response = await self._post_endpoint(data)
        return response['data']['accessToken'], response['data']['refreshToken']

    async def _check_token(self) -> None:
        """Checks to see if token has expired and needs to be refreshed."""

        if self.check_token:
            current_dt = datetime.now()
            if any(token_var is None for token_var in [self.access_token, self.refresh_token, self.token_expiration]):
                await self.login()
            # Refresh access token if it expires within 5 minutes
            elif (self.token_expiration-current_dt).total_seconds() < 300:
                LOGGER.debug('Refreshing access and refresh tokens')
                await self._refresh_token()
            else:
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
        async with self._session.post(url, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            response = await self._response(resp)
            self.access_token = response['data']['accessToken']
            self.refresh_token = response['data']['refreshToken']
            self.token_expiration = datetime.now() + timedelta(seconds=3600)

    async def _get_country_code(self) -> str:
        """Obtain country code associated with the account."""

        endpoint = f'{Endpoint.BASE_URI}{Endpoint.USER_INFO}'
        headers = await self._create_endpoint_header()
        response = await self._get_endpoint(endpoint=endpoint, headers=headers, params=None)
        if 'error' in response:
            raise CowayError(f'Failed to get country code associated with account. {response["error"]}')
        return response['data']['memberInfo']['countryCode']

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
        response = await self._get_endpoint(endpoint=endpoint, headers=headers, params=params)
        if 'error' in response:
            raise CowayError(f'Failed to get places associated with account. {response["error"]}')
        return response['data']['content']

    async def async_get_purifiers(self) -> list[dict[str, Any]]:
        """Gets all purifiers linked to Coway account."""

        params = {
            'pageIndex': '0',
            'pageSize': '100'
        }
        purifiers: list[dict[str, Any]] = []
        for place in self.places:
            if place['deviceCnt'] != 0:
                url = f'{Endpoint.BASE_URI}{Endpoint.PLACES}/{place["placeId"]}/devices'
                headers = await self._create_endpoint_header()
                try:
                    response = await self._get_endpoint(url, headers, params)
                except AuthError:
                    LOGGER.debug('Coway IoCare access and refresh tokens are invalid. Attempting to fetch new tokens.')
                    await self.login()
                    headers = await self._create_endpoint_header()
                    response = await self._get_endpoint(url, headers, params)
                if 'error' in response:
                    raise CowayError(f'Failed to get Coway devices. {response["error"]}')
                for device in response['data']['content']:
                    if device['categoryName'] == CATEGORY_NAME:
                        purifiers.append(device)
        return purifiers

    async def async_get_purifiers_data(self) -> PurifierData:
        """Return dataclass with Purifier Devices."""

        if not self.places:
            await self.login()
        purifiers = await self.async_get_purifiers()
        #  Prevent checking access token for every purifier iteration after it has
        #  already been checked once.
        self.check_token = False
        device_data: dict[str, CowayPurifier] = {}
        for dev in purifiers:
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
                purifier_info: dict[str, Any] = {}
                for data in purifier_json['children']:
                    if isinstance(data, dict):
                        purifier_info = data
            except (AttributeError, Exception) as purifier_error:
                raise CowayError(f'Coway Error - Failed to parse purifier HTML page for info: {purifier_error}')

            parsed_info = {
                'device_info': None,
                'mcu_info': None,
                'network_info': None,
                'sensor_info': None,
                'status_info': None,
                'aq_grade': None,
                'filter_info': None,
                'timer_info': None,
            }
            LOGGER.debug(
                f'Purifier {dev["dvcNick"]} Fetched: {json.dumps(purifier_info, indent=4)}'
            )
            for data in purifier_info['coreData']:
                if 'currentMcuVer' in data['data']:
                    parsed_info['mcu_info'] = data['data']
                if 'sensorInfo' in data['data']:
                    parsed_info['sensor_info'] = data['data']['sensorInfo']['attributes']
            if 'deviceStatusData' in purifier_info:
                parsed_info['status_info'] = purifier_info['deviceStatusData']['data']['statusInfo']['attributes']
            if 'baseInfoForModelCodeData' in purifier_info:
                parsed_info['device_info'] = purifier_info['baseInfoForModelCodeData']['deviceInfo']
            if 'deviceModule' in purifier_info:
                parsed_info['network_info'] = purifier_info['deviceModule']['data']['content']['deviceModuleDetailInfo']
                parsed_info['aq_grade'] = purifier_info['deviceModule']['data']['content']['deviceModuleDetailInfo']['airStatusInfo']

            filter_info = await self.async_fetch_filter_status(
                dev['placeId'],
                dev['deviceSerial'],
                dev['dvcNick']
            )

            filter_dict: dict[str, Any] = {}
            for dev_filter in filter_info:
                if dev_filter['supplyNm'] == 'Pre-Filter':
                    filter_dict['pre-filter'] = dev_filter
                else:
                    filter_dict['max2'] = dev_filter
            parsed_info['filter_info'] = filter_dict

            timer = await self.async_fetch_timer(dev['deviceSerial'], dev['dvcNick'])
            parsed_info['timer_info'] = timer['offTimer']

            device_attr = {
                'device_id': dev['deviceSerial'],
                'model': parsed_info['device_info']['productName'],
                'model_code': dev['productModel'],
                'name': dev['dvcNick'],
                'product_name': parsed_info['device_info']['prodName'],
                'place_id': dev['placeId'],
            }
            network_status = parsed_info['network_info']['wifiConnected']
            if not network_status:
                LOGGER.debug(f'{device_attr["name"]} Purifier is not connected to WiFi.')

            mcu_version = parsed_info['mcu_info']['currentMcuVer']
            is_on = parsed_info['status_info']['0001'] == 1
            auto_mode = parsed_info['status_info']['0002'] == 1
            auto_eco_mode = parsed_info['status_info']['0002'] == 6
            eco_mode = parsed_info['status_info']['0002'] == 6
            night_mode = parsed_info['status_info']['0002'] == 2
            rapid_mode = parsed_info['status_info']['0002'] == 5
            fan_speed = parsed_info['status_info']['0003']
            light_on = parsed_info['status_info']['0007'] == 2
            # 250s purifier has more than just on and off
            light_mode = parsed_info['status_info']['0007']
            timer = parsed_info['timer_info']
            timer_remaining = parsed_info['status_info']['0008']
            pre_filter_pct = parsed_info['filter_info']['pre-filter']['filterRemain']
            max2_pct = parsed_info['filter_info']['max2']['filterRemain']
            aq_grade = parsed_info['aq_grade']['iaqGrade']
            if '0001' in parsed_info['sensor_info']:
                particulate_matter_2_5 = parsed_info['sensor_info']['0001']
            else:
                particulate_matter_2_5 = parsed_info['sensor_info'].get('PM25_IDX', None)
            if '0002' in parsed_info['sensor_info']:
                particulate_matter_10 = parsed_info['sensor_info']['0002']
            else:
                particulate_matter_10 = parsed_info['sensor_info'].get('PM10_IDX', None)
            carbon_dioxide = parsed_info['sensor_info'].get('CO2_IDX', None)
            volatile_organic_compounds = parsed_info['sensor_info'].get('VOCs_IDX', None)
            air_quality_index = parsed_info['sensor_info'].get('IAQ', None)
            lux_sensor = parsed_info['sensor_info'].get('0007', None)  # raw value has units of lx. Likely only on 400S
            pre_filter_change_frequency = parsed_info['filter_info']['pre-filter']['replaceCycle']
            smart_mode_sensitivity = parsed_info['status_info']['000A']
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
                timer=timer,
                timer_remaining=timer_remaining,
                pre_filter_pct=pre_filter_pct,
                max2_pct=max2_pct,
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
        #  Make sure token is checked again during next poll / when control
        #  commands are sent
        self.check_token = True
        return PurifierData(purifiers=device_data)

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
        return response['data']['suppliesList']

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
        return response['data']

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
                if (page_title is not None) and (page_title == 'Coway - Password change message'):
                    if self.skip_password_change:
                        form_url = soup.find('form', id='kc-password-change-form').get('action')
                        password_skip_init = True
                        return form_url, password_skip_init
                    else:
                        raise PasswordExpired("Coway servers are requesting a password change as the password on this account hasn't been changed for 60 days or more.")
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
            params: dict[str, Any] | None
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
        return response
