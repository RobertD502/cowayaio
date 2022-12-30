"""Python API for Coway IoCare Purifiers"""
from __future__ import annotations

from typing import Any
import asyncio
import json
import logging

from bs4 import BeautifulSoup
from aiohttp import ClientResponse, ClientSession
from http.cookies import SimpleCookie

from cowayaio.constants import (Endpoint, Endpoint_JSON, Header, Parameter, TIMEOUT,)
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

        self.username = username
        self.password = password
        self.skip_password_change = False
        self._session = session if session else ClientSession()
        self.access_token = None
        self.refresh_token = None
        self.timeout = timeout

    async def login(self) -> None:
        login_url, cookies = await self._get_login_cookies()
        auth_code = await self._get_auth_code(login_url, cookies)
        self.access_token, self.refresh_token = await self._get_token(auth_code)

    async def _get_login_cookies(self) -> tuple[str, SimpleCookie]:
        """Get openid-connect login url and associated cookies."""

        response, html_page = await self._get(Endpoint.OAUTH_URL)
        if response.status != 200:
            error = response.text()
            raise CowayError(f'Coway API error while fetching login page: {error}')
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

        params = {
            'authCode': auth_code,
            'isMobile': 'M',
            'langCd': 'en',
            'osType': 1,
            'redirectUrl': Endpoint.REDIRECT_URL,
            'serviceCode': Parameter.SERVICE_CODE,
        }

        response = await self._post_endpoint(Endpoint_JSON.TOKEN_REFRESH, params)
        return response['header']['accessToken'], response['header']['refreshToken']

    async def async_get_purifiers(self) -> dict[str, Any]:
        """Gets all purifiers linked to Coway account."""

        if self.access_token is None:
            await self.login()

        params = {
            'pageIndex': '0',
            'pageSize': '100'
        }

        try:
            response = await self._post_endpoint(Endpoint_JSON.DEVICE_LIST, params)
        except AuthError:
            LOGGER.warning('Coway IoCare access and refresh tokens are invalid. Attempting to fetch new tokens.')
            await self.login()
            response = await self._post_endpoint(Endpoint_JSON.DEVICE_LIST, params)
        return response

    async def async_get_purifiers_data(self) -> PurifierData:
        """Return dataclass with Purifier Devices."""

        purifiers = []
        data = await self.async_get_purifiers()
        try:
            for purifier in data['body']['deviceInfos']:
                purifiers.append(purifier)
        except KeyError:
            raise CowayError(f'Coway API error: Coway server failed to return purifier data.')

        device_data: dict[str, CowayPurifier] = {}
        dev: dict
        for dev in purifiers:
            device_attr = {
                'device_id': dev.get('barcode'),
                'model': dev.get('dvcModel'),
                'name': dev.get('dvcNick'),
                'product_name': dev.get('prodName'),
                'product_name_full': dev.get('prodNameFull'),
                'device_type': dev.get('dvcTypeCd'),
                'device_brand': dev.get('dvcBrandCd'),
            }
            state = await self.async_fetch_all_endpoints(device_attr)
            network_status = state[1][1]
            try:
                mcu_version = state[0].get('curMcuVer')
                is_on = state[1][0].get('0001') == '1'
                auto_mode = state[1][0].get('0002') == '1'
                auto_eco_mode = state[1][0].get('0002') == '6'
                eco_mode = state[1][0].get('0002') == '6'
                night_mode = state[1][0].get('0002') == '2'
                fan_speed = state[1][0].get('0003')
                light_on = state[1][0].get('0007') == '2'
                timer = state[1][0].get('offTimerData')
                timer_remaining = state[1][0].get('0008')
                pre_filter_name = state[2][0][0].get('filterName')
                pre_filter_pct = state[2][0][0].get('filterPer')
                pre_filter_last_changed = state[2][0][0].get('lastChangeDate')
                pre_filter_change_months = state[2][0][0].get('changeCycle')
                max2_name = state[2][0][1].get('filterName')
                max2_pct = state[2][0][1].get('filterPer')
                max2_last_changed = state[2][0][1].get('lastChangeDate')
                max2_change_months = state[2][0][1].get('changeCycle')
                dust_pollution = state[2][1][0].get('dustPollution')
                air_volume = state[2][1][0].get('airVolume')
                pollen_mode = state[2][1][0].get('pollenMode')
                particulate_matter_2_5 = state[2][2][0].get('dustpm25')
                particulate_matter_10 = state[2][2][0].get('dustpm10')
                carbon_dioxide = state[2][2][0].get('co2')
                volatile_organic_compounds = state[2][2][0].get('vocs')
                air_quality_index = state[2][2][0].get('inairquality')
            except IndexError:
                if not network_status:
                    LOGGER.warning(f'Purifier {device_attr["name"]} is not connected to WiFi.')
                    continue
                else:
                    raise

            device_data[device_attr['device_id']] = CowayPurifier(
                device_attr=device_attr,
                mcu_version=mcu_version,
                network_status=network_status,
                is_on=is_on,
                auto_mode=auto_mode,
                auto_eco_mode=auto_eco_mode,
                eco_mode=eco_mode,
                night_mode=night_mode,
                fan_speed=fan_speed,
                light_on=light_on,
                timer=timer,
                timer_remaining=timer_remaining,
                pre_filter_name=pre_filter_name,
                pre_filter_pct=pre_filter_pct,
                pre_filter_last_changed=pre_filter_last_changed,
                pre_filter_change_months=pre_filter_change_months,
                max2_name=max2_name,
                max2_pct=max2_pct,
                max2_last_changed=max2_last_changed,
                max2_change_months=max2_change_months,
                dust_pollution=dust_pollution,
                air_volume=air_volume,
                pollen_mode=pollen_mode,
                particulate_matter_2_5=particulate_matter_2_5,
                particulate_matter_10=particulate_matter_10,
                carbon_dioxide=carbon_dioxide,
                volatile_organic_compounds=volatile_organic_compounds,
                air_quality_index=air_quality_index,
            )

        return PurifierData(purifiers=device_data)


    async def async_fetch_all_endpoints(self, device_attr) -> tuple:
        """Parallel request are made to all endpoints for each purifier.

        Returns a list containing mcu_version, control status, filters, and air quality sensors
        """

        results = await asyncio.gather(*[self.async_get_mcu_version(device_attr), self.async_get_control_status(device_attr), self.async_get_quality_status(device_attr)],)
        return results

    async def async_get_mcu_version(self, device_attr: dict[str, Any]) -> dict[str, Any]:
        """Return MCU version for a single purifier."""

        params = {
            'deviceId': device_attr['device_id'],
        }

        response = await self._post_endpoint(Endpoint_JSON.MCU_VERSION, params)
        return response['body']

    async def async_get_control_status(self, device_attr: dict[str, Any]) -> tuple[dict, bool]:
        """Returns power state, mode, speed, etc. for a single purifier."""

        params = {
            'barcode': device_attr['device_id'],
            'dvcBrandCd': device_attr['device_brand'],
            'prodName': device_attr['product_name'],
            'stationCd': '',
            'resetDttm': '',
            'dvcTypeCd': device_attr['device_type'],
            'refreshFlag': 'true'
        }

        response = await self._post_endpoint(Endpoint_JSON.STATUS, params)
        return response['body']['controlStatus'], response['body']['netStatus']

    async def async_get_quality_status(self, device_attr: dict[str, Any]) -> tuple[list, list, list]:
        """Returns data for prefilter, max2 filter, and air quality sensors."""

        params = {
            'barcode': device_attr['device_id'],
            'dvcBrandCd': device_attr['device_brand'],
            'prodName': device_attr['product_name'],
            'stationCd': '',
            'resetDttm': '',
            'dvcTypeCd': device_attr['device_type'],
            'refreshFlag': 'true'
        }

        response = await self._post_endpoint(Endpoint_JSON.FILTERS, params)
        return response['body']['filterList'], response['body']['prodStatus'], response['body']['IAQ']


    """
    **************************************************************************************************************************************************

                                                            Functions for controlling purifiers


    **************************************************************************************************************************************************
    """

    async def async_set_power(self, device_attr: dict[str, str], is_on: bool) -> None:
        """Provide is_on as True for On and False for Off."""

        await self.async_control_purifier(device_attr, '0001', '1' if is_on else '0')

    async def async_set_auto_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Auto Mode."""

        await self.async_control_purifier(device_attr, '0002', '1')

    async def async_set_night_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Night Mode."""

        await self.async_control_purifier(device_attr, '0002', '2')

    async def async_set_eco_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Eco Mode.
        Only applies to AIRMEGA AP-1512HHS models.
        """

        await self.async_control_purifier(device_attr, '0002', '6')        

    async def async_set_fan_speed(self, device_attr: dict[str, str], speed: str) -> None:
        """Speed can be 1, 2, or 3 represented as a string."""

        await self.async_control_purifier(device_attr, '0003', speed)

    async def async_set_light(self, device_attr: dict[str, str], light_on: bool) -> None:
        """Provide light_on as True for On and False for Off."""

        await self.async_control_purifier(device_attr, '0007', '2' if light_on else '0')

    async def async_set_timer(self, device_attr: dict[str, str], time: str) -> None:
        """Time, in minutes, can be 0, 60, 120, 240, or 480 represented as a string. A time of 0 sets the timer to off."""

        await self.async_control_purifier(device_attr, '0008', time)


#####################################################################################################################################################


    async def _get(self, url: str, cookies: SimpleCookie | None = None) -> ClientResponse:
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
            'ui_locales': 'en-US',
            'dvc_cntry_id': 'US',
            'redirect_uri': Endpoint.REDIRECT_URL
        }

        async with self._session.get(url, cookies=cookies, headers=headers, params=params, timeout=self.timeout) as resp:
            html_page = await resp.text()
            return resp, html_page

    async def _post(self, url: str, cookies: SimpleCookie, headers: dict[str, Any], data: dict[str, Any]) -> ClientResponse:
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

    async def _post_endpoint(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Make POST API call to various endpoints."""


        url = Endpoint.BASE_URI + '/' + endpoint + '.json'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1'
        }

        message = {
            'header': {
                "result": False,
                "error_code": "",
                "error_text": "",
                "info_text": "",
                "message_version": "",
                "login_session_id": "",
                'trcode': endpoint,
                'accessToken': self.access_token if self.access_token else "",
                'refreshToken': self.refresh_token if self.refresh_token else ""
            },
            'body': params
        }
        data = {
            'message': json.dumps(message)
        }

        async with self._session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
            return await self._response(resp)


    async def async_control_purifier(self, device_attr: dict[str, str], command: str, value: Any) -> ClientResponse:
        url = Endpoint.BASE_URI + '/' + Endpoint_JSON.CONTROL + '.json'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': Header.USER_AGENT
        }
        params = {
            'barcode': device_attr.get('device_id'),
            'dvcBrandCd': device_attr.get('device_brand'),
            'prodName': device_attr.get('product_name'),
            'dvcTypeCd': device_attr.get('device_type'),
            'funcList': [{
              'comdVal': value,
              'funcId': command
            }],
            'mqttDevice': True
        }
        message = {
            'header': {
                'trcode': Endpoint_JSON.CONTROL,
                'accessToken': self.access_token,
                'refreshToken': self.refresh_token
            },
            'body': params
        }
        data = {
            'message': json.dumps(message)
        }

        async with self._session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
            return resp

    @staticmethod
    async def _response(resp: ClientResponse) -> dict[str, Any]:
        """Return response from API call."""

        if resp.status != 200:
            error = await resp.text()
            raise CowayError(f'Coway API error: {error}')
        try:
            response: dict[str, Any] = await resp.json()
        except Exception as error:
            raise CowayError(f'Could not return json {error}') from error
        if (header := response['header']['error_code'])  == 'CWIG0304COWAYLgnE':
            raise AuthError(f'Error code {header}: Coway IoCare access and refresh tokens are invalid. Attempting to fetch new tokens.')
        return response
