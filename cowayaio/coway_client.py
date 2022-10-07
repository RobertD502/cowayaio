"""Python API for Coway IoCare Purifiers"""
from __future__ import annotations

from typing import Any
import asyncio
import json
import base64
import logging

from Crypto.Cipher import AES
from Crypto import Random
from aiohttp import ClientResponse, ClientSession
from http.cookies import SimpleCookie

from cowayaio.constants import (Endpoint, Endpoint_JSON, Header, pad, Parameter, TIMEOUT,)
from cowayaio.exceptions import CowayError, AuthError
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
        self._session = session if session else ClientSession()
        self.access_token = None
        self.refresh_token = None
        self.timeout = timeout

    async def login(self) -> None:
        state_id = await self._get_state_id()
        cookies = await self._authenticate(state_id)
        code = await self._get_auth_code(cookies)
        self.access_token, self.refresh_token = await self._get_token(code)

    async def _get_state_id(self) -> str:
        """Get OAuth2 state."""

        response = await self._get(Endpoint.OAUTH_URL)
        if response.status != 200:
            error = response.text()
            raise CowayError(f'Coway API error while fetching OAuth2 state_id: {error}')
        state = response.url.query_string.split('state=',1)[1]
        return state

    async def _authenticate(self, state_id: str) -> SimpleCookie:
        """Get OAuth2 cookie."""

        key = Random.new().read(16)
        iv = Random.new().read(AES.block_size)
        aes = AES.new(key, AES.MODE_CBC, IV=iv)
        i = base64.b64encode(iv).decode('utf-8')
        k = base64.b64encode(key).decode('utf-8')
        enc = aes.encrypt(pad(self.password).encode('utf-8')).hex()

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': Header.USER_AGENT
        }

        data = {
            'username': self.username,
            'password': i + ":" + enc + ":" + k,
            'state': state_id,
            'auto_login': 'Y'
        }

        response = await self._post(Endpoint.SIGNIN_URL, headers, data)
        return response.cookies

    async def _get_auth_code(self, cookies: SimpleCookie) -> str:
        """Get OAuth2 auth code."""

        response = await self._get(Endpoint.OAUTH_URL, cookies)
        try:
            query_string = response.url.query_string
            auth_code = query_string[query_string.index('code=')+len('code='):query_string.index('&')]
            return auth_code
        except ValueError as verr:
            raise AuthError(f'Coway API authentication error: unable to retrieve auth code. Likely due to invalid username/password.') from verr

    async def _get_token(self, code: str) -> tuple[str, str]:
        """Get access token and refresh token."""

        params = {
            'authCode': code,
            'isMobile': 'M',
            'langCd': 'en',
            'osType': 1,
            'redirectUrl': Endpoint.REDIRECT_URL,
            'serviceCode': Parameter.SERVICE_CODE
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
        for purifier in data['body']['deviceInfos']:
            purifiers.append(purifier)

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
            mcu_version = state[0].get('curMcuVer')
            network_status = state[1][1]
            is_on = state[1][0].get('0001') == '1'
            auto_mode = state[1][0].get('0002') == '1'
            auto_eco_mode = state[1][0].get('0002') == '6'
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

            device_data[device_attr['device_id']] = CowayPurifier(
                device_attr=device_attr,
                mcu_version=mcu_version,
                network_status=network_status,
                is_on=is_on,
                auto_mode=auto_mode,
                auto_eco_mode=auto_eco_mode,
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
            'User-Agent': Header.USER_AGENT
        }

        params = {
            'auth_type': 0,
            'response_type': 'code',
            'client_id': Parameter.CLIENT_ID,
            'scope': 'login',
            'lang': 'en_US',
            'redirect_url': Endpoint.REDIRECT_URL
        }

        async with self._session.get(url, cookies=cookies, headers=headers, params=params, timeout=self.timeout) as resp:
            return resp

    async def _post(self, url: str, headers: dict[str, Any], data: dict[str, Any]) -> ClientResponse:
        """Make POST API call to for authentication endpoint."""

        async with self._session.post(url, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            return resp

    async def _post_endpoint(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Make POST API call to various endpoints."""

        url = Endpoint.BASE_URI + '/' + endpoint + '.json'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': Header.USER_AGENT
        }
        message = {
            'header': {
                'trcode': endpoint,
                'accessToken': self.access_token,
                'refreshToken': self.refresh_token
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
