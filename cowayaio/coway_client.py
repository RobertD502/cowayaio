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

from cowayaio.constants import (Endpoint, EndpointJSON, ErrorMessages, Header, LightMode, Parameter, TIMEOUT,)
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
        self.timeout: int = timeout

    async def login(self) -> None:
        login_url, cookies = await self._get_login_cookies()
        auth_code = await self._get_auth_code(login_url, cookies)
        self.access_token, self.refresh_token = await self._get_token(auth_code)
        # Token expires in 1 hour
        self.token_expiration = datetime.now() + timedelta(seconds=3600)

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

        response = await self._post_endpoint(EndpointJSON.GET_TOKEN, params)
        return response['header']['accessToken'], response['header']['refreshToken']

    async def _check_token(self) -> None:
        """Checks to see if token has expired and needs to be refreshed."""

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
            'profile': 'prod',
            'accept': '*/*',
            'authorization': f'Bearer {self.access_token}',
            'accept-language': Header.ACCEPT_LANG,
            'user-agent': Header.USER_AGENT,
            'trcode': EndpointJSON.TOKEN_REFRESH,
        }
        data = {
            'refreshToken': self.refresh_token,
        }

        async with self._session.post(Endpoint.TOKEN_REFRESH, headers=headers, data=json.dumps(data), timeout=self.timeout) as resp:
            response = await self._response(resp, new_api=True)
            self.access_token = response['data']['accessToken']
            self.refresh_token = response['data']['refreshToken']

    async def async_get_purifiers(self) -> dict[str, Any]:
        """Gets all purifiers linked to Coway account."""

        params = {
            'pageIndex': '0',
            'pageSize': '100'
        }

        try:
            response = await self._get_endpoint(EndpointJSON.DEVICE_LIST, params)
        except AuthError:
            LOGGER.debug('Coway IoCare access and refresh tokens are invalid. Attempting to fetch new tokens.')
            await self.login()
            response = await self._get_endpoint(EndpointJSON.DEVICE_LIST, params)
        if 'error' in response:
            raise CowayError(f'Failed to get Coway devices. {response["error"]}')
        return response

    async def async_get_purifiers_data(self) -> PurifierData:
        """Return dataclass with Purifier Devices."""

        purifiers = []
        data = await self.async_get_purifiers()
        try:
            for purifier in data['data']['deviceInfos']:
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
                'device_seq': dev.get('dvcSeq'),
                'order_number': dev.get('ordNo'),
            }
            state = await self.async_fetch_all_endpoints(device_attr)
            network_status = state[1][1]
            if not network_status:
                LOGGER.debug(f'{device_attr["name"]} is not connected to WiFi.')
            try:
                mcu_version = state[0].get('curMcuVer')
                is_on = state[1][0].get('0001') == '1'
                auto_mode = state[1][0].get('0002') == '1'
                auto_eco_mode = state[1][0].get('0002') == '6'
                eco_mode = state[1][0].get('0002') == '6'
                night_mode = state[1][0].get('0002') == '2'
                rapid_mode = state[1][0].get('0002') == '5'
                fan_speed = state[1][0].get('0003')
                light_on = state[1][0].get('0007') == '2'
                # 250s purifier has more than just on and off
                light_mode = state[1][0].get('0007')
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
                dust_pollution = state[2][1].get('dustPollution')
                air_volume = state[2][1].get('airVolume')
                pollen_mode = state[2][1].get('pollenMode')
                particulate_matter_2_5 = state[2][2].get('dustpm25')
                particulate_matter_10 = state[2][2].get('dustpm10')
                carbon_dioxide = state[2][2].get('co2')
                volatile_organic_compounds = state[2][2].get('vocs')
                air_quality_index = state[2][2].get('inairquality')
                pre_filter_change_frequency = state[3][1]
                smart_mode_sensitivity = state[3][2]
            except IndexError:
                # An index error exception may not be encountered with
                # the new API when network_status is False. Logic could possibly
                # be removed in the future.
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
                rapid_mode=rapid_mode,
                fan_speed=fan_speed,
                light_on=light_on,
                light_mode=light_mode,
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
                pre_filter_change_frequency=pre_filter_change_frequency,
                smart_mode_sensitivity=smart_mode_sensitivity
            )

        return PurifierData(purifiers=device_data)


    async def async_fetch_all_endpoints(self, device_attr) -> tuple:
        """Parallel request are made to all endpoints for each purifier.

        Returns a tuple containing mcu_version, control status, filters, and air quality sensors
        """

        results = await asyncio.gather(*[self.async_get_mcu_version(device_attr), self.async_get_control_status(device_attr), self.async_get_quality_status(device_attr), self.async_get_prod_settings(device_attr)],)
        return results

    async def async_get_mcu_version(self, device_attr: dict[str, Any]) -> dict[str, Any]:
        """Return MCU version for a single purifier."""

        params = {
            'devId': device_attr['device_id'],
        }

        response = await self._get_endpoint(EndpointJSON.MCU_VERSION, params)
        if 'error' in response:
            raise CowayError(f'Coway server failed to return purifier MCU version. {response["error"]}')
        if not response['data']:
            raise CowayError('Coway server failed to return purifier MCU version.')

        try:
            mcu_version = response['data']
        except KeyError as key_err:
            raise CowayError(f'Coway API error: Coway server failed to return purifier MCU version.') from key_err
        return mcu_version

    async def async_get_control_status(self, device_attr: dict[str, Any]) -> tuple[dict, bool]:
        """Returns power state, mode, speed, etc. for a single purifier."""

        params = {
            'devId': device_attr['device_id'],
            'mqttDevice': 'true',
            'dvcBrandCd': device_attr['device_brand'],
            'dvcTypeCd': device_attr['device_type'],
            'prodName': device_attr['product_name'],
        }

        response = await self._get_endpoint(EndpointJSON.STATUS, params)
        if 'error' in response:
            raise CowayError(f'Coway API error: Coway server failed to return purifier control status. {response["error"]}')
        if not response['data']:
            raise CowayError('Coway server failed to return purifier control status.')
        try:
            control_status = response['data']['controlStatus']
            net_status = response['data']['netStatus']
        except KeyError as key_err:
            raise CowayError(f'Coway API error: Coway server failed to return purifier control status.') from key_err
        return control_status, net_status

    async def async_get_quality_status(self, device_attr: dict[str, Any]) -> tuple[list, list, list]:
        """Returns data for prefilter, max2 filter, and air quality sensors."""

        params = {
            'barcode': device_attr['device_id'],
            'dvcBrandCd': device_attr['device_brand'],
            'prodName': device_attr['product_name'],
            'deviceType': device_attr['device_type'],
            'mqttDevice': 'true',
            'orderNo': device_attr['order_number'],
            'membershipYn': 'N',
        }

        response = await self._get_endpoint(EndpointJSON.FILTERS, params)
        if 'error' in response:
            raise CowayError(f'Coway API error: Coway server failed to return purifier quality status. {response["error"]}')
        if not response['data']:
            raise CowayError('Coway server failed to return purifier quality status.')
        try:
            filter_list = response['data']['filterList']
            prod_status = response['data']['prodStatus']
            iaq = response['data']['IAQ']
        except KeyError as key_err:
            raise CowayError(f'Coway API error: Coway server failed to return purifier quality status.') from key_err
        return filter_list, prod_status, iaq

    async def async_get_prod_settings(self, device_attr: dict[str, Any]) -> tuple[list, list, list]:
        """Returns purifier settings such as pre-filter frequency and smart mode sensitivity."""

        params = {
            'dvcSeq': device_attr['device_seq']
        }

        response = await self._get_endpoint(EndpointJSON.PROD_SETTINGS, params)
        if 'error' in response:
            raise CowayError(f'Coway API error: Coway server failed to return purifier settings. {response["error"]}')
        if not response['data']:
            raise CowayError('Coway server failed to return purifier settings.')
        try:
            device_infos = response['data']['deviceInfos']
            pre_filter_frequency = response['data']['frequency']
            smart_mode_sensitivity = response['data']['sensitivity']
        except KeyError as key_err:
            raise CowayError(f'Coway API error: Coway server failed to return purifier settings.') from key_err
        return device_infos, pre_filter_frequency, smart_mode_sensitivity

    
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

    async def async_set_auto_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Auto Mode."""

        response = await self.async_control_purifier(device_attr, '0002', '1')
        LOGGER.debug(
            f'{device_attr.get("name")} - Auto mode command sent. Response: {response}'
        )

    async def async_set_night_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Night Mode."""

        response = await self.async_control_purifier(device_attr, '0002', '2')
        LOGGER.debug(
            f'{device_attr.get("name")} - Night mode command sent. Response: {response}'
        )

    async def async_set_eco_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Eco Mode.
        Only applies to AIRMEGA AP-1512HHS models.
        """

        response = await self.async_control_purifier(device_attr, '0002', '6')
        LOGGER.debug(
            f'{device_attr.get("name")} - Eco mode command sent. Response: {response}'
        )

    async def async_set_rapid_mode(self, device_attr: dict[str, str]) -> None:
        """Set Purifier to Rapid Mode.
        Only applies to AIRMEGA 250s.
        """

        response = await self.async_control_purifier(device_attr, '0002', '5')
        LOGGER.debug(
            f'{device_attr.get("name")} - Rapid mode command sent. Response: {response}'
        )

    async def async_set_fan_speed(self, device_attr: dict[str, str], speed: str) -> None:
        """Speed can be 1, 2, or 3 represented as a string."""

        response = await self.async_control_purifier(device_attr, '0003', speed)
        LOGGER.debug(
            f'{device_attr.get("name")} - Fan speed command sent. Response: {response}'
        )

    async def async_set_light(self, device_attr: dict[str, str], light_on: bool) -> None:
        """Provide light_on as True for On and False for Off.
        NOT used for 250s purifiers.
        """

        response = await self.async_control_purifier(device_attr, '0007', '2' if light_on else '0')
        LOGGER.debug(
            f'{device_attr.get("name")} - Light command sent. Response: {response}'
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

    async def async_set_timer(self, device_attr: dict[str, str], time: str) -> None:
        """Time, in minutes, can be 0, 60, 120, 240, or 480 represented as a string. A time of 0 sets the timer to off."""

        response = await self.async_control_purifier(device_attr, '0008', time)
        LOGGER.debug(
            f'{device_attr.get("name")} - Timer command sent. Response: {response}'
        )

    async def async_set_smart_mode_sensitivity(self, device_attr: dict[str, str], sensitivity: str) -> None:
        """Sensitivity can be 1, 2, or 3. 1 = Sensitive, 2 = Normal, 3 = Insensitive. """

        response = await self.async_control_purifier(device_attr, '000A', sensitivity)
        LOGGER.debug(
            f'{device_attr.get("name")} - Sensitivity command sent. Response: {response}'
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
            'ui_locales': 'en-US',
            'dvc_cntry_id': 'US',
            'redirect_uri': Endpoint.REDIRECT_URL
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

    async def _post_endpoint(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Used exclusively by _get_token function."""

        url = f'{Endpoint.BASE_URI}/{endpoint}.json'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': Header.USER_AGENT,
        }

        message = {
            'header': {
                'result': False,
                'error_code': '',
                'error_text': '',
                'info_text': '',
                'message_version': '',
                'login_session_id': '',
                'trcode': endpoint,
                'accessToken': '',
                'refreshToken': '',
            },
            'body': params
        }
        data = {
            'message': json.dumps(message)
        }

        async with self._session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
            return await self._response(resp)

    async def _get_endpoint(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Temp usage of new Coway API."""

        await self._check_token()
        headers = {
            'content-type': 'application/json',
            'profile': 'prod',
            'accept': '*/*',
            'authorization': f'Bearer {self.access_token}',
            'accept-language': Header.ACCEPT_LANG,
            'user-agent': Header.USER_AGENT,
            'trcode': endpoint,
        }
        url: str = ''
        if endpoint == EndpointJSON.DEVICE_LIST:
            url = f'{Endpoint.NEW_BASE_URI}{Endpoint.DEVICE_LIST}'
        if endpoint == EndpointJSON.FILTERS:
            url = f'{Endpoint.NEW_BASE_URI}{Endpoint.FILTERS}{params["barcode"]}{Endpoint.HOME}'
        if endpoint == EndpointJSON.MCU_VERSION:
            url = f'{Endpoint.NEW_BASE_URI}{Endpoint.MCU_VERSION}'
        if endpoint == EndpointJSON.STATUS:
            url = f'{Endpoint.NEW_BASE_URI}{Endpoint.COMMON_DEVICES}{params["devId"]}{Endpoint.CONTROL}'
        if endpoint == EndpointJSON.PROD_SETTINGS:
            url = f'{Endpoint.NEW_BASE_URI}{Endpoint.PROD_SETTINGS}'

        async with self._session.get(url, headers=headers, params=params, timeout=self.timeout) as resp:
            return await self._response(resp, new_api=True)

    async def async_control_purifier(self, device_attr: dict[str, str], command: str, value: Any) -> dict[str, Any] | str:
        """Main function to execute individual purifier control commands."""

        await self._check_token()
        url = f'{Endpoint.BASE_URI}/{EndpointJSON.CONTROL}.json'
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
        message = await self._construct_control_message(EndpointJSON.CONTROL, params)
        data = {
            'message': json.dumps(message)
        }

        async with self._session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
            response = await self._control_command_response(resp)
            return response

    async def async_change_prefilter_setting(self, device_attr: dict[str, str], value: str) -> None:
        """ Used to change the pre-filter wash frequency. Value can be 2, 3, or 4."""

        await self._check_token()
        url = f'{Endpoint.BASE_URI}/{EndpointJSON.CHANGE_PRE_FILTER}.json'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': Header.USER_AGENT
        }
        params = {
            'barcode': device_attr.get('device_id'),
            'comdVal': value,
            'mqttDevice': False
        }
        message = await self._construct_control_message(EndpointJSON.CHANGE_PRE_FILTER, params)
        data = {
            'message': json.dumps(message)
        }

        async with self._session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
            response = await self._control_command_response(resp)
            LOGGER.debug(
                f'{device_attr.get("name")} - Prefilter command sent. Response: {response}'
            )

    async def _construct_control_message(self, json_endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Create message dict used by control and prefilter setting functions."""

        message = {
            'header': {
                'trcode': json_endpoint,
                'accessToken': self.access_token,
                'refreshToken': self.refresh_token
            },
            'body': params
        }
        return message

    @staticmethod
    async def _response(resp: ClientResponse, new_api=False) -> dict[str, Any]:
        """Return response from API call."""

        response: dict[str, Any] = {}
        if resp.status != 200:
            error = await resp.text()
            try:
                error_json = await resp.json()
            except Exception as resp_error:
                raise CowayError(f'Could not return json: {error}') from resp_error
            if 'message' in error_json:
                if error_json['message'] == ErrorMessages.BAD_TOKEN:
                    raise AuthError(
                        f'Coway Auth error: Coway IoCare authentication failed; {ErrorMessages.BAD_TOKEN}'
                    )
                if error_json['message'] == ErrorMessages.EXPIRED_TOKEN:
                    LOGGER.debug(f'Current access token has expired. Error: {ErrorMessages.EXPIRED_TOKEN}')
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
        if not new_api:
            if header := response['header']['error_code']  == 'CWIG0304COWAYLgnE':
                raise AuthError(f'Error code {header}: Coway IoCare access and refresh tokens are invalid. Attempting to fetch new tokens.')
            if error_text := response['header']['error_text']:
                response['error'] = f'Coway API error: {error_text}, Code: {response["header"]["error_code"]}'
                return response
        # Sometimes an unauthorized message is returned with a 200 status
        # and we need to handle it separately.
        if 'message' in response:
            if response['message'] == ErrorMessages.INVALID_REFRESH_TOKEN:
                raise AuthError(
                    f'Coway Auth error: Coway IoCare authentication failed; {ErrorMessages.INVALID_REFRESH_TOKEN}'
                )
        return response

    @staticmethod
    async def _control_command_response(resp: ClientResponse) -> dict[str, Any] | str:
        """Handle response returned for purifier command functions."""

        try:
            response = await resp.json()
        except Exception:
            response = await resp.text()
            return response
        return response
