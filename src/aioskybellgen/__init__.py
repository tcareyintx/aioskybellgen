"""An asynchronous client for Skybell Generation v5 API.

Async spinoff of https://github.com/MisterWil/skybellpy
             and https://github.com/tkdrob/aioskybellgen

Published under the MIT license - See LICENSE file for more details.

"Skybell" is a trademark owned by SkyBell Technologies, Inc, see
www.skybell.com for more information. I am in no way affiliated with Skybell.
"""

from __future__ import annotations

import asyncio
from asyncio.exceptions import TimeoutError as Timeout
from datetime import datetime
import logging
import os
from typing import Any, cast

from aiohttp.client import ClientSession, ClientTimeout
from aiohttp.client_exceptions import (
    ClientConnectorError,
    ClientError,
    ContentTypeError,
)

from . import utils as UTILS
from .device import SkybellDevice
from .exceptions import (
    SkybellAccessControlException,
    SkybellAuthenticationException,
    SkybellException,
    SkybellRequestException,
    SkybellUnknownResourceException,
)
from .helpers import const as CONST, errors as ERROR

_LOGGER = logging.getLogger(__name__)


class Skybell:  # pylint:disable=too-many-instance-attributes
    """Main Skybell class."""

    _close_session = False

    def __init__(  # pylint:disable=too-many-arguments, too-many-positional-arguments
        self,
        username: str | None = None,
        password: str | None = None,
        auto_login: bool = False,
        get_devices: bool = True,
        cache_path: str = CONST.CACHE_PATH,
        disable_cache: bool = False,
        login_sleep: bool = True,
        session: ClientSession | None = None,
    ) -> None:
        """Initialize Skybell object."""
        self._auto_login = auto_login
        self._cache_path = cache_path
        self._devices: dict[str, SkybellDevice] = {}
        self._disable_cache = disable_cache
        self._get_devices = get_devices
        self._password = password
        if username is not None and self._cache_path == CONST.CACHE_PATH:
            self._cache_path = f"skybell_{username.replace('.', '')}.pickle"
        self._username = username
        if session is None:
            session = ClientSession()
            self._close_session = True
        self._session = session
        self._login_sleep = login_sleep
        self._user: dict[str, str] = {}

        # Create a new cache template
        self._cache: dict[str, Any] = {
            CONST.AUTHENTICATION_RESULT: {},
        }

    async def __aenter__(self) -> Skybell:
        """Async enter."""
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        """Async exit."""
        if self._session and self._close_session:
            await self._session.close()

    async def async_initialize(self) -> list[SkybellDevice]:
        """Initialize the Skybell API.

        Exceptions: SkybellAuthentionException, SkybellException.
        """
        if not self._disable_cache:
            await self._async_load_cache()

        # Login option on initialization, otherwise wait until
        # A request is made
        if (
            self._username is not None
            and self._password is not None
            and self._auto_login
        ):
            await self.async_login()

        # Obtain the user data -  which will login
        response = await self.async_send_request(CONST.USER_URL)
        self._user = {}
        if response is not None and response:
            self._user = response

        # Obtain the devices for the user
        devices = []
        if self._user is not None and self._get_devices:
            devices = await self.async_get_devices()
        return devices

    async def async_login(
        self, username: str | None = None, password: str | None = None
    ):
        """Execute Skybell login.

        Exceptions: SkybellAuthentionException, SkybellException.
        """
        if username is not None:
            self._username = username
        if password is not None:
            self._password = password

        if self._username is None or self._password is None:
            raise SkybellAuthenticationException(
                self, f"{ERROR.USERNAME}: {ERROR.PASSWORD}"
            )

        # Clear any cached login data
        await self.async_update_cache({CONST.AUTHENTICATION_RESULT: {}})

        login_data: dict[str, str | int] = {
            "username": self._username,
            "password": self._password,
        }

        response = await self.async_send_request(
            url=CONST.LOGIN_URL,
            json=login_data,
            method=CONST.HTTPMethod.POST,
            retry=False,
        )
        if response is not None and response:
            _LOGGER.debug("Login Response: %s", response)
            # Store the Authorization result
            auth_result = response[CONST.AUTHENTICATION_RESULT]
            # Add an expiration date
            expires_in = auth_result[CONST.TOKEN_EXPIRATION]
            expiration = UTILS.calculate_expiration(
                expires_in=expires_in,
                slack=CONST.EXPIRATION_SLACK,
                refresh_cycle=CONST.REFRESH_CYCLE,
            )
            auth_result[CONST.EXPIRATION_DATE] = expiration
            await self.async_update_cache({CONST.AUTHENTICATION_RESULT: auth_result})

            if self._login_sleep:
                _LOGGER.info("Login successful, waiting 5 seconds...")
                await asyncio.sleep(5)
            else:
                _LOGGER.info("Login successful")

    async def async_logout(self) -> bool:
        """Explicit Skybell logout."""
        if len(self.cache(CONST.AUTHENTICATION_RESULT)) > 0:
            # No explicit logout call as it doesn't seem to matter
            # if a logout happens without registering the app which
            # we aren't currently doing.
            if self._session and self._close_session:
                await self._session.close()
            self._devices = {}

        await self.async_update_cache({CONST.AUTHENTICATION_RESULT: {}})

        return True

    async def async_refresh_session(self) -> bool:
        """Execute Skybell refresh.

        Exceptions: SkybellAuthentionException, SkybellException.
        """
        auth_result = self.cache(CONST.AUTHENTICATION_RESULT)
        refresh_token = ""
        if auth_result:
            refresh_token = cast(dict, auth_result).get(CONST.REFRESH_TOKEN, "")

        if not self._session or not refresh_token:
            raise SkybellAuthenticationException(self, "No session established")

        body_data: dict[str, str | int] = {
            CONST.REFRESH_TOKEN_BODY: refresh_token,
        }

        response = await self.async_send_request(
            url=CONST.REFRESH_TOKEN_URL,
            json=body_data,
            method=CONST.HTTPMethod.PUT,
            retry=False,
        )
        if response is not None and response:
            _LOGGER.debug("Token Refresh Response: %s", response)
            # Add an expiration date
            expires_in = response[CONST.TOKEN_EXPIRATION]
            expiration = UTILS.calculate_expiration(
                expires_in=expires_in,
                slack=CONST.EXPIRATION_SLACK,
                refresh_cycle=CONST.REFRESH_CYCLE,
            )
            response[CONST.EXPIRATION_DATE] = expiration
            # Update the cache entities
            UTILS.update(
                cast(dict[str, Any], auth_result), cast(dict[str, Any], response)
            )
            await self.async_update_cache({CONST.AUTHENTICATION_RESULT: auth_result})
            _LOGGER.debug("Refresh successful")

        return True

    async def async_get_devices(self, refresh: bool = False) -> list[SkybellDevice]:
        """Get all devices from Skybell.

        Exceptions: kybellException.
        """
        if refresh or len(self._devices) == 0:
            _LOGGER.info("Updating all devices...")
            response = await self.async_send_request(CONST.DEVICES_URL)
            _LOGGER.debug("Get Devices Response: %s", response)
            if response is not None and response:
                response_rows = response[CONST.RESPONSE_ROWS]
                for device_json in response_rows:
                    # No existing device, create a new one
                    if device := self._devices.get(device_json[CONST.DEVICE_ID]):
                        await device.async_update(
                            {device_json[CONST.DEVICE_ID]: device_json}
                        )
                    else:
                        device = SkybellDevice(device_json, self)
                        self._devices[device.device_id] = device

        return list(self._devices.values())

    async def async_get_device(
        self, device_id: str, refresh: bool = False
    ) -> SkybellDevice:
        """Get a single device.

        Exceptions: SkybellException.
        """
        if len(self._devices) == 0:
            await self.async_get_devices(refresh=refresh)
            refresh = False

        if not (device := self._devices.get(device_id)):
            raise SkybellException(self, "Device not found")
        if refresh:
            await device.async_update(refresh=refresh)

        return device

    @property
    def user_id(self) -> str | None:
        """Return logged in user id."""
        return self._user.get(CONST.USER_ID, None)

    @property
    def user_first_name(self) -> str | None:
        """Return logged in user first name."""
        return self._user.get(CONST.FIRST_NAME, None)

    @property
    def user_last_name(self) -> str | None:
        """Return logged in user last name."""
        return self._user.get(CONST.LAST_NAME, None)

    @property
    def session_refresh_period(self) -> int:
        """Return period, in seconds.

        The period that the session will last without a refresh of the login.
        """
        auth_result = self.cache(CONST.AUTHENTICATION_RESULT)
        period = 0
        if auth_result:
            period = cast(dict[str, Any], auth_result).get(CONST.TOKEN_EXPIRATION, 0)
        return period

    @property
    def session_refresh_timestamp(self) -> datetime | None:
        """Return expiration datetime that the session will last."""
        expires = None
        if auth_result := self.cache(CONST.AUTHENTICATION_RESULT):
            expires = cast(dict[str, Any], auth_result).get(CONST.EXPIRATION_DATE, None)

        return expires

    async def async_send_request(
        # pylint:disable=too-many-arguments, too-many-branches, too-many-statements
        self,
        url: str,
        headers: dict[str, str] | None = None,
        method: CONST.HTTPMethod = CONST.HTTPMethod.GET,
        retry: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Send requests to Skybell.

        Exceptions SkybellAuthenticationException, SkybellException,
                   SkybellUnknownResourceExceptionm SkybellRequestException
        """
        if len(self.cache(CONST.AUTHENTICATION_RESULT)) == 0 and url != CONST.LOGIN_URL:
            await self.async_login()

        headers = headers if headers else {}
        if CONST.BASE_AUTH_DOMAIN in url or CONST.BASE_API_DOMAIN in url:
            auth_result = self.cache(CONST.AUTHENTICATION_RESULT)
            token = cast(dict[str, Any], auth_result).get(CONST.ID_TOKEN, "")
            token_type = cast(dict[str, Any], auth_result).get(CONST.TOKEN_TYPE, "")
            if token and token_type:
                headers["Authorization"] = f"Bearer {token}"
            headers["content-type"] = "application/json"
            headers["accept"] = "*/*"
            headers["x-skybell-app"] = CONST.APP_VERSION

        _LOGGER.debug("HTTP %s %s Request with headers: %s", method, url, headers)

        try:
            client_response = await self._session.request(
                method.value,
                url,
                headers=headers,
                timeout=ClientTimeout(30),
                **kwargs,
            )
            if client_response.status == 401 or (
                client_response.status == 403 and url == CONST.LOGIN_URL
            ):
                if url.find(CONST.VIDEO_STREAM_PATH) > 0:
                    raise SkybellAccessControlException(await client_response.text())
                if url.find(CONST.REBOOT_PATH) > 0:
                    raise SkybellAccessControlException(await client_response.text())

                await self.async_update_cache({CONST.AUTHENTICATION_RESULT: {}})
                raise SkybellAuthenticationException(await client_response.text())
            if client_response.status in (403, 404):
                # 403/404 for expired request/device key no
                # longer present in S3
                _LOGGER.exception(await client_response.text())
                raise SkybellUnknownResourceException(await client_response.text())
            if client_response.status == 400:
                # Bad request problem that cant be fixed by user or logging in
                _LOGGER.exception(await client_response.text())
                raise SkybellRequestException(await client_response.text())
            client_response.raise_for_status()
        except ClientError as ex:
            if retry:
                try:
                    await self.async_login()
                    return await self.async_send_request(
                        url,
                        headers=headers,
                        method=method,
                        retry=False,
                        **kwargs,
                    )
                except (ClientError, SkybellException) as exc:
                    raise SkybellException from exc
            raise SkybellException from ex
        try:
            if client_response.content_type == "application/json":
                local_response = await client_response.json()
            else:
                local_response = await client_response.read()
        except (
            ContentTypeError,
            TypeError,
            ValueError,
            ClientError,
            RuntimeError,
        ) as ex:
            raise SkybellRequestException from ex
        # Now we have a local response which could be
        # a json dictionary or byte stream
        # If the json dictionary doesn't provide a data object
        # return false
        result = local_response
        if isinstance(local_response, dict):
            result = local_response.get(CONST.RESPONSE_DATA, False)
        return result

    def cache(self, key: str) -> str | dict[str, Any]:
        """Get a cached value."""
        return self._cache.get(key, "")

    async def async_update_cache(self, data: dict[str, Any]) -> None:
        """Update a cached value."""
        UTILS.update(self._cache, data)
        await self._async_save_cache()

    async def _async_load_cache(self) -> None:
        """Load existing cache and merge for updating if required."""
        if not self._disable_cache:
            if os.path.exists(self._cache_path):
                _LOGGER.debug("Cache found at: %s", self._cache_path)
                if os.path.getsize(self._cache_path) > 0:
                    loaded_cache = await UTILS.async_load_cache(self._cache_path)
                    UTILS.update(self._cache, loaded_cache)
                else:
                    _LOGGER.debug("Cache file is empty.  Removing it.")
                    os.remove(self._cache_path)

        await self._async_save_cache()

    async def _async_save_cache(self) -> None:
        """Trigger a cache save."""
        if not self._disable_cache:
            await UTILS.async_save_cache(self._cache, self._cache_path)

    async def async_delete_cache(self) -> None:
        """Remove the cache if required."""
        if os.path.exists(self._cache_path):
            _LOGGER.debug("Removing cache found at: %s", self._cache_path)
            os.remove(self._cache_path)
            self._cache_path = CONST.CACHE_PATH

    async def async_test_ports(self, host: str, ports: list[int] | None = None) -> bool:
        """Test if ports are open. Only use this for discovery."""
        result = False
        for port in ports or [6881, 6969]:
            try:
                await self._session.get(
                    f"http://{host}:{port}",
                    timeout=ClientTimeout(10),
                )
            except ClientConnectorError as ex:
                if ex.errno == 61:
                    result = True
            except Timeout:
                return False
        return result
