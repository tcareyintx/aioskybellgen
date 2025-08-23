# pylint:disable=protected-access, too-many-statements, too-many-lines
"""
Test Skybell device functionality.

Tests the device initialization and attributes of the Skybell device class.
"""

from asyncio.exceptions import TimeoutError as Timeout
from datetime import datetime, timedelta
import os
from unittest.mock import patch

import aiofiles
from aiohttp import ClientConnectorError
from aresponses import ResponsesMockServer
from freezegun.api import FrozenDateTimeFactory
import pytest

from aioskybellgen import Skybell, exceptions, utils as UTILS
from aioskybellgen.device import SkybellDevice
from aioskybellgen.helpers import const as CONST

from tests import EMAIL, PASSWORD, load_fixture


def login_response(aresponses: ResponsesMockServer) -> None:
    """Generate login response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/login/",
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("login.json"),
        ),
    )


def refresh_response(aresponses: ResponsesMockServer) -> None:
    """Generate refresh session response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/token/",
        "PUT",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("refresh_session.json"),
        ),
    )


def user_response(aresponses: ResponsesMockServer) -> None:
    """Generate login response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/user/",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("user.json"),
        ),
    )


def failed_user_response(aresponses: ResponsesMockServer) -> None:
    """Generate login response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/user/",
        "GET",
        aresponses.Response(
            status=500,
            headers={"Content-Type": "application/json"},
            text=load_fixture("user.json"),
        ),
    )


def failed_login_response(aresponses: ResponsesMockServer) -> None:
    """Generate failed login response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/login/",
        "POST",
        aresponses.Response(
            status=403,
            headers={"Content-Type": "application/json"},
            text=load_fixture("failure_status.json"),
        ),
    )


def failed_content_login_response(aresponses: ResponsesMockServer) -> None:
    """Generate failed login response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/login/",
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("failure_status.txt"),
        ),
    )


def devices_response(aresponses: ResponsesMockServer) -> None:
    """Generate devices response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/devices/",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("devices.json"),
        ),
    )


def devices_readonly_response(aresponses: ResponsesMockServer) -> None:
    """Generate devices response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/devices/",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("devices_readonly.json"),
        ),
    )


def failed_resource_devices_response(aresponses: ResponsesMockServer) -> None:
    """Generate devices response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/devices/",
        "GET",
        aresponses.Response(
            status=403,
            headers={"Content-Type": "application/json"},
            text=load_fixture("devices.json"),
        ),
    )


def failed_request_devices_response(aresponses: ResponsesMockServer) -> None:
    """Generate devices response."""
    aresponses.add(
        "api.skybell.network",
        "/api/v5/devices/",
        "GET",
        aresponses.Response(
            status=400,
            headers={"Content-Type": "application/json"},
            text=load_fixture("devices.json"),
        ),
    )


def device_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate devices response."""
    path = f"/api/v5/devices/{device}/"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device.json"),
        ),
    )


def device_readonly_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate devices response."""
    path = f"/api/v5/devices/{device}/"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_readonly.json"),
        ),
    )


def snapshot_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate snapshot response."""
    path = f"/api/v5/devices/{device}/snapshot/"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_snapshot.json"),
        ),
    )


def activities_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate snapshot response."""
    path = f"/api/v5/activity?device_id={device}"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_activities.json"),
        ),
        match_querystring=True,
    )


def failed_activities_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate snapshot response."""
    path = f"/api/v5/activity?device_id={device}"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=403,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_activities.json"),
        ),
        match_querystring=True,
    )


def activities_image_response(
    aresponses: ResponsesMockServer, device: str, query: str
) -> None:
    """Generate snapshot response."""
    path = f"/api/v5/activity?device_id={device}{query}"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_activity.json"),
        ),
        match_querystring=True,
    )


def device_settings_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate device settings response."""
    path = f"/api/v5/devices/{device}/settings/"
    aresponses.add(
        "api.skybell.network",
        path,
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_settings.json"),
        ),
    )


def device_settings_led_false_response(
    aresponses: ResponsesMockServer, device: str
) -> None:
    """Generate device settings response."""
    path = f"/api/v5/devices/{device}/settings/"
    aresponses.add(
        "api.skybell.network",
        path,
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_settings_led_false.json"),
        ),
    )


def download_video_url_response(aresponses: ResponsesMockServer, video_id: str) -> None:
    """Generate download video url response."""
    path = f"/api/v5{video_id}"
    aresponses.add(
        "api.skybell.network",
        path,
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("video_url.json"),
        ),
    )


def delete_activity_response(aresponses: ResponsesMockServer, activity: str) -> None:
    """Generate delete activity response."""
    path = f"/api/v5/activity/{activity}"
    aresponses.add(
        "api.skybell.network",
        path,
        "DELETE",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("video_url.json"),
        ),
    )


def get_video_response(aresponses: ResponsesMockServer, video: str) -> None:
    """Generate video response."""
    aresponses.add(
        "skybell-gen5-video.s3.us-east-2.amazonaws.com",
        video,
        "GET",
        aresponses.Response(
            status=200, headers={"Content-Type": "binary/octet-stream"}, body=bytes(2)
        ),
    )


def start_livestream_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate start livestream response."""
    path = f"/api/v5/devices/{device}/videostream/"
    aresponses.add(
        "api.skybell.network",
        path,
        "POST",
        aresponses.Response(
            status=201,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_start_livestream.json"),
        ),
    )


def failed_livestream_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate start livestream failure response."""
    path = f"/api/v5/devices/{device}/videostream/"
    aresponses.add(
        "api.skybell.network",
        path,
        "POST",
        aresponses.Response(
            status=401,
            headers={"Content-Type": "application/json"},
            text=load_fixture("livestream_failure.json"),
        ),
    )


def stop_livestream_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate stop livestream response."""
    path = f"/api/v5/devices/{device}/videostream/"
    aresponses.add(
        "api.skybell.network",
        path,
        "DELETE",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_stop_livestream.json"),
        ),
    )


def reboot_device_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate reboot device response."""
    path = f"/api/v5/devices/{device}/reboot/"
    aresponses.add(
        "api.skybell.network",
        path,
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_reboot.json"),
        ),
    )


def failed_device_reboot_response(aresponses: ResponsesMockServer, device: str) -> None:
    """Generate start reboot device failure response."""
    path = f"/api/v5/devices/{device}/reboot/"
    aresponses.add(
        "api.skybell.network",
        path,
        "POST",
        aresponses.Response(
            status=401,
            headers={"Content-Type": "application/json"},
            text=load_fixture("device_reboot_failure.json"),
        ),
    )


@pytest.mark.asyncio
async def test_loop() -> None:
    """Test loop usage is handled correctly."""
    async with Skybell(EMAIL, PASSWORD) as skybell:
        assert isinstance(skybell, Skybell)
        cemail = EMAIL.replace(".", "")
        assert skybell._cache_path == f"skybell_{cemail}.pickle"


@pytest.mark.asyncio
async def test_async_failed_login(aresponses: ResponsesMockServer) -> None:
    """Test failed_login."""
    failed_login_response(aresponses)
    client = Skybell(
        EMAIL, "password", auto_login=False, get_devices=False, login_sleep=False
    )
    with pytest.raises(exceptions.SkybellAuthenticationException):
        await client.async_login()

    # Test a failed login when sending another request
    failed_login_response(aresponses)
    await client.async_update_cache({CONST.AUTHENTICATION_RESULT: {}})
    with pytest.raises(exceptions.SkybellAuthenticationException):
        await client.async_send_request(CONST.USER_URL)
    await client.async_logout()

    # Test No password
    with pytest.raises(exceptions.SkybellAuthenticationException):
        client = Skybell(
            EMAIL, None, auto_login=False, get_devices=False, login_sleep=False
        )
        await client.async_login()
    await client.async_logout()

    # Test wrong content type
    failed_content_login_response(aresponses)
    with pytest.raises(exceptions.SkybellRequestException):
        client = Skybell(
            EMAIL, PASSWORD, auto_login=False, get_devices=False, login_sleep=False
        )
        await client.async_login()
    await client.async_logout()

    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_async_failed_request(aresponses: ResponsesMockServer) -> None:
    """Test failed request, failed resource request and retry login."""
    client = Skybell(
        EMAIL, PASSWORD, auto_login=True, get_devices=True, login_sleep=False
    )

    # Test failed resource and failed request
    login_response(aresponses)
    user_response(aresponses)
    failed_resource_devices_response(aresponses)
    with pytest.raises(exceptions.SkybellUnknownResourceException):
        await client.async_initialize()
    login_response(aresponses)
    user_response(aresponses)
    failed_request_devices_response(aresponses)
    with pytest.raises(exceptions.SkybellRequestException):
        await client.async_initialize()

    # Test retry on fail
    failed_user_response(aresponses)
    login_response(aresponses)
    with pytest.raises(exceptions.SkybellException):
        await client.async_send_request(url=CONST.USER_URL, retry=True)

    # Test no retry on fail
    failed_user_response(aresponses)
    with pytest.raises(exceptions.SkybellException):
        await client.async_send_request(url=CONST.USER_URL, retry=False)

    await client.async_logout()
    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_async_initialize_and_logout(aresponses: ResponsesMockServer) -> None:
    """Test ;login initializing and logout."""
    # Login
    login_response(aresponses)
    client = Skybell(
        EMAIL, PASSWORD, auto_login=False, get_devices=False, login_sleep=True
    )
    await client.async_login(username=EMAIL, password=PASSWORD)

    # Test refresh session cache token
    auth = client._cache[CONST.AUTHENTICATION_RESULT]
    auth[CONST.REFRESH_TOKEN] = ""
    with pytest.raises(exceptions.SkybellAuthenticationException):
        await client.async_refresh_session()

    await client.async_logout()
    # Test initializing and logout.
    client = Skybell(
        EMAIL, PASSWORD, auto_login=True, get_devices=True, login_sleep=False
    )
    login_response(aresponses)
    user_response(aresponses)
    devices_response(aresponses)
    refresh_response(aresponses)
    data = await client.async_initialize()
    assert client.user_id == "1234567890abcdef12345678"
    assert client.user_first_name == "First"
    assert client.user_last_name == "Last"
    assert client._cache["AuthenticationResult"]
    ar = client._cache["AuthenticationResult"]
    assert ar["AccessToken"] == "superlongkey"

    assert isinstance(data[0], SkybellDevice)
    device = client._devices["012345670123456789abcdef"]
    assert isinstance(device, SkybellDevice)
    assert isinstance(device.skybell, Skybell)

    # Test the session refresh
    await client.async_refresh_session()
    ar = client._cache["AuthenticationResult"]
    assert ar["AccessToken"] == "LongToken"
    assert ar["ExpiresIn"] == 3600
    assert client.session_refresh_period == 3600
    assert ar["TokenType"] == "Bearer"
    assert isinstance(ar["ExpirationDate"], datetime)
    assert isinstance(client.session_refresh_timestamp, datetime)

    # Test get_devices where device does exist
    del client._devices["012345670123456789abcdef"]
    devices_response(aresponses)
    await client.async_get_devices(refresh=True)
    assert isinstance(client._devices["012345670123456789abcdef"], SkybellDevice)

    # Test the session logout
    assert await client.async_logout() is True
    assert not client._devices

    with pytest.raises(RuntimeError):
        await client.async_login()

    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_async_get_devices(
    aresponses: ResponsesMockServer, client: Skybell, freezer: FrozenDateTimeFactory
) -> None:
    """Test getting devices."""
    freezer.move_to("2023-03-30 13:33:00+00:00")

    # Test the Get Device and device specific attributes
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_device("012345670123456789abcdef", refresh=True)
    assert isinstance(data, SkybellDevice)
    device = client._devices["012345670123456789abcdef"]
    assert isinstance(device, SkybellDevice)
    # Test public API and device data structure
    assert device._device_json["basic_motion"] == {
        "fd_notify": True,
        "fd_record": True,
        "hbd_notify": True,
        "hbd_record": True,
        "motion_notify": True,
        "motion_record": True,
    }
    assert device.basic_motion == {
        "fd_notify": True,
        "fd_record": True,
        "hbd_notify": True,
        "hbd_record": True,
        "motion_notify": True,
        "motion_record": True,
    }
    assert device.basic_motion_fd_notify is True
    assert device.basic_motion_fd_record is True
    assert device.basic_motion_hbd_notify is True
    assert device.basic_motion_hbd_record is True
    assert device.basic_motion_notify is True
    assert device.basic_motion_record is True

    assert device._device_json["created_at"] == "2020-10-20T14:35:00.745Z"
    assert (
        device._device_json["invite_token"]
        == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
    assert device._device_json["device_id"] == "012345670123456789abcdef"
    assert device.device_id == "012345670123456789abcdef"
    assert device._device_json["name"] == "FrontDoor"
    assert device.name == "FrontDoor"
    assert device._device_json["last_connected"] == "2020-10-21T14:35:00.745Z"
    assert device.last_connected.strftime("%Y-%m-%d") == "2020-10-21"
    assert device._device_json["last_disconnected"] == "2020-10-20T14:35:00.745Z"
    assert device.last_disconnected.strftime("%Y-%m-%d") == "2020-10-20"
    assert device._device_json["updated_at"] == "2021-10-20T14:35:00.745Z"
    assert device._device_json["account_id"] == "123-123-123"
    assert device.user_id == "123-123-123"
    assert device.is_shared is False
    assert device.is_readonly is False
    assert device.status == "Up"
    assert device.is_up is True
    assert (
        device.desc
        == "FrontDoor (id: 012345670123456789abcdef) "
        + "- SB_SLIM2_0001 - status: Up - WiFi link quality: 98/100"
    )

    # Test public API and device settings structure
    device_settings = device._device_json["device_settings"]
    assert device_settings["model_rev"] == "SB_SLIM2_0001"
    assert device.type == "SB_SLIM2_0001"
    assert device_settings["MAC_address"] == "AA:BB:CC:DD:EE:FF"
    assert device.mac == "AA:BB:CC:DD:EE:FF"
    assert device_settings["serial_number"] == "ASERIALNUM"
    assert device.serial_no == "ASERIALNUM"
    assert device_settings["serial_number"] == "ASERIALNUM"
    assert device.serial_no == "ASERIALNUM"
    assert device_settings["firmware_version"] == "1.7.21"
    assert device.firmware_ver == "1.7.21"
    assert device_settings["ESSID"] == "SSID"

    # Test public API and device telemetry structure
    telemetry = device._device_json["telemetry"]
    assert telemetry["last_seen"] == "2022-10-20T14:35:00.745Z"
    assert device.last_seen.strftime("%Y-%m-%d") == "2022-10-20"
    assert telemetry["link_quality"] == "98/100"
    assert device.wifi_link_quality == "98/100"
    assert telemetry["signal_level"] == "-54"
    assert device.wifi_signal_level == "-54"
    assert telemetry["essid"] == "SSID"
    assert device.wifi_ssid == "SSID"

    # Test punlic API and settings structure
    settings = device._device_json["settings"]
    assert settings["time_zone_info"] == {
        "mapLat": 1.0,
        "mapLong": -1.0,
        "place": "Anywhere",
    }
    assert device.location == {"mapLat": 1.0, "mapLong": -1.0, "place": "Anywhere"}
    assert device.location_lat == 1.0
    assert device.location_lon == -1.0
    assert device.location_place == "Anywhere"
    assert settings["device_name"] == "FrontDoor"
    assert settings["button_pressed"] is True
    assert device.button_pressed is True
    assert settings["led_control"] == "Normal"
    assert device.led_control == "Normal"
    assert settings["led_color"] == "#00ff00"
    assert device.led_color == "#00ff00"
    assert settings["indoor_chime"] is True
    assert device.indoor_chime is True
    assert settings["digital_chime"] is False
    assert device.digital_chime is False
    assert settings["outdoor_chime"] is True
    assert device.outdoor_chime is True
    assert settings["outdoor_chime_volume"] == 2
    assert device.outdoor_chime_volume == 2
    assert settings["speaker_volume"] == 1
    assert device.speaker_volume == 1
    assert settings["motion_detection"] is True
    assert device.motion_detection is True
    assert settings["debug_motion_detect"] is True
    assert device.debug_motion_detect is True
    assert settings["motion_sensitivity"] == 534
    assert device.motion_sensitivity == 534
    assert settings["hmbd_sensitivity"] == 500
    assert device.hmbd_sensitivity == 500
    assert settings["fd_sensitivity"] == 573
    assert device.fd_sensitivity == 573
    assert settings["pir_sensitivity"] == 524
    assert device.pir_sensitivity == 524
    assert settings["image_quality"] == 0
    assert device.image_quality == 0

    # Test get devices when device exists
    devices_response(aresponses)
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    await client.async_get_devices(refresh=True)
    assert device._device_json["device_id"] == "012345670123456789abcdef"

    # Test get device refresh when device exists
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    await client.async_get_device(device_id="012345670123456789abcdef", refresh=True)
    assert device._device_json["device_id"] == "012345670123456789abcdef"

    assert aresponses.assert_no_unused_routes() is None


@pytest.mark.asyncio
async def test_async_refresh_device(
    aresponses: ResponsesMockServer,
    client: Skybell,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test refreshing device."""
    freezer.move_to("2023-03-30 13:33:00+00:00")
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]

    # Test the update for the devices
    device_response(aresponses, device.device_id)
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    await device.async_update(get_devices=True)
    assert device._device_json["device_id"] == "012345670123456789abcdef"
    assert device.device_id == "012345670123456789abcdef"
    assert device._device_json["name"] == "FrontDoor"
    assert device.name == "FrontDoor"

    # Test the images
    assert device.images[CONST.SNAPSHOT] == b"hello world"
    assert device.images[CONST.ACTIVITY] == b"hello world"

    # Test the activities for the device
    data = device.activities()[0]

    assert data["activity_id"] == "bdc15f68-4c7b-41e2-8c54-adfb800898a9"
    assert data["event_type"] == "doorbell"
    assert data["event_time"] == 1751732391135
    assert data["device_id"] == "012345670123456789abcdef"
    assert data["image"] is None
    assert data["video_ready"] is True
    assert data["video_url"] == "/activity/act-doorbell/video"

    assert isinstance(device.activities(event="motion"), list)
    assert isinstance(device.latest(event_type="motion"), dict)
    assert (
        device.latest(event_type="motion")[CONST.CREATED_AT]
        == "2019-07-05T14:30:17.659Z"
    )
    assert (
        device.latest(event_type="doorbell")[CONST.CREATED_AT]
        == "2019-07-05T16:19:51.157Z"
    )

    # Test a basic update that does not get the device
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    await device.async_update()
    assert device._device_json["device_id"] == "012345670123456789abcdef"
    assert device.device_id == "012345670123456789abcdef"
    assert device._device_json["name"] == "FrontDoor"
    assert device.name == "FrontDoor"

    # Clear the cache file
    os.remove(client._cache_path)

    assert aresponses.assert_no_unused_routes() is None


@pytest.mark.asyncio
async def test_async_change_setting(
    aresponses: ResponsesMockServer, client: Skybell
) -> None:
    """Test changing settings on device."""
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]
    assert isinstance(device._device_json["settings"], dict)

    # Test public API and settings structure
    device_response(aresponses, device.device_id)
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("name", "FrontDoor")
    settings = device._device_json["settings"]
    assert settings["device_name"] == "FrontDoor"

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("button_pressed", True)
    settings = device._device_json["settings"]
    assert settings["button_pressed"] is True

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("led_control", "Normal")
    settings = device._device_json["settings"]
    assert settings["led_control"] == "Normal"

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("led_color", "#00ff00")
    settings = device._device_json["settings"]
    assert settings["led_color"] == "#00ff00"

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("normal_led", True)
    settings = device._device_json["settings"]
    assert settings["led_color"] == "#00ff00"

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("indoor_chime", True)
    settings = device._device_json["settings"]
    assert settings["indoor_chime"] is True

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("digital_chime", False)
    settings = device._device_json["settings"]
    assert settings["digital_chime"] is False

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("outdoor_chime", True)
    settings = device._device_json["settings"]
    assert settings["outdoor_chime"] is True

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("outdoor_chime_volume", 2)
    settings = device._device_json["settings"]
    assert settings["outdoor_chime_volume"] == 2

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("speaker_volume", 1)
    settings = device._device_json["settings"]
    assert settings["speaker_volume"] == 1

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("motion_detection", True)
    settings = device._device_json["settings"]
    assert settings["motion_detection"] is True

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("debug_motion_detect", True)
    settings = device._device_json["settings"]
    assert settings["debug_motion_detect"] is True

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("motion_sensitivity", 1000)
    settings = device._device_json["settings"]
    assert settings["motion_sensitivity"] == 1000

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("hmbd_sensitivity", 500)
    settings = device._device_json["settings"]
    assert settings["hmbd_sensitivity"] == 500

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("fd_sensitivity", 500)
    settings = device._device_json["settings"]
    assert settings["fd_sensitivity"] == 500

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("pir_sensitivity", 524)
    settings = device._device_json["settings"]
    assert settings["pir_sensitivity"] == 524
    assert device.pir_sensitivity == 524

    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("image_quality", 0)
    settings = device._device_json["settings"]
    assert settings["image_quality"] == 0
    assert device.image_quality == 0

    with pytest.raises(exceptions.SkybellException):
        await client.async_get_device("foo")

    # Test Range Exceptions (_validate_setting)
    # Check the enumerations
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.OUTDOOR_CHIME_VOLUME, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.SPEAKER_VOLUME, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.IMAGE_QUALITY, 4)

    # Check the booleans
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.NORMAL_LED, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.INDOOR_CHIME, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.INDOOR_DIGITAL_CHIME, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.OUTDOOR_CHIME, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_DETECTION, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.DEBUG_MOTION_DETECTION, 4)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.BUTTON_PRESSED, 4)

    # Check the ranges
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_SENSITIVITY, 1500)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_PIR_SENSITIVITY, 1500)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_HMBD_SENSITIVITY, 1500)

    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_FD_SENSITIVITY, 1500)

    # Validate the basic motion fields
    motion_dict = {
        CONST.BASIC_MOTION_NOTIFY: True,
        CONST.BASIC_MOTION_RECORD: True,
        CONST.BASIC_MOTION_FD_NOTIFY: True,
        CONST.BASIC_MOTION_FD_RECORD: True,
        CONST.BASIC_MOTION_HBD_NOTIFY: True,
        CONST.BASIC_MOTION_HBD_RECORD: True,
        "invalid_field": False,
    }
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.BASIC_MOTION, motion_dict)

    # Validate the basic motion fields are boolean and missing data
    motion_dict = {
        CONST.BASIC_MOTION_NOTIFY: 4,
        CONST.BASIC_MOTION_RECORD: True,
        CONST.BASIC_MOTION_FD_NOTIFY: True,
        CONST.BASIC_MOTION_FD_RECORD: True,
        CONST.BASIC_MOTION_HBD_NOTIFY: True,
        CONST.BASIC_MOTION_HBD_RECORD: True,
    }
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.BASIC_MOTION, motion_dict)
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.BASIC_MOTION_NOTIFY, 4)

    settings_json = device._device_json.get(CONST.SETTINGS, {})
    bm = settings_json[CONST.BASIC_MOTION]
    settings_json[CONST.BASIC_MOTION] = {}
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.BASIC_MOTION_NOTIFY, True)
    settings_json[CONST.BASIC_MOTION] = bm

    # Validate the time zone fields
    tz_dict = {
        CONST.LOCATION_LAT: 1.0,
        CONST.LOCATION_LON: -1.0,
        CONST.LOCATION_PLACE: "Anywhere",
        "invalid_field": False,
    }
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.TIMEZONE_INFO, tz_dict)

    # Validate lat and long are floats
    tz_dict = {
        CONST.LOCATION_LAT: False,
        CONST.LOCATION_LON: -1.0,
        CONST.LOCATION_PLACE: "Anywhere",
    }
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.TIMEZONE_INFO, tz_dict)

    # Validate place is a string and exceptions for missing data
    tz_dict = {
        CONST.LOCATION_LAT: 1.0,
        CONST.LOCATION_LON: -1.0,
        CONST.LOCATION_PLACE: False,
    }
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.TIMEZONE_INFO, tz_dict)
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.LOCATION_PLACE, False)

    settings_json = device._device_json.get(CONST.SETTINGS, {})
    tz = settings_json[CONST.TIMEZONE_INFO]
    settings_json[CONST.TIMEZONE_INFO] = {}
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.LOCATION_PLACE, "Anyplace")
    settings_json[CONST.TIMEZONE_INFO] = tz

    # Test that PIR sensitivity is an integer
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_PIR_SENSITIVITY, "str")

    # Test that HMBD sensitivity is an integer
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.MOTION_HMBD_SENSITIVITY, "str")

    # Test the timestamp public exceptions
    old = device._device_json[CONST.LAST_CONNECTED]
    device._device_json[CONST.LAST_CONNECTED] = None
    assert device.last_connected is None
    device._device_json[CONST.LAST_CONNECTED] = ""
    assert device.last_connected is None
    device._device_json[CONST.LAST_CONNECTED] = old

    old = device._device_json[CONST.LAST_DISCONNECTED]
    device._device_json[CONST.LAST_DISCONNECTED] = None
    assert device.last_disconnected is None
    device._device_json[CONST.LAST_DISCONNECTED] = ""
    assert device.last_disconnected is None
    device._device_json[CONST.LAST_DISCONNECTED] = old

    telemetry = device._device_json[CONST.DEVICE_TELEMETRY]
    old = telemetry[CONST.DEVICE_LAST_SEEN]
    telemetry[CONST.DEVICE_LAST_SEEN] = None
    assert isinstance(device.last_seen, datetime)
    telemetry[CONST.DEVICE_LAST_SEEN] = ""
    assert device.last_seen is None
    telemetry[CONST.DEVICE_LAST_SEEN] = old

    # Test the last doorbell and motion event time
    old = device._events[CONST.DOORBELL_ACTIVITY]
    del device._events[CONST.DOORBELL_ACTIVITY]
    assert device.latest_doorbell_event_time is None
    device._events[CONST.DOORBELL_ACTIVITY] = old
    ts = device.latest_doorbell_event_time
    assert isinstance(ts, datetime)

    old = device._events[CONST.MOTION_ACTIVITY]
    del device._events[CONST.MOTION_ACTIVITY]
    assert device.latest_motion_event_time is None
    device._events[CONST.MOTION_ACTIVITY] = old
    ts = device.latest_motion_event_time
    assert isinstance(ts, datetime)

    old = device._events[CONST.LIVESTREAM_ACTIVITY]
    del device._events[CONST.LIVESTREAM_ACTIVITY]
    assert device.latest_livestream_event_time is None
    device._events[CONST.LIVESTREAM_ACTIVITY] = old
    ts = device.latest_livestream_event_time
    assert isinstance(ts, datetime)

    # Test to get the SSID from alternate attribute
    telemetry = device._device_json[CONST.DEVICE_TELEMETRY]
    old = telemetry[CONST.WIFI_SSID]
    del telemetry[CONST.WIFI_SSID]
    assert device.wifi_ssid == "SSID"
    telemetry[CONST.WIFI_SSID] = old

    # Tests for LED Enable = False
    # Test for False when LED COLOR exists
    device_settings_led_false_response(aresponses, device.device_id)
    await device.async_set_setting("normal_led", False)
    settings = device._device_json["settings"]
    assert settings["led_color"] == ""

    # Test for True when LED COLOR empty
    device_settings_response(aresponses, device.device_id)
    await device.async_set_setting("normal_led", True)
    settings = device._device_json["settings"]
    assert settings["led_color"] == "#00ff00"

    # Test if the normal led is on
    assert device.normal_led_is_on is True

    # Test for Motion detection fields when motion detection is False
    motion_dict = {
        CONST.BASIC_MOTION_NOTIFY: True,
        CONST.BASIC_MOTION_RECORD: True,
        CONST.BASIC_MOTION_FD_NOTIFY: True,
        CONST.BASIC_MOTION_FD_RECORD: True,
        CONST.BASIC_MOTION_HBD_NOTIFY: True,
        CONST.BASIC_MOTION_HBD_RECORD: True,
    }
    settings = device._device_json[CONST.SETTINGS]
    settings[CONST.MOTION_DETECTION] = False
    with pytest.raises(exceptions.SkybellException):
        await device.async_set_setting(CONST.BASIC_MOTION, motion_dict)

    os.remove(client._cache_path)
    assert aresponses.assert_no_unused_routes() is None


@pytest.mark.asyncio
async def test_async_shared(aresponses: ResponsesMockServer, client: Skybell) -> None:
    """Test changing settings on device."""
    login_response(aresponses)
    devices_readonly_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]
    assert device._device_json[CONST.SHARED] is True
    assert device._device_json[CONST.SHARED_READ_ONLY] is True

    # Test the settings against read-only
    with pytest.raises(exceptions.SkybellAccessControlException):
        await device.async_set_setting("name", "FrontDoor")

    # Test the delete activity
    with pytest.raises(exceptions.SkybellAccessControlException):
        await device.async_delete_activity(activity_id="any")

    os.remove(client._cache_path)
    assert aresponses.assert_no_unused_routes() is None


@pytest.mark.asyncio
async def test_async_get_activity_video_url(
    aresponses: ResponsesMockServer, client: Skybell
) -> None:
    """Test getting the video url for an activity.

    Test simulating a download of a video.
    """
    # Get the device with its activity
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]

    # Test the update for the devices
    device_response(aresponses, device.device_id)
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    await device.async_update(get_devices=True)

    # Get video url associated with an activity
    act = device.latest()
    video_id = act[CONST.VIDEO_URL]
    download_video_url_response(aresponses, video_id=video_id)
    download_url = await device.async_get_activity_video_url(video=video_id)
    assert (
        download_url == "https://skybell-gen5-video.s3.us-east-2.amazonaws.com/video-id"
    )

    # Get video url associated for latest activity
    act = device.latest()
    video_id = act[CONST.VIDEO_URL]
    download_video_url_response(aresponses, video_id=video_id)
    download_url = await device.async_get_activity_video_url(video=None)
    assert (
        download_url == "https://skybell-gen5-video.s3.us-east-2.amazonaws.com/video-id"
    )

    # Download the video ( and cleanup file)
    activity_id = act[CONST.ACTIVITY_ID]
    delete_activity_response(aresponses, activity_id)
    download_video_url_response(aresponses, video_id=video_id)
    get_video_response(aresponses, "/video-id")
    await device.async_download_videos(video=video_id, delete=True)
    path = client._cache_path[:-7]
    file = f"{path}_{act[CONST.EVENT_TIME]}.mp4"
    assert os.path.exists(file) is True
    if os.path.exists(file):
        os.remove(file)

    # Download the video from activities ( and cleanup file)
    activities = device.activities(limit=1)
    act = activities[0]
    activity_id = act[CONST.ACTIVITY_ID]
    video_id = act[CONST.VIDEO_URL]
    delete_activity_response(aresponses, activity_id)
    download_video_url_response(aresponses, video_id=video_id)
    get_video_response(aresponses, "/video-id")
    await device.async_download_videos(video=None, limit=1, delete=True)
    path = client._cache_path[:-7]
    file = f"{path}_{act[CONST.EVENT_TIME]}.mp4"
    assert os.path.exists(file) is True
    if os.path.exists(file):
        os.remove(file)

    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_async_delete_activity(
    aresponses: ResponsesMockServer, client: Skybell
) -> None:
    """Test deleting an activity."""
    # Get the device with its activity
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]

    # Test the update for the devices
    device_response(aresponses, device.device_id)
    snapshot_response(aresponses, device.device_id)
    activities_response(aresponses, device.device_id)
    query = "&start=1751732390135&end=1751732392135&nopreviews=0"
    activities_image_response(aresponses, device.device_id, query)
    await device.async_update(get_devices=True)

    # Get activiry id associated with an activity
    act = device.latest()
    activity_id = act[CONST.ACTIVITY_ID]
    delete_activity_response(aresponses, activity_id)
    await device.async_delete_activity(activity_id=activity_id)
    assert len(device._activities) == 2
    assert len(device._events) == 2

    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_async_livestream(
    aresponses: ResponsesMockServer, client: Skybell
) -> None:
    """Test starting and stopping livestream."""
    # Get the device
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]

    # Test the livestream
    start_livestream_response(aresponses, device._device_id)
    result = await device.async_start_livestream()
    assert "channelARN" in result

    stop_livestream_response(aresponses, device._device_id)
    result = await device.async_stop_livestream()
    assert result is None

    # Test the Access Exception when starting the livestream
    device._device_json[CONST.SHARED] = True
    device._device_json[CONST.SHARED_READ_ONLY] = True
    failed_livestream_response(aresponses, device._device_id)
    with pytest.raises(exceptions.SkybellAccessControlException):
        await device.async_start_livestream()

    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_async_reboot(aresponses: ResponsesMockServer, client: Skybell) -> None:
    """Test rebooting the device."""
    # Get the device
    login_response(aresponses)
    devices_response(aresponses)
    data = await client.async_get_devices()
    device = data[0]

    # Test the reboot
    reboot_device_response(aresponses, device._device_id)
    result = await device.async_reboot_device()
    assert result is None

    # Test the Access Exception when rebooting the device
    device._device_json[CONST.SHARED] = True
    device._device_json[CONST.SHARED_READ_ONLY] = True
    failed_device_reboot_response(aresponses, device._device_id)
    with pytest.raises(exceptions.SkybellAccessControlException):
        await device.async_reboot_device()

    os.remove(client._cache_path)
    assert not aresponses.assert_no_unused_routes()


@pytest.mark.asyncio
async def test_cache(
    aresponses: ResponsesMockServer, client: Skybell, freezer: FrozenDateTimeFactory
) -> None:
    """Test cache."""
    freezer.move_to("2023-03-30 13:33:00+00:00")

    login_response(aresponses)
    user_response(aresponses)
    devices_response(aresponses)
    # Create the cache file
    if os.path.exists(client._cache_path):
        os.remove(client._cache_path)

    # Load the cache and write to the file
    await client.async_initialize()

    # Test that the cache file has content
    assert os.path.getsize(client._cache_path) > 0

    # Test loading an empty cache
    old_cache = client._cache
    async with aiofiles.open(client._cache_path, "wb") as file:
        await file.close()
    await client._async_load_cache()
    assert os.path.exists(client._cache_path) is True
    assert client._cache == old_cache

    # Test the delete cache
    old_cache_path = client._cache_path
    await client.async_delete_cache()
    assert os.path.exists(old_cache_path) is False

    # Test the expires in min to the expires in
    ts = UTILS.calculate_expiration(expires_in=1, slack=0, refresh_cycle=30)
    ex_ts = datetime.now() + timedelta(seconds=1)
    assert ts == ex_ts

    # Test coverage: update something other than a dictionary
    result = UTILS.update(dct=[], dct_merge={})
    assert isinstance(result, dict) is False


@pytest.mark.asyncio
async def test_async_test_ports(client: Skybell) -> None:
    """Test open ports."""
    with patch("aioskybellgen.ClientSession.get") as session:
        session.side_effect = ClientConnectorError("", OSError(61, ""))
        assert await client.async_test_ports("1.2.3.4") is True

    with patch("aioskybellgen.ClientSession.get") as session:
        session.side_effect = Timeout
        assert await client.async_test_ports("1.2.3.4") is False


@pytest.mark.asyncio
async def clean_up_cache(client: Skybell) -> None:
    """Cleanup the cache file."""
    if os.path.exists(client._cache_path):
        await os.remove(client._cache_path)
    assert await os.path.exists(client._cache_path) is False
