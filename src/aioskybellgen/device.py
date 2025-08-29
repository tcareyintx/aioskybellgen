"""The device class used by aioskybellgen."""

from __future__ import annotations

from base64 import b64decode
from datetime import datetime, timezone
import logging
from typing import TYPE_CHECKING, Any, cast

import aiofiles

from . import utils as UTILS
from .exceptions import SkybellAccessControlException, SkybellException
from .helpers import const as CONST, errors as ERROR
from .helpers.const import RESPONSE_ROWS

from .helpers.models import (  # isort:skip
    SnapshotData,
    DeviceData,
    ActivityData,
    ActivityType,
    SettingsData,
    LiveStreamConnectionData,
)

if TYPE_CHECKING:  # pragma: no cover
    from . import Skybell

_LOGGER = logging.getLogger(__name__)


class SkybellDevice:
    # pylint:disable=too-many-public-methods, too-many-instance-attributes
    """Class to represent each Skybell device."""

    _skybell: Skybell

    def __init__(self, device_json: DeviceData, skybell: Skybell) -> None:
        """Set up Skybell device."""
        self._activities: list[ActivityData] = []
        self._snapshot_json = SnapshotData()
        self._device_id = device_json.get(CONST.DEVICE_ID, "")
        self._device_json = device_json
        self._skybell = skybell
        device_settings = self._device_json.get(CONST.DEVICE_SETTINGS, {})
        self._type = device_settings.get(CONST.MODEL_REV, "")
        self.images: dict[str, bytes | None] = {CONST.ACTIVITY: None}
        self._events: ActivityType = {}
        self._local_events: dict[str, datetime] = {}

    async def _async_device_request(self) -> DeviceData:
        url = str.replace(CONST.DEVICE_URL, "$DEVID$", self.device_id)
        return await self._skybell.async_send_request(url)

    async def _async_snapshot_request(self) -> SnapshotData:
        url = str.replace(CONST.DEVICE_SNAPSHOT_URL, "$DEVID$", self.device_id)
        return await self._skybell.async_send_request(url)

    async def _async_settings_request(
        self,
        json: dict[str, bool | str | int | float | dict] | None = None,
        **kwargs: Any,
    ) -> SettingsData:
        url = str.replace(CONST.DEVICE_SETTINGS_URL, "$DEVID$", self.device_id)
        return await self._skybell.async_send_request(url, json=json, **kwargs)

    async def _async_activities_request(
        self, query: str | None = None
    ) -> list[ActivityData]:
        """Activities request returns a list of all activity on the device.

        Note that the activities is limited to default limit
        as pagination is not supported in the activities request.
        If a query is passed append that to the URL that already
        has the device query item.
        """
        url = str.replace(CONST.DEVICE_ACTIVITIES_URL, "$DEVID$", self.device_id)
        if query is not None:
            url += query
        response = await self._skybell.async_send_request(url)
        result = []
        if response is not None and response:
            result = response.get(RESPONSE_ROWS, [])
        return result

    async def async_update(  # pylint:disable=too-many-arguments
        self,
        device_json: dict[str, str | dict[str, str]] | None = None,
        snapshot_json: dict[str, str] | None = None,
        refresh: bool = True,
        get_devices: bool = False,
    ) -> None:
        """Update the internal data from the API."""
        # Update the internal device json data.
        if refresh or device_json or not self._device_json:
            if get_devices:
                device_json = await self._async_device_request()
                UTILS.update(self._device_json, device_json or {})

        # The Snapshot image is the avatar of the doorbell.
        if refresh or snapshot_json or not self._snapshot_json:
            response = await self._async_snapshot_request()
            if response is not None and response:
                # Update the image for the avatar snapshot.
                if response[CONST.PREVIEW_CREATED_AT] != self._snapshot_json.get(
                    CONST.PREVIEW_CREATED_AT, None
                ):
                    base64_string = response[CONST.PREVIEW_IMAGE]
                    self.images[CONST.SNAPSHOT] = b64decode(base64_string)
                self._snapshot_json = response
                UTILS.update(self._snapshot_json, snapshot_json or {})

        if refresh:
            await self._async_update_activities()

    async def _async_update_activities(self) -> None:
        """Update stored activities and update caches as required."""
        self._activities = await self._async_activities_request()
        _LOGGER.debug("Device Activities Response: %s", self._activities)

        # Update the selected events from the activity list.
        await self._async_update_events()
        await self._async_update_activity_image(activity=None)

    async def _async_update_activity_image(self, activity: ActivityData | None) -> None:
        """Update images for an activity.

        If no activity is passed get the latest.
        """
        if activity is None:
            activity = self.latest()

        if activity:
            act_id = activity[CONST.ACTIVITY_ID]
            act_time = activity[CONST.EVENT_TIME]
            start_time = act_time - 1000
            end_time = act_time + 1000
            image = b""

            query = f"&start={start_time}&end={end_time}&nopreviews=0"
            act_list = await self._async_activities_request(query=query)
            for act in act_list:
                if act[CONST.ACTIVITY_ID] == act_id:
                    image = act[CONST.IMAGE]

            self.images[CONST.ACTIVITY] = b64decode(image)

    async def _async_update_events(
        self, activities: list[ActivityData] | None = None
    ) -> None:
        # Update our cached list of latest activity events by type.
        activities = activities or self._activities
        for activity in activities:
            event_type = activity[CONST.EVENT_TYPE]
            event_time = activity[CONST.EVENT_TIME]

            old = self._events.get(event_type)
            if not old or event_time >= old[CONST.EVENT_TIME]:
                self._events[event_type] = activity

    def activities(
        self, limit: int = 1, event: str | None = None
    ) -> list[ActivityData]:
        """Return device activity information."""
        activities = self._activities

        # Filter our activity array if requested
        if event:
            activities = list(
                filter(lambda act: act[CONST.EVENT_TYPE] == event, activities)
            )

        # Return the requested number
        return activities[:limit]

    def latest(self, event_type: str | None = None) -> ActivityData:
        """Return the latest event activity. Allow for a filter by type."""
        _LOGGER.debug(self._events)

        # The event (e.g. button, motion is passed)
        latest_event: ActivityData = ActivityData()
        latest_date = None
        for evt in self._events.values():
            if event_type is None or evt[CONST.EVENT_TYPE] == event_type:
                date = evt[CONST.EVENT_TIME]
                if not latest_event or latest_date is None or latest_date < date:
                    latest_event = evt
                    latest_date = date
        return latest_event

    async def async_set_setting(
        self, key: str, value: bool | str | int | float | dict
    ) -> None:
        """Call the API to update the settings."""
        # Set an attribute for the device.
        # The key isn't necessarily equal to the corresponding field
        # and may require transformation logic.
        if key == CONST.NORMAL_LED:
            # Normal LED control of false has to reset the LED COLOR to Empty
            if not isinstance(value, bool):
                raise SkybellException(self, ERROR.INVALID_SETTING_VALUE, (key, value))
            key = CONST.LED_COLOR
            # If the Normal LED value is True - use the color
            # else clear the color
            if value:
                if not (value := self.led_color):
                    value = CONST.DEFAULT_NORMAL_LED_COLOR
            else:
                value = ""
        elif key == CONST.NAME:
            key = CONST.DEVICE_NAME
        elif key in CONST.BASIC_MOTION_FIELDS:
            if not (bm := self.basic_motion.copy()):
                raise SkybellException(self, ERROR.INVALID_SETTING_VALUE, (key, value))
            bm[key] = value
            key = CONST.BASIC_MOTION
            value = bm
        elif key in CONST.TIME_ZONE_FIELDS:
            if not (loc := self.location.copy()):
                raise SkybellException(self, ERROR.INVALID_SETTING_VALUE, (key, value))
            loc[key] = value
            key = CONST.TIMEZONE_INFO
            value = loc

        # Update the settings value for the key
        return await self._async_set_setting({key: value})

    async def _async_set_setting(
        self, settings: dict[str, bool | str | int | float | dict]
    ) -> None:
        """Validate the settings and then send the POST request."""
        for key, value in settings.items():
            if self.is_readonly and key not in CONST.ACL_EXCLUSIONS:
                _LOGGER.warning(
                    "Exception changing settings with read-only scope: %s",
                    settings,
                )
                raise SkybellAccessControlException(
                    self, "Attempted setting with read-only scope."
                )
            self._validate_setting(key, value)
            full_update = False
            if key in CONST.FULL_UPDATE_REQUIRED:
                full_update = True

            # Send network call
            result = await self._async_settings_request(
                json=settings, method=CONST.HTTPMethod.POST
            )

            if result is not None and result:
                # Several fields are outside are displayed outside settings
                if full_update:
                    await self.async_update(get_devices=True)
                else:
                    old_settings = self._device_json[CONST.SETTINGS]
                    UTILS.update(old_settings, result)

    async def async_get_activity_video_url(self, video: str | None = None) -> str:
        """Get url for the video to download.

        If an activity video url is not passed use the latest video url.
        """
        if not video:
            activity = self.latest()
            video = activity.get(CONST.VIDEO_URL, "")

        result = ""
        if video:
            act_url = CONST.ACTIVITY_VIDEO_URL + video
            response = await self._skybell.async_send_request(act_url)
            if response is not None and response:
                result = response.get(CONST.DOWNLOAD_URL, "")

        return result

    async def async_download_videos(
        self,
        path: str | None = None,
        video: str | None = None,
        limit: int = 1,
        delete: bool = False,
    ) -> None:
        """Download videos to specified path.

        path (optional): path to save the videos.
            If path is not passed, use the path to the cache.
        video (optional): activities video url is passed use that url
            If activities video url is not passed download the videos from the
            activities as specified in the limit.
        if requested, delete the activity after saving the video.
        """
        _path = self._skybell._cache_path[:-7]  # pylint:disable=protected-access
        if video and (
            _id := [ev for ev in self._activities if video == ev[CONST.VIDEO_URL]]
        ):
            return await self._async_save_video(path or _path, _id[0], delete)
        for event in self.activities(limit=limit):
            await self._async_save_video(path or _path, event, delete)

    async def _async_save_video(
        self, path: str, event: ActivityData, delete: bool
    ) -> None:
        """Write video from S3 to file.

        Place the file in path directory passed.
        If delete is true, delete the associated activity.
        """
        async with aiofiles.open(f"{path}_{event[CONST.EVENT_TIME]}.mp4", "wb") as file:
            url = await self.async_get_activity_video_url(event[CONST.VIDEO_URL])
            response = await self._skybell.async_send_request(url, retry=False)
            if response is not None and response:
                await file.write(response)
        if delete:
            await self.async_delete_activity(event[CONST.ACTIVITY_ID])

    async def async_delete_activity(self, activity_id: str) -> None:
        """Delete activity with specified activity id.

        Exceptions: SkybellAccessControlException
        """
        if self.is_readonly:
            _LOGGER.warning("Exception deleting activity with read-only scope.")
            raise SkybellAccessControlException(
                self, "Attempted delete activity with read-only scope."
            )

        act_url = str.replace(CONST.ACTIVITY_URL, "$ACTID$", activity_id)
        response = await self._skybell.async_send_request(
            act_url, method=CONST.HTTPMethod.DELETE
        )
        if response is not None and response:
            # Clean out the local events
            for key, act in list(self._events.items()):
                if act[CONST.ACTIVITY_ID] == activity_id:
                    self._events.pop(key)
                    break
            for act in self._activities:
                if act[CONST.ACTIVITY_ID] == activity_id:
                    self._activities.remove(act)
                    break

    async def async_start_livestream(
        self, force: bool = False
    ) -> LiveStreamConnectionData:
        """Request to start a live call using WebRTC.

        Allows caller to establish a live audio and video WebRTC connection with
        the SkyBell device.
        Returns: LiveStreamConnectionData
        Exceptions: SkybellException, SkybellAccessControlException
        """
        body_data: dict[str, str | int] = {
            CONST.LIVESTREAM_FORCE_BODY: force,
        }

        url = str.replace(CONST.DEVICE_LIVESTREAM_URL, "$DEVID$", self.device_id)

        response = await self._skybell.async_send_request(
            url=url,
            json=body_data,
            method=CONST.HTTPMethod.POST,
            retry=False,
        )
        result = LiveStreamConnectionData()
        if response is not None and response:
            result = response

        return result

    async def async_stop_livestream(self) -> None:
        """Request to stop a live call using WebRTC.

        Allows caller to end a live audio and video WebRTC connection with
        the SkyBell device.
        Exceptions: SkybellException
        """
        url = str.replace(CONST.DEVICE_LIVESTREAM_URL, "$DEVID$", self.device_id)

        await self._skybell.async_send_request(
            url=url,
            method=CONST.HTTPMethod.DELETE,
            retry=False,
        )

        return

    async def async_reboot_device(self) -> None:
        """Request to reboot the device.

        Device will reboot 10 - 60 seconds after successful command.
        Exceptions: SkybellException
        """
        url = str.replace(CONST.DEVICE_REBOOT_URL, "$DEVID$", self.device_id)

        await self._skybell.async_send_request(
            url=url,
            method=CONST.HTTPMethod.POST,
            retry=False,
        )

        return

    def _validate_setting(  # pylint:disable=too-many-branches # noqa: C901
        self, setting: str, value: bool | str | int | float | dict
    ) -> None:
        """Validate the public property setting and value.

        Exceptions: SkybellException
        """
        if setting in CONST.MOTION_FIELDS and not self.motion_detection:
            # Motion fields cannot be updated if motion detection is false
            raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
        if setting in CONST.BOOL_SETTINGS:
            if not isinstance(value, bool):
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
        if setting == CONST.BASIC_MOTION:
            for field, field_value in cast(dict, value).items():
                if field not in CONST.BASIC_MOTION_FIELDS:
                    raise SkybellException(
                        ERROR.INVALID_SETTING_VALUE, (field, field_value)
                    )
                if not isinstance(field_value, bool):
                    raise SkybellException(
                        ERROR.INVALID_SETTING_VALUE, (field, field_value)
                    )
        if setting == CONST.TIMEZONE_INFO:
            for field, field_value in cast(dict, value).items():
                if field not in CONST.TIME_ZONE_FIELDS:
                    raise SkybellException(
                        ERROR.INVALID_SETTING_VALUE, (field, field_value)
                    )
                if field in CONST.LOCATION_COORD_FIELDS:
                    if not isinstance(field_value, float):
                        raise SkybellException(
                            ERROR.INVALID_SETTING_VALUE, (field, field_value)
                        )
                if field == CONST.LOCATION_PLACE:
                    if not isinstance(field_value, str):
                        raise SkybellException(
                            ERROR.INVALID_SETTING_VALUE, (field, field_value)
                        )
        if setting == CONST.OUTDOOR_CHIME_VOLUME:
            if value not in CONST.OUTDOOR_CHIME_VALUES:
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
        if setting == CONST.SPEAKER_VOLUME:
            if value not in CONST.SPEAKER_VOLUME_VALUES:
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
        if setting == CONST.IMAGE_QUALITY:
            if value not in CONST.IMAGE_QUALITY_VALUES:
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
        if setting in CONST.GRANULAR_PCT_SETTINGS:
            if not isinstance(value, int):
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
            if value > CONST.SENSITIVITY_MAX:
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
        if setting in CONST.DETAIL_SENSITIVITY_SETTINGS:
            if not isinstance(value, int):
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))
            if value > CONST.SENSITIVITY_MAX and value != CONST.USE_MOTION_SENSITIVITY:
                raise SkybellException(ERROR.INVALID_SETTING_VALUE, (setting, value))

    def set_local_event_message(self, message_type: str) -> None:
        """Set the timestamp for the latest local event message."""
        _LOGGER.debug(
            "Setting local event message: %s for %s", message_type, self.device_id
        )
        event_time = datetime.now(tz=timezone.utc)
        self._local_events[message_type] = event_time

    @property
    def skybell(self) -> Skybell:
        """Get owning Skybell API hub."""
        return self._skybell

    @property
    def is_shared(self) -> bool:
        """Return if the device is a shared device for the user."""
        return self._device_json.get(CONST.SHARED, False)

    @property
    def is_readonly(self) -> bool:
        """Return if the user has readonly access to the device."""
        result = False
        if self.is_shared:
            result = self._device_json.get(CONST.SHARED_READ_ONLY, False)
        return result

    @property
    def user_id(self) -> str:
        """Get user id that owns the device."""
        return self._device_json.get(CONST.ACCOUNT_ID, "")

    @property
    def device_id(self) -> str:
        """Get the device id."""
        return self._device_id

    @property
    def name(self) -> str:
        """Get device name."""
        return self._device_json.get(CONST.NAME, "")

    @property
    def type(self) -> str:
        """Get device type."""
        return self._type

    @property
    def mac(self) -> str | None:
        """Get device mac address."""
        device_settings = self._device_json.get(CONST.DEVICE_SETTINGS, {})
        return device_settings.get(CONST.MAC_ADDRESS, "")

    @property
    def serial_no(self) -> str:
        """Get device serial number."""
        device_settings = self._device_json.get(CONST.DEVICE_SETTINGS, {})
        return device_settings.get(CONST.SERIAL_NUM, "")

    @property
    def firmware_ver(self) -> str:
        """Get device firmware version."""
        device_settings = self._device_json.get(CONST.DEVICE_SETTINGS, {})
        return device_settings.get(CONST.FIRMWARE_VERSION, "")

    @property
    def desc(self) -> str:
        """Get a short description of the device."""
        # Front Door (id: ) - skybell hd - status: up - wifi status: x/100
        string = f"{self.name} (id: {self.device_id}) - {self.type}"
        return (
            f"{string} - status: {self.status} - "
            + f"WiFi link quality: {self.wifi_link_quality}"
        )

    @property
    def status(self) -> str:
        """Get the generic status of a device (up/down)."""
        result = CONST.STATUS_DOWN
        if self.is_up:
            result = CONST.STATUS_UP
        return result

    @property
    def is_up(self) -> bool:
        """Shortcut to get if the device status is up."""
        ld = self._device_json.get(CONST.LAST_DISCONNECTED, datetime(1970, 1, 1))
        lc = self._device_json.get(CONST.LAST_CONNECTED, datetime(1970, 1, 1))

        return lc > ld

    @property
    def last_connected(self) -> datetime | None:
        """Get last connected timestamp."""
        if (tss := self._device_json.get(CONST.LAST_CONNECTED, None)) is not None:
            try:
                ts = datetime.fromisoformat(tss)
            except ValueError:
                ts = None
        else:
            ts = None
        return ts

    @property
    def last_disconnected(self) -> datetime | None:
        """Get last connected timestamp."""
        if (tss := self._device_json.get(CONST.LAST_DISCONNECTED, None)) is not None:
            try:
                ts = datetime.fromisoformat(tss)
            except ValueError:
                ts = None
        else:
            ts = None
        return ts

    @property
    def last_seen(self) -> datetime | None:
        """Get last checkin timestamp.

        If not availalbe return the last connected.
        """
        telemetry = self._device_json.get(CONST.DEVICE_TELEMETRY, {})
        tss = telemetry.get(CONST.DEVICE_LAST_SEEN, None)
        ts = None
        if tss is None:
            ts = self.last_connected
        if ts is None:
            try:
                ts = datetime.fromisoformat(tss)
            except ValueError:
                ts = None
        return ts

    @property
    def latest_doorbell_event_time(self) -> datetime | None:
        """Get latest doorbell event."""
        if act := self.latest(event_type=CONST.DOORBELL_ACTIVITY):
            if (act_time := act.get(CONST.EVENT_TIME, None)) is not None:
                # Event time is a js unix format needs adapted to unix time.
                act_time = datetime.fromtimestamp(act_time / 1000, tz=timezone.utc)
        else:
            act_time = None
        return act_time

    @property
    def latest_local_doorbell_event_time(self) -> datetime | None:
        """Get latest local doorbell event."""
        event_time = self._local_events.get(CONST.BUTTON_PRESSED, None)
        return event_time

    @property
    def latest_livestream_event_time(self) -> datetime | None:
        """Get latest livestream event."""
        if act := self.latest(event_type=CONST.LIVESTREAM_ACTIVITY):
            if (act_time := act.get(CONST.EVENT_TIME, None)) is not None:
                # Event time is a js unix format needs adapted to unix time.
                act_time = datetime.fromtimestamp(act_time / 1000, tz=timezone.utc)
        else:
            act_time = None
        return act_time

    @property
    def latest_motion_event_time(self) -> datetime | None:
        """Get latest motion event."""
        if act := self.latest(event_type=CONST.MOTION_ACTIVITY):
            if (act_time := act.get(CONST.EVENT_TIME, None)) is not None:
                # Event time is a js unix format needs adapted to unix time.
                act_time = datetime.fromtimestamp(act_time / 1000, tz=timezone.utc)
        else:
            act_time = None
        return act_time

    @property
    def latest_local_motion_event_time(self) -> datetime | None:
        """Get latest local doorbell event."""
        event_time = self._local_events.get(CONST.MOTION_DETECTION, None)
        return event_time

    @property
    def ip_address(self) -> str:
        """Get the IP address of the device."""
        telemetry = self._device_json.get(CONST.DEVICE_TELEMETRY, {})
        return telemetry.get(CONST.DEVICE_IPADDR, "")

    @property
    def wifi_link_quality(self) -> str:
        """Get the wifi link quality."""
        telemetry = self._device_json.get(CONST.DEVICE_TELEMETRY, {})
        return telemetry.get(CONST.WIFI_LINK_QUALITY, "")

    @property
    def wifi_signal_level(self) -> str:
        """Get the wifi signal level."""
        telemetry = self._device_json.get(CONST.DEVICE_TELEMETRY, {})
        return telemetry.get(CONST.WIFI_SIGNAL_LEVEL, "")

    @property
    def wifi_ssid(self) -> str:
        """Get the wifi ssid."""
        telemetry = self._device_json.get(CONST.DEVICE_TELEMETRY, {})
        if not (ssid := telemetry.get(CONST.WIFI_SSID, "")):
            device_settings = self._device_json.get(CONST.DEVICE_SETTINGS, {})
            ssid = device_settings.get(CONST.WIFI_ESSID, "")
        return ssid

    @property
    def location(self) -> dict:
        """Get devices location."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.TIMEZONE_INFO, {})

    @property
    def location_lat(self) -> float | None:
        """Get devices location latitude."""
        loc = self.location
        result = None
        if loc:
            result = loc[CONST.LOCATION_LAT]
        return result

    @property
    def location_lon(self) -> float | None:
        """Get devices location longitude."""
        loc = self.location
        result = None
        if loc:
            result = loc[CONST.LOCATION_LON]
        return result

    @property
    def location_place(self) -> str:
        """Get devices location place."""
        loc = self.location
        result = ""
        if loc:
            result = loc[CONST.LOCATION_PLACE]
        return result

    @property
    def button_pressed(self) -> bool:
        """Get the devices button pressed notification property."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.BUTTON_PRESSED)

    @property
    def indoor_chime(self) -> bool:
        """Get if the devices indoor chime is enabled."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.INDOOR_CHIME)

    @property
    def digital_chime(self) -> bool:
        """Get if the devices indoor digital chime is enabled."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.INDOOR_DIGITAL_CHIME)

    @property
    def outdoor_chime(self) -> bool:
        """Get if the devices outdoor chime is enabled."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.OUTDOOR_CHIME)

    @property
    def outdoor_chime_volume(self) -> int:
        """Get devices outdoor chime volume."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(
            settings_json.get(CONST.OUTDOOR_CHIME_VOLUME, CONST.OUTDOOR_CHIME_LOW)
        )

    @property
    def speaker_volume(self) -> int:
        """Get devices livestream volume."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(settings_json.get(CONST.SPEAKER_VOLUME, CONST.SPEAKER_VOLUME_LOW))

    @property
    def led_control(self) -> str:
        """Get devices LED Control."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.LED_CONTROL, "")

    @property
    def led_color(self) -> str:
        """Get devices LED color as red, green blue integers."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        hex_color = settings_json.get(CONST.LED_COLOR, "")
        return hex_color

    @property
    def normal_led_is_on(self) -> bool:
        """Get the devices normal led enablement property."""
        hex_color = ""
        if self.led_control == CONST.NORMAL_LED_CONTROL:
            settings_json = self._device_json.get(CONST.SETTINGS, {})
            hex_color = settings_json.get(CONST.LED_COLOR, "")
        return len(hex_color) > 0

    @property
    def image_quality(self) -> int:
        """Get devices livestream resolution."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(settings_json.get(CONST.IMAGE_QUALITY, CONST.IMAGE_QUALITY_LOW))

    @property
    def motion_detection(self) -> bool:
        """Get devices detection setting for triggering motion events.

        This will also enable recordings when motion events are detected
        if the corresponding record and notify events are enabled in basic
        motion or rules.
        """
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return bool(settings_json.get(CONST.MOTION_DETECTION, False))

    @property
    def debug_motion_detect(self) -> bool:
        """Get devices detection setting for oxes around detected motion."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return bool(settings_json.get(CONST.DEBUG_MOTION_DETECTION, False))

    @property
    def motion_sensitivity(self) -> int:
        """Get devices sensitivity in order to detect motion.

        Value 0 - Low, 1 - Medium, High - 2, 3-1000 .1% increment
        """
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(settings_json.get(CONST.MOTION_SENSITIVITY, 0))

    @property
    def hmbd_sensitivity(self) -> int:
        """Get devices sensitivity in order to detect human body.

        Value 0 - Low, 1 - Medium, High - 2, 3-1000 .1% increment
        Value USE_MOTION_SENSITIVITY - Tells device to use
        motion_sensitivy value.
        """
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(settings_json.get(CONST.MOTION_HMBD_SENSITIVITY, 0))

    @property
    def fd_sensitivity(self) -> int:
        """Get devices sensitivity in order to detect human face.

        Value 0 - Low, 1 - Medium, High - 2, 3-1000 .1% increment
        Value USE_MOTION_SENSITIVITY - Tells device to use
        motion_sensitivy value.
        """
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(settings_json.get(CONST.MOTION_FD_SENSITIVITY, 0))

    @property
    def pir_sensitivity(self) -> int:
        """Get devices passive infrared (pir) sensitivity.

        This hapeens when motion is detected.
        Value 0 - Low, 1 - Medium, High - 2, 3-1000 .1% increment
        """
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return int(settings_json.get(CONST.MOTION_PIR_SENSITIVITY, 0))

    @property
    def basic_motion(self) -> dict:
        """Get devices basic motion rules (recording, notification)."""
        settings_json = self._device_json.get(CONST.SETTINGS, {})
        return settings_json.get(CONST.BASIC_MOTION, {})

    @property
    def basic_motion_notify(self) -> bool | None:
        """Get devices basic motion notify."""
        bm = self.basic_motion
        result = None
        if bm:
            result = bm[CONST.BASIC_MOTION_NOTIFY]
        return result

    @property
    def basic_motion_record(self) -> bool | None:
        """Get devices basic motion record."""
        bm = self.basic_motion
        result = None
        if bm:
            result = bm[CONST.BASIC_MOTION_RECORD]
        return result

    @property
    def basic_motion_fd_notify(self) -> bool | None:
        """Get devices basic motion fd notify."""
        bm = self.basic_motion
        result = None
        if bm:
            result = bm[CONST.BASIC_MOTION_FD_NOTIFY]
        return result

    @property
    def basic_motion_fd_record(self) -> bool | None:
        """Get devices basic motion fd record."""
        bm = self.basic_motion
        result = None
        if bm:
            result = bm[CONST.BASIC_MOTION_FD_RECORD]
        return result

    @property
    def basic_motion_hbd_notify(self) -> bool | None:
        """Get devices basic motion hbd notify."""
        bm = self.basic_motion
        result = None
        if bm:
            result = bm[CONST.BASIC_MOTION_HBD_NOTIFY]
        return result

    @property
    def basic_motion_hbd_record(self) -> bool | None:
        """Get devices basic motion hbd record."""
        bm = self.basic_motion
        result = None
        if bm:
            result = bm[CONST.BASIC_MOTION_HBD_RECORD]
        return result
