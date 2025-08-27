"""Models for Skybell."""

from __future__ import annotations

from typing import Any

class TriggerData(dict):
    """Class for Webhook trigger associated with the device.
    
    See /api/v5/devices/DEVICE_ID/triggers.
    """

    trigger_id: str
    device_id: str
    account_id: str
    client_id: str
    type: str
    enabled: bool
    on_events: list[str]
    fail_count: int
    created_at: str
    updated_at: str
    disabled_on: str | None
    disabled_reason: str | None

class TimezoneData(dict):
    """Class for Timezone settings permitted for the device.

    See /api/v5/devices/DEVICE_ID/settings.
    """

    place: str | None
    mapLat: float | None
    mapLong: float | None


class BasicMotionData(dict):
    """Class for Basic Motion settings permitted for the device.

    See /api/v5/devices/DEVICE_ID/settings.
    """

    fd_notify: bool
    fd_record: bool
    hbd_notify: bool
    hbd_record: bool
    motion_notify: bool
    motion_record: bool


class SettingsData(dict):
    """Class for update settings permitted for the device.

    See /api/v5/devices/DEVICE_ID/settings.
    """

    device_name: str | None
    button_pressed: bool | None
    led_color: str | None
    led_control: str | None
    indoor_chime: bool | None
    digital_chime: bool | None
    outdoor_chime: bool | None
    outdoor_chime_volume: int | None
    speaker_volume: str | None
    motion_detection: bool | None
    debug_motion_detect: bool | None
    motion_sensitivity: int | None
    hmbd_sensitivity: int | None
    fd_sensitivity: int | None
    pir_sensitivity: int | None
    image_quality: int | None
    basic_motion: BasicMotionData | None
    time_zone_info: TimezoneData | None


class DeviceSettingsData(dict):
    """Class for device_settings in a retrieved device.

    See /api/v5/devices/DEVICE_ID.
    """

    essid: str
    model_rev: str
    mac_address: str
    serial_number: str
    firmware_patch: str
    firmware_version: str
    firmare_major_release: str


class TelemetryData(dict):
    """Class for telemetry in a retrieved device.

    See /api/v5/devices/DEVICE_ID.
    """

    wifi_noise: str
    link_quality: str
    signal_level: str
    last_seen: str
    ip_address: str


class SnapshotData(dict):
    """Class for the device snapshot (avatar).

    See /api/v5/devices/DEVICE_ID.
    """

    date_time: str
    preview: str


class DeviceData(dict):
    """Class for device.

    See /api/v5/devices/DEVICE_ID.
    """

    device_id: str
    client_id: str
    account_id: str
    certificate_id: str
    invite_token: str
    last_event: str
    last_connected: str
    last_disconnected: str
    name: str
    created_at: str
    updated_at: str
    device_settings: DeviceSettingsData
    telemetry: TelemetryData
    settings: SettingsData


class ActivityData(dict):
    """Class for an activity (event).

    See /api/v5/activities.
    """

    event_time: int
    account_id: str
    device_id: str
    device_name: str
    activity_id: str
    event_type: str
    date: str
    video_url: str
    video_ready: bool
    image: bytes | None
    edge_tags: list
    ai_ppe: str | None
    created_at: str
    video_size: int
    video_ready_time: str


TriggerType = list[TriggerData]
LiveStreamConnectionData = dict[str, Any]
ActivityType = dict[str, ActivityData]
DeviceType = dict[str, dict[str, ActivityType] | dict[str, TriggerType]]
DevicesDict = dict[str, DeviceType]
