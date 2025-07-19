"""aioskybellgen utility methods."""

from __future__ import annotations

from datetime import datetime, timedelta
import pickle
from typing import Any

import aiofiles

from .helpers.models import DeviceType


async def async_save_cache(
    data: dict[str, str | dict[str, DeviceType]],
    filename: str,
) -> None:
    """Save cache from file."""
    async with aiofiles.open(filename, "wb") as file:
        pickled_foo = pickle.dumps(data)
        await file.write(pickled_foo)


async def async_load_cache(
    filename: str,
) -> dict[str, str | dict[str, dict[str, dict[str, dict[str, str]]]]]:
    """Load cache from file."""
    async with aiofiles.open(filename, "rb") as file:
        pickled_foo = await file.read()

    return pickle.loads(pickled_foo)


def calculate_expiration(expires_in: int, slack: int, refresh_cycle: int) -> datetime:
    """Calculate the expiration datetime."""
    adj_expires_in = expires_in - slack
    if adj_expires_in <= refresh_cycle:
        adj_expires_in = expires_in
    expires = datetime.now() + timedelta(seconds=adj_expires_in)

    return expires


def update(
    dct: dict[str, Any],
    dct_merge: dict[str, Any],
) -> dict[str, Any]:
    """Recursively merge dicts."""
    if not isinstance(dct, dict):
        return dct
    for key, value in dct_merge.items():
        if key in dct and isinstance(dct[key], dict):
            dct[key] = update(dct[key], value)
        else:
            dct[key] = value
    return dct
