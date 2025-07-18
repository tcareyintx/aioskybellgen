"""Example usage of aioskybellgen."""

import asyncio

from aioskybellgen import Skybell
from aioskybellgen.helpers import const as CONST

USER_NAME = "username"
PASSWORD = "password"


async def async_example():
    """Provide an example usage of aioskybellgen."""
    # Sign on to Skybell API
    async with Skybell(
        username=USER_NAME, password=PASSWORD, get_devices=True
    ) as client:
        # Update the user and session cache
        await client.async_update_cache({CONST.ACCESS_TOKEN: ""})
        # Get the initial set of devices without events and activities
        devices = await client.async_initialize()
        for device in devices:
            # Update/refresh the activities and events
            await device.async_update()
            print(f"Device: {device.device_id}, Status: {device.status}")


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(async_example())
except KeyboardInterrupt:
    pass
