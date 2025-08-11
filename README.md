# aioskybellgen
_Asynchronous python communication driver for Skybell Cloud APIs_

![python version](https://img.shields.io/badge/Python->=3.11-blue.svg)
[![PyPI](https://img.shields.io/pypi/v/aioskybellgen)](https://pypi.org/project/aioskybellgen)

## Installation

```bash
python3 -m pip install aioskybellgen
```

## Example usage

More examples can be found in the `tests` directory.

```python
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
```

## Contribute

**All** contributions are welcome!

1. Fork the repository
2. Clone the repository locally and open the devcontainer or use GitHub codespaces
3. Do your changes
4. Lint the files with `make lint`
5. Ensure all tests passes with `make test`
6. Ensure 100% coverage with `make coverage`
7. Commit your work, and push it to GitHub
8. Create a PR against the `develop` branch