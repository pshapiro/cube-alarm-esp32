# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""MicroPython alarm clock for the ESP32-2432S022C board.

This script demonstrates using the integrated touchscreen to display and
configure a simple clock with two alarms.  It also reports the connection
and scramble state of the cube.  When an alarm fires it plays a WAV file
through a MAX98357A I2S amplifier until the screen is touched.
"""

import uasyncio as asyncio
import machine
from display import TouchDisplay
from audio import ESP32AudioManager

ALARM_WAV = "alarm.wav"


class ClockApp:
    """Minimal touchscreen alarm clock."""

    def __init__(self) -> None:
        self.display = TouchDisplay()
        self.audio = ESP32AudioManager()
        self.rtc = machine.RTC()
        self.alarms = [None, None]  # each alarm is (hour, minute) or None
        self.cube_connected = False
        self.cube_scrambled = True
        self._last_alarm_minute = None

    # ------------------------------------------------------------------
    # Touch helpers

    async def set_time(self) -> None:
        dt = list(self.rtc.datetime())
        hour, minute = dt[4], dt[5]
        while True:
            self.display.show_set_screen("Time", hour, minute)
            touch = self.display.get_touch()
            if touch:
                x, y = touch
                if y > 260:  # bottom area saves
                    dt[4], dt[5] = hour, minute
                    self.rtc.datetime(tuple(dt))
                    return
                elif x < 120:
                    hour = (hour + 1) % 24
                else:
                    minute = (minute + 1) % 60
            await asyncio.sleep(0.2)

    async def set_alarm(self, idx: int) -> None:
        hour, minute = self.alarms[idx] or (0, 0)
        while True:
            self.display.show_set_screen(f"Alarm {idx + 1}", hour, minute)
            touch = self.display.get_touch()
            if touch:
                x, y = touch
                if y > 260:
                    self.alarms[idx] = (hour, minute)
                    return
                elif x < 120:
                    hour = (hour + 1) % 24
                else:
                    minute = (minute + 1) % 60
            await asyncio.sleep(0.2)

    async def alarm_task(self) -> None:
        self.display.fill(0)
        self.display.text("Solve cube to stop!", 10, 150)
        self.audio.start_alarm(ALARM_WAV)
        try:
            while True:
                if self.display.get_touch():
                    break
                await asyncio.sleep(0.1)
        finally:
            self.audio.stop_alarm()

    # ------------------------------------------------------------------

    async def run(self) -> None:
        while True:
            now = self.rtc.datetime()
            self.display.show_home(
                now, self.alarms, self.cube_connected, self.cube_scrambled
            )

            touch = self.display.get_touch()
            if touch:
                x, y = touch
                if y < 80:
                    await self.set_time()
                elif x < 120:
                    await self.set_alarm(0)
                else:
                    await self.set_alarm(1)

            # Check alarms once per loop
            for alarm in self.alarms:
                if not alarm:
                    continue
                ah, am = alarm
                if (
                    now[4] == ah
                    and now[5] == am
                    and self._last_alarm_minute != now[5]
                ):
                    await self.alarm_task()
                    self._last_alarm_minute = now[5]

            await asyncio.sleep(1)

    def deinit(self) -> None:
        self.audio.deinit()


async def _main() -> None:
    app = ClockApp()
    try:
        await app.run()
    finally:
        app.deinit()


asyncio.run(_main())

