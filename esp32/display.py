# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""Display and touch helpers for the ESP32-2432S022C board.

The board integrates a 2.2" 240x320 ST7789 TFT driven over SPI and a
capacitive touch controller.  This module provides minimal wrappers
around commonly used MicroPython drivers for drawing text and reading
touch coordinates.
"""

from machine import Pin, SPI, I2C
import st7789

try:
    import ft6x36  # driver for FT6x36/FT6336 capacitive touch IC
except ImportError:  # pragma: no cover - optional dependency
    ft6x36 = None


class TouchDisplay:
    """Helper class combining TFT screen and touch controller."""

    def __init__(self, rotation: int = 1):
        # SPI configuration for the ST7789 display
        spi = SPI(
            2,
            baudrate=60_000_000,
            sck=Pin(18),
            mosi=Pin(23),
            miso=Pin(19),
        )
        self.tft = st7789.ST7789(
            spi,
            240,
            320,
            reset=Pin(12, Pin.OUT),
            cs=Pin(5, Pin.OUT),
            dc=Pin(16, Pin.OUT),
            backlight=Pin(4, Pin.OUT),
            rotation=rotation,
        )
        self.tft.init()

        # Optional capacitive touch controller over I2C
        self._touch = None
        if ft6x36 is not None:
            i2c = I2C(0, sda=Pin(21), scl=Pin(22))
            self._touch = ft6x36.FT6x36(i2c)

    def fill(self, color: int) -> None:
        self.tft.fill(color)

    def text(self, msg: str, x: int = 0, y: int = 0, color: int = st7789.WHITE) -> None:
        self.tft.text(msg, x, y, color)

    def get_touch(self):
        """Return the current touch coordinates or ``None`` if untouched."""
        if self._touch and self._touch.touched:
            return self._touch.get_point()
        return None

    # ------------------------------------------------------------------
    # High level helpers used by ``main.py``

    def show_home(self, now, alarms, connected: bool, scrambled: bool) -> None:
        """Render the home screen with time, alarms and cube status."""
        self.fill(st7789.BLACK)

        hour, minute = now[4], now[5]
        self.text(f"Time {hour:02d}:{minute:02d}", 10, 10)

        for idx, alarm in enumerate(alarms):
            if alarm:
                ah, am = alarm
                msg = f"A{idx+1} {ah:02d}:{am:02d}"
            else:
                msg = f"A{idx+1} --:--"
            self.text(msg, 10, 30 + idx * 20)

        status = "Connected" if connected else "No Cube"
        cube_state = "Scrambled" if scrambled else "Solved"
        self.text(f"Cube: {status}", 10, 80)
        self.text(cube_state, 10, 100)
        self.text("Tap time or alarm to edit", 10, 140)

    def show_set_screen(self, label: str, hour: int, minute: int) -> None:
        """Display a simple time adjustment screen."""
        self.fill(st7789.BLACK)
        self.text(f"Set {label}", 10, 10)
        self.text(f"{hour:02d}:{minute:02d}", 80, 120)
        self.text("L:+hour R:+min", 10, 200)
        self.text("Bottom=save", 10, 220)
