# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""ESP32 Audio Manager using MAX98357A I2S amplifier.

This module provides a lightweight audio playback helper intended for
MicroPython running on the ESP32-2432S022C board.  It streams 16-bit
mono WAV files over I2S to a connected MAX98357A DAC.

The pin assignments match the default wiring on the board but can be
customised when instantiating :class:`ESP32AudioManager`.
"""

from machine import I2S, Pin
import uasyncio as asyncio

class ESP32AudioManager:
    """Simple audio playback helper for I2S DACs."""

    def __init__(self, sck: Pin = Pin(14), ws: Pin = Pin(15), sd: Pin = Pin(32)):
        # Configure I2S for transmitting 16-bit mono samples at 44.1kHz
        self.i2s = I2S(
            0,
            sck=sck,
            ws=ws,
            sd=sd,
            mode=I2S.TX,
            bits=16,
            format=I2S.MONO,
            rate=44_100,
            ibuf=20_000,
        )
        self._task = None

    def _play_wav(self, path: str) -> None:
        """Stream a WAV file to the DAC once."""
        with open(path, "rb") as wav:
            # Skip WAV header (44 bytes) – assumes PCM little-endian
            wav.seek(44)
            while True:
                data = wav.read(1024)
                if not data:
                    break
                self.i2s.write(data)

    async def _loop(self, path: str) -> None:
        """Continuously play ``path`` until cancelled."""
        try:
            while True:
                self._play_wav(path)
                await asyncio.sleep(0)
        finally:
            # Ensure the DAC is quiet when the task is cancelled
            silence = b"\x00\x00" * 256
            self.i2s.write(silence)

    def start_alarm(self, path: str = "alarm.wav") -> None:
        """Start looping the given WAV file."""
        if self._task is None:
            loop = asyncio.get_event_loop()
            self._task = loop.create_task(self._loop(path))

    def stop_alarm(self) -> None:
        """Stop audio playback."""
        if self._task:
            self._task.cancel()
            self._task = None

    def deinit(self) -> None:
        """Release the I2S peripheral."""
        self.stop_alarm()
        self.i2s.deinit()
