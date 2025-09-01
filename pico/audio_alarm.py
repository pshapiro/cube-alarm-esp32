# audio_alarm.py — I2S alarm beeper for Pico W + MAX98357A
# Pins (per your wiring): BCLK=GP10, LRCLK=GP11, DIN=GP9
# Generates a continuous sine tone until stopped.

import math
import time
import _thread
import array

try:
    from machine import I2S, Pin
except ImportError:  # In case this port lacks I2S
    I2S = None
    Pin = None

class AudioAlarm:
    def __init__(self, bclk=10, lrclk=11, din=9, rate=22050, tone_hz=880,
                 mode='siren', f_lo=750, f_hi=1200, cycle_ms=700, frame_nsamp=512):
        self._i2s = None
        self._running = False
        self._buf = None
        self._rate = rate
        self._tone = tone_hz
        self._mode = mode or 'siren'
        self._f_lo = int(f_lo)
        self._f_hi = int(f_hi)
        self._cycle_ms = int(cycle_ms)
        # Streaming synth state
        self._tbl_len = 1024
        self._tbl_mask = self._tbl_len - 1
        self._tbl = None
        self._out = None
        self._frame_nsamp = max(128, int(frame_nsamp))
        self._phase = 0.0
        self._lfo_phase = 0.0
        self.ok = False
        if I2S is None or Pin is None:
            print("I2S not available on this firmware")
            return
        try:
            # id=0 is typical; adjust if needed
            self._i2s = I2S(
                0,
                sck=Pin(bclk),
                ws=Pin(lrclk),
                sd=Pin(din),
                mode=I2S.TX,
                bits=16,
                format=I2S.MONO,
                rate=self._rate,
                ibuf=20000,
            )
            # Build sine table and output buffer for streaming synthesis
            amp = 15000
            self._tbl = array.array('h', (0 for _ in range(self._tbl_len)))
            for i in range(self._tbl_len):
                self._tbl[i] = int(amp * math.sin(2 * math.pi * i / self._tbl_len))
            self._out = array.array('h', (0 for _ in range(self._frame_nsamp)))
            # Fallback static tone buffer for legacy pollers (not used in siren mode)
            self._buf = self._make_tone_chunk(self._rate, self._tone)
            self.ok = True
        except Exception as e:
            print("I2S init failed:", e)
            self.ok = False

    def _make_tone_chunk(self, rate, freq):
        # Build one cycle (or more) of a 16-bit mono sine wave and repeat for a decent chunk
        import array
        length = max(32, rate // freq)
        amp = 16000  # 50% of full scale to avoid clipping
        s = array.array('h', (0 for _ in range(length)))
        for i in range(length):
            s[i] = int(amp * math.sin(2 * math.pi * i / length))
        tobytes = getattr(s, 'tobytes', None)
        chunk = tobytes() if tobytes else bytes(s)
        # Repeat to reduce Python call overhead
        return chunk * 8  # ~8 cycles per write

    def start(self):
        if not self.ok or self._running:
            return
        # Polled mode: main loop calls poll() frequently
        self._running = True

    def poll(self):
        if not self.ok or not self._running:
            return
        # Streaming synthesis: fill a small frame and write
        try:
            # LFO increment per sample (triangle 0..1..0 over cycle_ms)
            total_lfo_samp = max(1, int(self._rate * max(200, self._cycle_ms) / 1000))
            lfo_inc = 1.0 / total_lfo_samp
            for i in range(self._frame_nsamp):
                # Triangle LFO
                p = self._lfo_phase
                tri = 1.0 - abs(2.0 * p - 1.0)
                if self._mode == 'siren':
                    freq = self._f_lo + tri * (self._f_hi - self._f_lo)
                else:
                    freq = self._tone
                inc = (self._tbl_len * freq) / self._rate
                idx = int(self._phase) & self._tbl_mask
                self._out[i] = self._tbl[idx]
                self._phase += inc
                if self._phase >= self._tbl_len:
                    self._phase -= self._tbl_len
                self._lfo_phase += lfo_inc
                if self._lfo_phase >= 1.0:
                    self._lfo_phase -= 1.0
            # Write directly from the array (supports buffer protocol)
            self._i2s.write(self._out)
        except Exception:
            time.sleep_ms(1)

    def _loop(self):
        # Continuously write the tone buffer
        while self._running:
            try:
                self._i2s.write(self._buf)
            except Exception:
                # Briefly yield if buffer not ready
                time.sleep_ms(1)
        # Optional short pause before exiting thread
        time.sleep_ms(2)

    def stop(self):
        if not self._running:
            return
        self._running = False
        # Allow loop to exit and drain a bit
        time.sleep_ms(10)

    def deinit(self):
        try:
            self.stop()
        finally:
            if self._i2s:
                try:
                    self._i2s.deinit()
                except Exception:
                    pass
                self._i2s = None
