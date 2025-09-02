# main.py — Pico W BLE central for GAN cube
# Requires gan_mpy.py with: derive_key_iv_from_mac(mac_str) and decrypt_packet(cipher_bytes, key, iv)

try:
    import ubluetooth as bluetooth
except ImportError:
    import bluetooth
import time
import _thread
try:
    import framebuf
except ImportError:  # pragma: no cover - environment without framebuf
    framebuf = None
from micropython import const
from machine import Pin, I2C, RTC
import ssd1306
from gan_mpy import derive_key_iv_from_mac, decrypt_packet, encrypt_packet
from audio_alarm import AudioAlarm

# --- Config ------------------------------------------------------------------

SCAN_MS     = const(10000)  # 10 s active scan
KNOWN_MAC   = "CF:AA:79:C9:96:9C"  # <- your cube's public MAC (normal big‑endian)
DEBUG_SCAN  = const(0)
DEBUG_SCAN_RATE_MS = const(200)  # throttle when DEBUG_SCAN is enabled
BTN_LONG_MS = const(1200)  # long-press threshold for manual alarm stop
ALARM_PREP_SEC = const(10)  # start cube polling this many seconds before alarm

# GAN Gen3 UUIDs
SERVICE_UUID = bluetooth.UUID('8653000a-43e6-47b7-9cb0-5fc21d4ae340')
STATE_UUID   = bluetooth.UUID('8653000b-43e6-47b7-9cb0-5fc21d4ae340')
CMD_UUID     = bluetooth.UUID('8653000c-43e6-47b7-9cb0-5fc21d4ae340')

# Resolve event constants (fallback to documented numeric values if missing)
_IRQ_SCAN_RESULT                  = getattr(bluetooth, "_IRQ_SCAN_RESULT", const(5))
_IRQ_SCAN_DONE                    = getattr(bluetooth, "_IRQ_SCAN_DONE", const(6))
_IRQ_PERIPHERAL_CONNECT           = getattr(bluetooth, "_IRQ_PERIPHERAL_CONNECT", const(7))
_IRQ_PERIPHERAL_DISCONNECT        = getattr(bluetooth, "_IRQ_PERIPHERAL_DISCONNECT", const(8))
_IRQ_GATTC_SERVICE_RESULT         = getattr(bluetooth, "_IRQ_GATTC_SERVICE_RESULT", const(9))
_IRQ_GATTC_SERVICE_DONE           = getattr(bluetooth, "_IRQ_GATTC_SERVICE_DONE", const(10))
_IRQ_GATTC_CHARACTERISTIC_RESULT  = getattr(bluetooth, "_IRQ_GATTC_CHARACTERISTIC_RESULT", const(11))
_IRQ_GATTC_CHARACTERISTIC_DONE    = getattr(bluetooth, "_IRQ_GATTC_CHARACTERISTIC_DONE", const(12))
_IRQ_GATTC_NOTIFY                 = getattr(bluetooth, "_IRQ_GATTC_NOTIFY", const(18))
_IRQ_GATTC_INDICATE               = getattr(bluetooth, "_IRQ_GATTC_INDICATE", const(20))
FLAG_NOTIFY                       = getattr(bluetooth, "FLAG_NOTIFY", const(0x10))
FLAG_INDICATE                     = getattr(bluetooth, "FLAG_INDICATE", const(0x20))

# --- Globals -----------------------------------------------------------------

ble = None  # created and activated inside run()

_key = None
_iv  = None
_rx_buf = b""

# Discovery state
_svc_ranges = []      # [(start, end)]
_char_queue = []      # [(start, end)] yet to process
_notify_handles = []  # value handles with NOTIFY
_notify_queue = []     # queued (conn, vh, bytes) notifications to process in main loop
_notify_drop_count = 0
_cccd_queue = []       # value handles whose CCCD needs enabling (processed in main loop)
_conn = None
_connecting = False
_audio = None
_alarm_on = False
_alarm_time = None  # (hour, minute)
_polling = False    # whether cube polling is active
_mode = 'normal'    # button UI mode
_char_discover_in_progress = False  # legacy var, not used in reverted flow
_char_discover_start_ms = 0         # legacy var, not used in reverted flow
_char_discover_item = None          # legacy var, not used in reverted flow
_service_discover_in_progress = False
_service_discover_start_ms = 0
_service_discover_pending = False
_discovery_complete_pending = False
_ble_next_ok_ms = 0
_initial_facelets_pending = False
_state_cccd_enabled = False
_initial_facelets_deadline_ms = 0

# GAN characteristic handles
_cmd_handle = None
_state_handle = None
_did_send_initial_facelets = False
_first_facelets_wr_mode0 = False

# Deferred command retry (handled in UI loop, not inside BLE IRQ)
_facelets_retry_count = 0
_facelets_retry_next_ms = 0

# Rate limiting for facelets polling after moves (ms)
_facelets_rate_next_ms = 0
# Enable detailed facelets debugging logs
_DBG_FACELETS = False
# Throttle for scan debug prints
_scan_dbg_next_ms = 0

# Packet debug printing (throttled)
_DBG_PACKETS = False
_pkt_dbg_next_ms = 0
_last_solved = None
_last_facelets_serial = -1
_last_facelets_ms = 0
_last_write_ealready = False

# Facelets mapping (URFDLB order) for optional facelets string output
_FACES_ORDER = "URFDLB"
_CORNER_FACELET_MAP = [
    (8, 9, 20),   # URF
    (6, 18, 38),  # UFL
    (0, 36, 47),  # ULB
    (2, 45, 11),  # UBR
    (29, 26, 15), # DFR
    (27, 44, 24), # DLF
    (33, 53, 42), # DBL
    (35, 17, 51), # DRB
]
_EDGE_FACELET_MAP = [
    (5, 10),   # UR
    (7, 19),   # UF
    (3, 37),   # UL
    (1, 46),   # UB
    (32, 16),  # DR
    (28, 25),  # DF
    (30, 43),  # DL
    (34, 52),  # DB
    (23, 12),  # FR
    (21, 41),  # FL
    (50, 39),  # BL
    (48, 14),  # BR
]

# Kociemba solved facelets string (backend parity)
_SOLVED_FACELETS = "UUUUUUUUURRRRRRRRRFFFFFFFFFDDDDDDDDDLLLLLLLLLBBBBBBBBB"

def _to_kociemba_facelets(cp, co, ep, eo):
    try:
        facelets = [ _FACES_ORDER[i // 9] for i in range(54) ]
        for i in range(8):
            for p in range(3):
                facelet_idx = _CORNER_FACELET_MAP[i][(p + co[i]) % 3]
                corner_face_idx = _CORNER_FACELET_MAP[cp[i]][p] // 9
                facelets[facelet_idx] = _FACES_ORDER[corner_face_idx]
        for i in range(12):
            for p in range(2):
                facelet_idx = _EDGE_FACELET_MAP[i][(p + eo[i]) % 2]
                edge_face_idx = _EDGE_FACELET_MAP[ep[i]][p] // 9
                facelets[facelet_idx] = _FACES_ORDER[edge_face_idx]
        return ''.join(facelets)
    except Exception:
        return None

# OLED UI (128x32 I2C1 GP2/GP3)
_oled = None
_ui_line1 = ""
_ui_line2 = ""
_ui_dirty = False
_ui_thread_running = False
_buttons_thread_running = False
_btn_a = None
_btn_b = None
_ui_last_sec = -1
_btn_a_last = 1
_btn_b_last = 1
_btn_a_press_ms = 0
_btn_b_press_ms = 0
_btn_a_next_ok_ms = 0
_btn_b_next_ok_ms = 0

def _ui_text(line1="", line2=""):
    # Only mark desired UI state; actual drawing happens in background thread
    global _ui_line1, _ui_line2, _ui_dirty
    _ui_line1 = line1 or ""
    _ui_line2 = line2 or ""
    _ui_dirty = True


def _draw_text_big(fb, text, x, y, scale=2):
    """Render scaled text. Falls back to normal size if framebuf missing."""
    if framebuf is None:
        fb.text(text, x, y, 1)
        return

    buf = framebuf.FrameBuffer(bytearray(8 * 8), 8, 8, framebuf.MONO_VLSB)
    for i, ch in enumerate(text):
        buf.fill(0)
        buf.text(ch, 0, 0, 1)
        for yy in range(8):
            for xx in range(8):
                if buf.pixel(xx, yy):
                    fb.fill_rect(
                        x + i * 8 * scale + xx * scale,
                        y + yy * scale,
                        scale,
                        scale,
                        1,
                    )

def _ui_draw(now_tuple=None):
    if _oled is None:
        return
    try:
        if now_tuple is None:
            now_tuple = time.localtime()
        hh, mm = now_tuple[3], now_tuple[4]
        ampm = "AM" if hh < 12 else "PM"
        hh = hh % 12
        if hh == 0:
            hh = 12
        t = "%d:%02d" % (hh, mm)
        _oled.fill(0)
        _draw_text_big(_oled, t, 0, 0, 3)
        _oled.text(ampm, 128 - len(ampm) * 8, 24)
        _oled.show()
    except Exception as e:
        # Avoid crashing UI loop on transient I2C errors
        print("OLED draw err:", e)

def _ui_loop():
    global _ui_dirty, _ui_thread_running, _btn_a_last, _btn_b_last, _btn_a_next_ok_ms, _btn_b_next_ok_ms, _facelets_retry_count, _facelets_retry_next_ms, _alarm_on, _btn_b_press_ms, _last_write_ealready
    last_sec = -1
    while _ui_thread_running:
        try:
            # 1) UI refresh once per second or when marked dirty
            now = time.localtime()
            if (now[5] != last_sec) or _ui_dirty:
                _ui_draw(now)
                _ui_dirty = False
                last_sec = now[5]

            # 2) Poll buttons (falling-edge on pull-ups)
            now_ms = time.ticks_ms()
            if _btn_a is not None:
                a = _btn_a.value()
                if _btn_a_last == 1 and a == 0 and time.ticks_diff(now_ms, _btn_a_next_ok_ms) >= 0:
                    send_request_facelets()
                    _btn_a_next_ok_ms = time.ticks_add(now_ms, 200)
                _btn_a_last = a
            if _btn_b is not None:
                b = _btn_b.value()
                if _btn_b_last == 1 and b == 0:
                    _btn_b_press_ms = now_ms
                elif _btn_b_last == 0 and b == 1:
                    dur = time.ticks_diff(now_ms, _btn_b_press_ms) if _btn_b_press_ms else 0
                    if dur >= BTN_LONG_MS:
                        # Long press: stop alarm
                        if _alarm_on and _audio:
                            try:
                                _audio.stop()
                            except Exception:
                                pass
                            _alarm_on = False
                            _ui_text("Alarm off", "")
                    else:
                        # Short press: reset cube
                        if time.ticks_diff(now_ms, _btn_b_next_ok_ms) >= 0:
                            send_request_reset()
                            try:
                                _btn_b_next_ok_ms = time.ticks_add(now_ms, 200)
                            except Exception:
                                _btn_b_next_ok_ms = now_ms + 200
                    _btn_b_press_ms = 0
                _btn_b_last = b

            # 3) Service audio alarm in polled mode
            if _alarm_on and _audio:
                try:
                    _audio.poll()
                except Exception:
                    pass
            # 4) Deferred facelets write retries (avoid doing this inside BLE IRQ)
            if (_conn is not None) and (_cmd_handle is not None) and (_facelets_retry_count > 0):
                if time.ticks_diff(now_ms, _facelets_retry_next_ms) >= 0:
                    ok = send_request_facelets()
                    delay = 200
                    try:
                        if (not ok) and _last_write_ealready:
                            delay = 60
                        else:
                            _facelets_retry_count -= 1
                    except Exception:
                        _facelets_retry_count -= 1
                    _facelets_retry_next_ms = time.ticks_add(now_ms, delay)
                    try:
                        print("Facelets retry ->", ok, "remaining", _facelets_retry_count)
                    except Exception:
                        pass
                    _last_write_ealready = False
        except Exception:
            pass
        # Tight-ish loop to keep audio fed and buttons responsive
        time.sleep_ms(5)

def _ui_init():
    global _oled, _ui_thread_running
    try:
        i2c = I2C(1, sda=Pin(2), scl=Pin(3), freq=100000)
        _oled = ssd1306.SSD1306_I2C(128, 32, i2c, addr=0x3C)
        _ui_text("Ready", "Set alarm")
    except Exception as e:
        print("OLED init failed:", e)
        _oled = None
    # Skip background UI thread to avoid core1 conflicts
    print("UI: Skipping thread to avoid core1 conflicts")

def _buttons_init():
    global _btn_a, _btn_b, _btn_a_last, _btn_b_last, _buttons_thread_running, _btn_a_press_ms, _btn_b_press_ms
    try:
        _btn_a = Pin(14, Pin.IN, Pin.PULL_UP)
        _btn_b = Pin(15, Pin.IN, Pin.PULL_UP)
        _btn_a_last = _btn_a.value()
        _btn_b_last = _btn_b.value()
        _btn_a_press_ms = 0
        _btn_b_press_ms = 0
        # No separate button thread; buttons are polled in _ui_loop to avoid core1 contention
    except Exception as e:
        print("Buttons init failed:", e)
        _btn_a = None
        _btn_b = None

def _fmt_hm(h, m):
    return "%02d:%02d" % (h, m)


def _rtc():
    try:
        return RTC()
    except Exception:
        return None


def _inc_time_hour():
    rtc = _rtc()
    if rtc:
        dt = list(rtc.datetime())
        dt[4] = (dt[4] + 1) % 24
        rtc.datetime(tuple(dt))
        _ui_text("Set time", _fmt_hm(dt[4], dt[5]))


def _inc_time_minute():
    rtc = _rtc()
    if rtc:
        dt = list(rtc.datetime())
        dt[5] = (dt[5] + 1) % 60
        rtc.datetime(tuple(dt))
        _ui_text("Set time", _fmt_hm(dt[4], dt[5]))


def _inc_alarm_hour():
    global _alarm_time
    if _alarm_time is None:
        _alarm_time = [0, 0]
    _alarm_time[0] = (_alarm_time[0] + 1) % 24
    _ui_text("Set alarm", _fmt_hm(_alarm_time[0], _alarm_time[1]))


def _inc_alarm_minute():
    global _alarm_time
    if _alarm_time is None:
        _alarm_time = [0, 0]
    _alarm_time[1] = (_alarm_time[1] + 1) % 60
    _ui_text("Set alarm", _fmt_hm(_alarm_time[0], _alarm_time[1]))


def set_time(h, m, s=0):
    rtc = _rtc()
    if rtc:
        dt = list(rtc.datetime())
        dt[4] = int(h) % 24
        dt[5] = int(m) % 60
        dt[6] = int(s) % 60
        rtc.datetime(tuple(dt))
        _ui_text("Time set", _fmt_hm(dt[4], dt[5]))


def set_alarm(h, m):
    global _alarm_time
    _alarm_time = [int(h) % 24, int(m) % 60]
    _ui_text("Alarm set", _fmt_hm(_alarm_time[0], _alarm_time[1]))
    return tuple(_alarm_time)


def set_alarm_in(seconds):
    now = time.localtime()
    total = now[3] * 3600 + now[4] * 60 + now[5] + int(seconds)
    total %= 86400
    h = total // 3600
    m = (total % 3600) // 60
    return set_alarm(h, m)


def start_cube_polling():
    global _polling
    if ble is None or _polling:
        return
    try:
        ble.gap_scan(SCAN_MS, 30000, 30000, True)
        _polling = True
        print("Started scanning for cube")
        _ui_text("Scanning...", "Twist to wake")
    except Exception as e:
        print("scan start err:", e)


def stop_cube_polling():
    global _polling, _conn, _connecting
    if ble and _polling:
        try:
            ble.gap_scan(None)
        except Exception:
            pass
        _polling = False
    if ble and _conn is not None:
        try:
            ble.gap_disconnect(_conn)
        except Exception:
            pass
        _conn = None
    _connecting = False


def _poll_tick():
    """Single cooperative tick: UI draw, buttons, audio, and deferred facelets writes."""
    global _ui_dirty, _ui_last_sec, _btn_a_last, _btn_b_last, _btn_a_press_ms, _btn_b_press_ms, _alarm_on, _notify_queue
    global _facelets_retry_count, _facelets_retry_next_ms, _last_write_ealready
    global _cccd_queue, _initial_facelets_pending, _did_send_initial_facelets, _cmd_handle, _state_handle, _discovery_complete_pending, _state_cccd_enabled, _initial_facelets_deadline_ms
    global _first_facelets_wr_mode0
    global _ble_next_ok_ms, _alarm_time, _polling, _mode
    try:
        # UI draw once per second or when marked dirty
        now = time.localtime()
        if (now[5] != _ui_last_sec) or _ui_dirty:
            _ui_draw(now)
            _ui_dirty = False
            _ui_last_sec = now[5]

        # Buttons and alarm/time setting
        now_ms = time.ticks_ms()
        if _btn_a is not None:
            a = _btn_a.value()
            if _btn_a_last == 1 and a == 0:
                _btn_a_press_ms = now_ms
            elif _btn_a_last == 0 and a == 1:
                dur = time.ticks_diff(now_ms, _btn_a_press_ms) if _btn_a_press_ms else 0
                if dur >= BTN_LONG_MS:
                    if _mode == 'normal':
                        _mode = 'set_time'
                        rtc = _rtc()
                        if rtc:
                            dt = rtc.datetime()
                            _ui_text('Set time', _fmt_hm(dt[4], dt[5]))
                    elif _mode == 'set_time':
                        _mode = 'normal'
                        _ui_text('', '')
                    elif _mode == 'set_alarm':
                        _inc_alarm_hour()
                else:
                    if _mode == 'set_time':
                        _inc_time_hour()
                    elif _mode == 'set_alarm':
                        _inc_alarm_hour()
                _btn_a_press_ms = 0
            _btn_a_last = a
        if _btn_b is not None:
            b = _btn_b.value()
            if _btn_b_last == 1 and b == 0:
                _btn_b_press_ms = now_ms
            elif _btn_b_last == 0 and b == 1:
                dur = time.ticks_diff(now_ms, _btn_b_press_ms) if _btn_b_press_ms else 0
                if dur >= BTN_LONG_MS:
                    if _alarm_on and _audio:
                        try:
                            _audio.stop()
                        except Exception:
                            pass
                        _alarm_on = False
                        stop_cube_polling()
                        _ui_text('Alarm off', '')
                    elif _mode == 'normal':
                        _mode = 'set_alarm'
                        if _alarm_time is None:
                            hh, mm = 0, 0
                        else:
                            hh, mm = _alarm_time
                        _ui_text('Set alarm', _fmt_hm(hh, mm))
                    elif _mode == 'set_alarm':
                        _mode = 'normal'
                        _ui_text('', '')
                    elif _mode == 'set_time':
                        _inc_time_minute()
                else:
                    if _mode == 'set_time':
                        _inc_time_minute()
                    elif _mode == 'set_alarm':
                        _inc_alarm_minute()
                _btn_b_press_ms = 0
            _btn_b_last = b

        # Alarm scheduling
        if _alarm_time is not None:
            now_sec = now[3] * 3600 + now[4] * 60 + now[5]
            alarm_sec = _alarm_time[0] * 3600 + _alarm_time[1] * 60
            delta = (alarm_sec - now_sec) % 86400
            if (not _polling) and (delta <= ALARM_PREP_SEC):
                start_cube_polling()
            if (not _alarm_on) and delta == 0:
                if _audio and getattr(_audio, 'ok', False):
                    _audio.start()
                    _alarm_on = True
                    _ui_text('Alarm!', 'Twist to wake')

        # Service audio alarm
        if _alarm_on and _audio:
            try:
                _audio.poll()
            except Exception:
                pass

        # Print discovery-complete message from main loop to avoid IRQ prints
        if _discovery_complete_pending:
            try:
                print("Discovery complete (CMD+STATE found)")
            except Exception:
                pass
            _discovery_complete_pending = False

        # Enable up to 2 CCCDs per tick in main loop (respect BLE cooldown)
        # If initial facelets has been scheduled but not yet sent/succeeded, pause CCCD enabling
        cccd_processed = 0
        while _cccd_queue and cccd_processed < 2 and (_conn is not None):
            try:
                if _did_send_initial_facelets and (_facelets_retry_count > 0):
                    break
            except Exception:
                pass
            # Don't issue a CCCD write if we're still in the cooldown window
            try:
                if _ble_next_ok_ms and time.ticks_diff(now_ms, _ble_next_ok_ms) < 0:
                    break
            except Exception:
                pass
            try:
                vh = _cccd_queue.pop(0)
                _enable_notify(_conn, vh)
                if (_state_handle is not None) and (vh == _state_handle):
                    _state_cccd_enabled = True
            except Exception:
                pass
            cccd_processed += 1

        # Schedule initial facelets once, outside IRQ, after STATE CCCD is enabled (or after timeout)
        if _initial_facelets_pending and (_cmd_handle is not None) and (_state_handle is not None) and (not _did_send_initial_facelets):
            # Start a deadline if not set
            if _initial_facelets_deadline_ms == 0:
                try:
                    _initial_facelets_deadline_ms = time.ticks_add(now_ms, 1500)
                except Exception:
                    _initial_facelets_deadline_ms = now_ms + 1500
            # Proceed when CCCD enabled or deadline passed
            should_schedule = _state_cccd_enabled
            try:
                if not should_schedule and (_initial_facelets_deadline_ms != 0):
                    should_schedule = time.ticks_diff(now_ms, _initial_facelets_deadline_ms) >= 0
            except Exception:
                pass
            if should_schedule:
                _did_send_initial_facelets = True
                _initial_facelets_pending = False
                _initial_facelets_deadline_ms = 0
                # Ensure at least a couple retries
                try:
                    if _facelets_retry_count < 2:
                        _facelets_retry_count = 2
                except Exception:
                    pass
                # Force the very first facelets to use write-with-response once
                _first_facelets_wr_mode0 = True
                # Schedule immediately (actual target respects BLE cooldown)
                _schedule_facelets_poll(0)
                # Debug: show target/now/cooldown to investigate pauses
                try:
                    print("Initial facelets target:", _facelets_retry_next_ms, "now:", now_ms, "cooldown until:", _ble_next_ok_ms)
                except Exception:
                    pass
                try:
                    print("Initial facelets scheduled")
                except Exception:
                    pass

        # Drain a few queued notifications without starving audio
        if _notify_queue:
            try:
                start_ms = time.ticks_ms()
            except Exception:
                start_ms = 0
            processed = 0
            while _notify_queue and processed < 3:
                try:
                    conn_handle, value_handle, chunk = _notify_queue.pop(0)
                    _on_notify(conn_handle, value_handle, chunk)
                except Exception:
                    pass
                processed += 1
                try:
                    if start_ms and time.ticks_diff(time.ticks_ms(), start_ms) > 4:
                        break
                except Exception:
                    pass

        # Process deferred facelets write retries scheduled from IRQ
        if (_conn is not None) and (_cmd_handle is not None) and (_facelets_retry_count > 0):
            if time.ticks_diff(now_ms, _facelets_retry_next_ms) >= 0:
                # Respect BLE cooldown before attempting a write
                cooldown = False
                try:
                    if _ble_next_ok_ms and time.ticks_diff(now_ms, _ble_next_ok_ms) < 0:
                        try:
                            print("Cooldown wait:", now_ms, "->", _ble_next_ok_ms)
                        except Exception:
                            pass
                        _facelets_retry_next_ms = _ble_next_ok_ms
                        cooldown = True
                except Exception:
                    pass
                if not cooldown:
                    ok = send_request_facelets()
                    delay = 200
                    try:
                        if (not ok) and _last_write_ealready:
                            delay = 40
                        else:
                            _facelets_retry_count -= 1
                    except Exception:
                        _facelets_retry_count -= 1
                    _facelets_retry_next_ms = time.ticks_add(now_ms, delay)
                    try:
                        print("Facelets retry ->", ok, "remaining", _facelets_retry_count)
                    except Exception:
                        pass
                    _last_write_ealready = False
        # If we haven't seen a new facelets in a while, proactively poll once
        try:
            if (_conn is not None) and (_cmd_handle is not None):
                if (_last_facelets_ms == 0) or (time.ticks_diff(now_ms, _last_facelets_ms) > 1200):
                    # Defer via scheduler (respects BLE cooldown and rate limit)
                    _schedule_facelets_poll(0)
                    # avoid spamming; wait at least 800ms before next proactive poll
                    try:
                        _last_facelets_ms = time.ticks_add(now_ms, 800)
                    except Exception:
                        _last_facelets_ms = now_ms + 800
        except Exception:
            pass
        # No BLE op scheduling here in reverted flow; discovery/CCCD handled in IRQ
    except Exception:
        pass

def _bits_from_bytes(data):
    """Convert a bytes object to a string of bits (MicroPython compatible)."""
    bits = []
    for byte in data:
        s = bin(byte)[2:]
        bits.append('0' * (8 - len(s)) + s)
    return "".join(bits)

def get_bits(bit_string, start_bit, num_bits):
    """Extract `num_bits` from a `bit_string` starting at `start_bit`."""
    if num_bits == 0:
        return 0
    end_bit = start_bit + num_bits
    if end_bit > len(bit_string):
        return -1 # Indicate error
    return int(bit_string[start_bit:end_bit], 2)

def _bits_from_bytes_revbits(data):
    """Build bit string with per-byte bit order reversed (LSB-first within each byte)."""
    bits = []
    for byte in data:
        s = bin(byte)[2:]
        s = ('0' * (8 - len(s)) + s)
        bits.append(s[::-1])
    return "".join(bits)

def _reverse_bytes(data):
    try:
        return bytes(data[::-1])
    except Exception:
        # Fallback for memoryview
        b = bytes(data)
        return bytes([b[i] for i in range(len(b) - 1, -1, -1)])

def _swap_nibbles_bytes(data):
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        out[i] = ((byte & 0x0F) << 4) | ((byte & 0xF0) >> 4)
    return bytes(out)

def _rotl1_per_byte(data):
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        out[i] = ((byte << 1) & 0xFF) | ((byte >> 7) & 0x01)
    return bytes(out)

def _parse_facelets_arrays_from_bitstr(bit_string, base_shift_bits=0):
    """Parse CP/CO/EP/EO from a bit_string given a base bit shift.

    Returns (cp, co, ep, eo) if valid; otherwise returns None.
    Valid means:
      - CP is a permutation of 0..7
      - CO are all in 0..2
      - EP is a permutation of 0..11
      - EO are all in 0..1
    """
    # Compute field starts with shift applied
    cp_start = 40 + base_shift_bits
    co_start = 61 + base_shift_bits
    ep_start = 77 + base_shift_bits
    eo_start = 121 + base_shift_bits

    # Bounds check to avoid Python negative indexing surprises
    if cp_start < 0 or co_start < 0 or ep_start < 0 or eo_start < 0:
        return None
    if eo_start + 11 > len(bit_string):
        return None

    cp = []
    co = []
    ep = []
    eo = []

    # Extract raw fields
    for i in range(7):
        vcp = get_bits(bit_string, cp_start + i * 3, 3)
        vco = get_bits(bit_string, co_start + i * 2, 2)
        if vcp < 0 or vco < 0:
            return None
        cp.append(vcp)
        co.append(vco)

    for i in range(11):
        vep = get_bits(bit_string, ep_start + i * 4, 4)
        veo = get_bits(bit_string, eo_start + i, 1)
        if vep < 0 or veo < 0:
            return None
        ep.append(vep)
        eo.append(veo)

    # Derive last elements
    cp.append(28 - sum(cp))
    co.append((3 - (sum(co) % 3)) % 3)
    ep.append(66 - sum(ep))
    eo.append((2 - (sum(eo) % 2)) % 2)

    # Validate ranges and permutations
    if not (len(cp) == 8 and min(cp) >= 0 and max(cp) <= 7 and set(cp) == set(range(8))):
        return None
    if not (len(co) == 8 and all(0 <= x <= 2 for x in co)):
        return None
    if not (len(ep) == 12 and min(ep) >= 0 and max(ep) <= 11 and set(ep) == set(range(12))):
        return None
    if not (len(eo) == 12 and all(0 <= x <= 1 for x in eo)):
        return None

    return (cp, co, ep, eo)

def _parse_facelets_canonical(clear: bytes):
    """Canonical Gen3 facelets parse for headerless plaintext.

    Expects the 2-byte header 0x55 0x02 to be removed already, so
    `clear` should typically be 17 bytes (19 total minus 2-byte header).

    Uses backend bit positions with a -16 bit shift (header removed):
      CP start=24, CO start=45, EP start=61, EO start=105 (relative to headered).
    Returns (cp, co, ep, eo) if valid; otherwise returns None.
    """
    try:
        # 17 bytes of headerless data is sufficient
        if len(clear) < 17:
            return None
        bits = _bits_from_bytes(clear)  # MSB-first per byte
        return _parse_facelets_arrays_from_bitstr(bits, -16)
    except Exception:
        return None

def _parse_facelets_headered(clear: bytes):
    """Parse CP/CO/EP/EO from a headered (0x55 0x02 + 17B) facelets packet.

    Matches backend bit positions exactly: CP@40, CO@61, EP@77, EO@121.
    Returns (cp, co, ep, eo) if valid; otherwise None.
    """
    try:
        if len(clear) < 19 or clear[0] != 0x55 or clear[1] != 0x02:
            return None
        bits = _bits_from_bytes(clear)
        # Same extraction as backend (first 7/11 values, derive last)
        cp = []
        co = []
        ep = []
        eo = []
        for i in range(7):
            vcp = get_bits(bits, 40 + i * 3, 3)
            vco = get_bits(bits, 61 + i * 2, 2)
            if vcp < 0 or vco < 0:
                return None
            cp.append(vcp)
            co.append(vco)
        for i in range(11):
            vep = get_bits(bits, 77 + i * 4, 4)
            veo = get_bits(bits, 121 + i, 1)
            if vep < 0 or veo < 0:
                return None
            ep.append(vep)
            eo.append(veo)
        cp.append(28 - sum(cp))
        co.append((3 - (sum(co) % 3)) % 3)
        ep.append(66 - sum(ep))
        eo.append((2 - (sum(eo) % 2)) % 2)
        # Validate
        if not (len(cp) == 8 and set(cp) == set(range(8))):
            return None
        if not (len(co) == 8 and all(0 <= x <= 2 for x in co)):
            return None
        if not (len(ep) == 12 and set(ep) == set(range(12))):
            return None
        if not (len(eo) == 12 and all(0 <= x <= 1 for x in eo)):
            return None
        return (cp, co, ep, eo)
    except Exception:
        return None

def _parse_facelets_with_variants(clear: bytes):
    """Try multiple bit order/offset variants and return the first valid parse.

    Returns tuple: (cp, co, ep, eo, variant_label)
    If none validate, returns (None, None, None, None, label) where label describes attempts.
    """
    variants = []
    try:
        variants.append(("norm", _bits_from_bytes(clear)))
    except Exception:
        pass
    try:
        variants.append(("rev_bytes", _bits_from_bytes(_reverse_bytes(clear))))
    except Exception:
        pass
    try:
        variants.append(("rev_bits", _bits_from_bytes_revbits(clear)))
    except Exception:
        pass
    try:
        variants.append(("rev_bytes+rev_bits", _bits_from_bytes_revbits(_reverse_bytes(clear))))
    except Exception:
        pass
    try:
        variants.append(("swap_nibbles", _bits_from_bytes(_swap_nibbles_bytes(clear))))
    except Exception:
        pass
    try:
        variants.append(("rotl1_per_byte", _bits_from_bytes(_rotl1_per_byte(clear))))
    except Exception:
        pass
    try:
        variants.append(("rev_all_bits", _bits_from_bytes(clear)[::-1]))
    except Exception:
        pass

    # Base shifts to cover header/prefix stripping and small padding
    base_shifts = [-48, -40, -32, -24, -16, -8, 0, 8, 16, 24]

    # Small jitter search to account for off-by-few-bits misalignment
    jitters = [-4, -3, -2, -1, 0, 1, 2, 3, 4]

    for (label, bits) in variants:
        for base in base_shifts:
            for j in jitters:
                shift = base + j
                parsed = _parse_facelets_arrays_from_bitstr(bits, shift)
                if parsed:
                    return parsed[0], parsed[1], parsed[2], parsed[3], "%s shift=%d" % (label, shift)

    # As a last resort, return default (non-validated) parse to preserve prior behavior
    try:
        bits_default = _bits_from_bytes(clear)
        cp = []
        co = []
        ep = []
        eo = []
        for i in range(7):
            cp.append(get_bits(bits_default, 40 + i * 3, 3))
            co.append(get_bits(bits_default, 61 + i * 2, 2))
        for i in range(11):
            ep.append(get_bits(bits_default, 77 + i * 4, 4))
            eo.append(get_bits(bits_default, 121 + i, 1))
        cp.append(28 - sum(cp))
        co.append((3 - (sum(co) % 3)) % 3)
        ep.append(66 - sum(ep))
        eo.append((2 - (sum(eo) % 2)) % 2)
        return cp, co, ep, eo, "default-unaligned"
    except Exception:
        return None, None, None, None, "parse-failed"

def _is_solved_facelets(clear: bytes) -> bool:
    """Return True if a decrypted packet (with or without 0x55 0x02 header) is solved."""
    try:
        # If facelets header present, try headered parse first (matches backend exactly)
        if len(clear) >= 19 and clear[0] == 0x55 and clear[1] == 0x02:
            parsed = _parse_facelets_headered(clear)
            # Also prepare headerless body for fallback
            body = clear[2:]
        else:
            parsed = None
            body = clear

        # If headered parse failed, try canonical headerless (-16 bit shift)
        if (not parsed) and (len(body) >= 17):
            parsed = _parse_facelets_canonical(body)
        if parsed:
            cp, co, ep, eo = parsed
        else:
            # 2) Fallback to variant search
            cp, co, ep, eo, _ = _parse_facelets_with_variants(body if len(body) >= 17 else clear)
            if not cp:
                return False

        # Convert to facelets string and compare against canonical solved
        facelets = _to_kociemba_facelets(cp, co, ep, eo)
        if not facelets:
            return False
        return facelets == _SOLVED_FACELETS

    except Exception as e:
        try:
            print("DBG facelets error:", e)
        except Exception:
            pass
        return False

def _debug_facelets(clear: bytes):
    """Debug helper: print CP/CO/EP/EO arrays from compressed bit fields."""
    try:
        # Accept packets with GAN header and strip it if present
        if len(clear) >= 21 and clear[0] == 0x55 and clear[1] == 0x02:
            body = clear[2:]
        else:
            body = clear

        if len(body) < 19:
            return

        # Default parse (for comparison; backend positions with no shift)
        bits_default = _bits_from_bytes(body)
        cp_d = []
        co_d = []
        ep_d = []
        eo_d = []
        for i in range(7):
            cp_d.append(get_bits(bits_default, 40 + i * 3, 3))
            co_d.append(get_bits(bits_default, 61 + i * 2, 2))
        for i in range(11):
            ep_d.append(get_bits(bits_default, 77 + i * 4, 4))
            eo_d.append(get_bits(bits_default, 121 + i, 1))
        cp_d.append(28 - sum(cp_d))
        co_d.append((3 - (sum(co_d) % 3)) % 3)
        ep_d.append(66 - sum(ep_d))
        eo_d.append((2 - (sum(eo_d) % 2)) % 2)

        # Canonical headerless parse (preferred)
        parsed_canon = _parse_facelets_canonical(body)
        if parsed_canon:
            cp_c, co_c, ep_c, eo_c = parsed_canon
        else:
            cp_c = co_c = ep_c = eo_c = None

        # Variant search parse (validated)
        cp, co, ep, eo, label = _parse_facelets_with_variants(body)

        # Validity checks
        valid_cp = bool(cp and set(cp) == set(range(8)))
        valid_co = bool(co and all(0 <= x <= 2 for x in co))
        valid_ep = bool(ep and set(ep) == set(range(12)))
        valid_eo = bool(eo and all(0 <= x <= 1 for x in eo))

        print("--- FACELETS DEBUG ---")
        print("CLR:", len(body), ":", _hex(body))
        print("Default CP:", cp_d)
        print("Default CO:", co_d)
        print("Default EP:", ep_d)
        print("Default EO:", eo_d)
        if cp_c:
            print("Canon   CP:", cp_c)
            print("Canon   CO:", co_c)
            print("Canon   EP:", ep_c)
            print("Canon   EO:", eo_c)
        print("Variant:", label)
        if cp:
            print("Parsed  CP:", cp, "(valid:", valid_cp, ")")
            print("Parsed  CO:", co, "(valid:", valid_co, ")")
            print("Parsed  EP:", ep, "(valid:", valid_ep, ")")
            print("Parsed  EO:", eo, "(valid:", valid_eo, ")")
        print("----------------------")

    except Exception as e:
        try:
            print("DBG facelets error:", e)
        except Exception:
            pass

# Parse 0x55 0x02 16-byte move-variant packets with tail-reversal fallback
def _parse_move_variant02(clear: bytes):
    try:
        if len(clear) < 16 or clear[0] != 0x55 or clear[1] != 0x02:
            return None
        move_byte = clear[5]
        if move_byte > 0x0B:
            # Keep header/type, reverse the rest (backend fallback)
            rev = clear[0:2] + clear[:1:-1]
            move_byte = rev[5]
            if move_byte > 0x0B:
                return None
            clear = rev
        table = ["B","B'","F","F'","U","U'","D","D'","R","R'","L","L'"]
        move = table[move_byte]
        serial = int.from_bytes(clear[2:4], "little")
        return (move, serial)
    except Exception:
        return None

def _analyze_packet_type(clear):
    """Analyze packet to determine its type and content."""
    try:
        if len(clear) < 16:
            return f'TOO_SHORT: {len(clear)} bytes'

        # Check first two bytes
        if len(clear) >= 2:
            b0, b1 = clear[0], clear[1]

            if b0 == 0x55:
                if b1 == 0x01:
                    return f'MOVE_PACKET: 0x{b0:02x} 0x{b1:02x} ({len(clear)} bytes)'
                elif b1 == 0x02:
                    return f'FACELETS_PACKET: 0x{b0:02x} 0x{b1:02x} ({len(clear)} bytes)'
                else:
                    return f'GAN_UNKNOWN: 0x{b0:02x} 0x{b1:02x} ({len(clear)} bytes)'
            else:
                return f'NON_GAN: 0x{b0:02x} 0x{b1:02x} ({len(clear)} bytes)'
        else:
            return f'NO_HEADER: {len(clear)} bytes'
    except Exception as e:
        return f'ERROR: {e}'

# --- Helpers -----------------------------------------------------------------

def _mac_norm_from_le(addr_le):
    """Convert little-endian addr bytes/memoryview from IRQ into normal 'AA:BB:..'."""
    b = bytes(addr_le)  # avoid slicing memoryview with negative step
    return ":".join("{:02X}".format(b[i]) for i in range(len(b) - 1, -1, -1))

def _hex(b):
    return " ".join("{:02X}".format(x) for x in b)

def _mac_direct(addr_le):
    """Direct-order hex, no reversal (for debugging address-endian issues)."""
    b = bytes(addr_le)
    return ":".join("{:02X}".format(x) for x in b)

def _norm(s: str) -> str:
    """Uppercase and remove separators for robust comparison."""
    return s.replace(":", "").replace("-", "").upper()

# --- Command send helpers ----------------------------------------------------

def _send_command_payload(payload: bytes, mode: int = 1) -> bool:
    """Encrypt and write a 16/32B payload to the command characteristic."""
    global _conn, _cmd_handle, _last_write_ealready
    if _conn is None or _cmd_handle is None:
        print("! Cannot send: no connection/cmd handle")
        return False
    try:
        key = _key
        iv = _iv
        enc = encrypt_packet(payload, key, iv)
        if _DBG_PACKETS:
            try:
                print("TX cmd (mode=", mode, ") len=", len(payload))
            except Exception:
                pass
        try:
            ble.gattc_write(_conn, _cmd_handle, enc, mode)
        except Exception as e:
            # Detect EALREADY to apply shorter backoff without consuming a retry
            try:
                en = getattr(e, 'errno', None)
                if (en is None) and hasattr(e, 'args') and e.args:
                    en = e.args[0]
            except Exception:
                en = None
            try:
                if (en == 114) or ("EALREADY" in str(e)):
                    _last_write_ealready = True
            except Exception:
                pass
            print("! gattc_write noresp err:", e)
            return False
        if _DBG_PACKETS:
            try:
                print("TX ENC", len(enc), ":", _hex(enc))
            except Exception:
                pass
        return True
    except Exception as e:
        print("! gattc_write err:", e)
        return False

def _schedule_facelets_poll(delay_ms=50):
    """Rate-limited scheduler to request facelets shortly after a move notification.

    Avoids writing inside IRQ by deferring to the UI loop via existing retry mechanism.
    """
    global _facelets_retry_count, _facelets_retry_next_ms, _facelets_rate_next_ms, _ble_next_ok_ms
    try:
        now_ms = time.ticks_ms()
        # Rate limit
        if time.ticks_diff(now_ms, _facelets_rate_next_ms) < 0:
            return
        # Ensure at least one retry is queued
        if _facelets_retry_count <= 0:
            _facelets_retry_count = 1
        # Schedule for near future, but not before BLE cooldown window
        try:
            target = time.ticks_add(now_ms, delay_ms)
        except Exception:
            target = now_ms + delay_ms
        try:
            if _ble_next_ok_ms:
                # if _ble_next_ok_ms is later than target, use it
                if time.ticks_diff(_ble_next_ok_ms, target) > 0:
                    target = _ble_next_ok_ms
        except Exception:
            pass
        try:
            if (_facelets_retry_next_ms == 0) or (time.ticks_diff(_facelets_retry_next_ms, now_ms) < 0):
                _facelets_retry_next_ms = target
        except Exception:
            _facelets_retry_next_ms = target
        # Next allowed poll time
        try:
            _facelets_rate_next_ms = time.ticks_add(now_ms, 250)
        except Exception:
            _facelets_rate_next_ms = now_ms + 250
        if _DBG_PACKETS:
            try:
                print("Facelets poll scheduled")
            except Exception:
                pass
    except Exception:
        pass

def send_request_facelets() -> bool:
    """Send REQUEST_FACELETS (0x02) command (16 bytes)."""
    global _first_facelets_wr_mode0
    payload = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    _ui_text("Connected", "Cmd:Face")
    try:
        if _first_facelets_wr_mode0:
            print("send_request_facelets() [mode=0 first]")
        else:
            print("send_request_facelets()")
    except Exception:
        pass
    if _first_facelets_wr_mode0:
        _first_facelets_wr_mode0 = False
        return _send_command_payload(payload, mode=0)
    return _send_command_payload(payload, mode=1)

def send_request_reset() -> bool:
    """Send REQUEST_RESET command (16 bytes)."""
    payload = bytes([0x68, 0x05, 0x05, 0x39, 0x77, 0x00, 0x00, 0x01,
                     0x23, 0x45, 0x67, 0x89, 0xAB, 0x00, 0x00, 0x00])
    _ui_text("Connected", "Cmd:Reset")
    return _send_command_payload(payload)

def send_request_battery() -> bool:
    """Send REQUEST_BATTERY (0x03) command (16 bytes)."""
    payload = bytes([0x03] + [0x00]*15)
    _ui_text("Connected", "Cmd:Batt")
    return _send_command_payload(payload)

def send_request_hardware() -> bool:
    """Send REQUEST_HARDWARE (0x01) command (16 bytes)."""
    payload = bytes([0x01] + [0x00]*15)
    _ui_text("Connected", "Cmd:HW")
    return _send_command_payload(payload)

def _is_scan_result_event(event, data) -> bool:
    # Prefer official constant when available
    if event == _IRQ_SCAN_RESULT:
        return True
    # Fallback: identify by tuple shape and that 2nd element looks like a 6-byte address
    try:
        if isinstance(data, tuple) and len(data) == 5:
            addr = data[1]
            if isinstance(addr, (bytes, bytearray, memoryview)):
                return len(bytes(addr)) == 6
    except Exception:
        pass
    return False

def _enable_notify(conn_handle, value_handle):
    # Write 0x0003 (notify+indicate) to CCCD (value_handle + 1) using write-without-response.
    # After writing, set a short BLE cooldown window to avoid immediate EALREADY on next op.
    global _ble_next_ok_ms
    try:
        ble.gattc_write(conn_handle, value_handle + 1, b"\x03\x00", 1)
        try:
            print("  CCCD enabled @", value_handle + 1)
        except Exception:
            pass
    except Exception as e:
        print("  CCCD write failed:", e)
    # Regardless of result, push next BLE op a bit into the future
    try:
        _ble_next_ok_ms = time.ticks_add(time.ticks_ms(), 60)
    except Exception:
        _ble_next_ok_ms = (globals().get('_ble_next_ok_ms') or 0) + 60

def _start_next_char_discovery():
    """Pop next service range and start characteristic discovery (one at a time)."""
    global _char_queue
    if not _char_queue or _conn is None:
        return
    item = _char_queue.pop(0)
    if isinstance(item, tuple) and len(item) >= 2:
        start = item[0]
        end = item[1]
    else:
        start, end = item
    try:
        print("  Discovering chars:", start, "-", end)
    except Exception:
        pass
    try:
        ble.gattc_discover_characteristics(_conn, start, end)
    except Exception as e:
        # If EALREADY or similar appears, let main loop retry by pushing this range back.
        print("  char discover err:", e)
        try:
            _char_queue.insert(0, (start, end))
        except Exception:
            pass

def _on_notify(conn_handle, value_handle, data):
    # Decrypt each notification payload directly (supports 16–20+ byte frames)
    global _alarm_on, _pkt_dbg_next_ms, _last_solved
    if conn_handle != _conn:
        return
    if not _key or not _iv:
        return
    # Prefer state handle, but accept packets from other notify/indicate handles too
    chunk = bytes(data)
    if _DBG_PACKETS:
        try:
            now_ms = time.ticks_ms()
            if time.ticks_diff(now_ms, _pkt_dbg_next_ms) >= 0:
                print("Notify vh=", value_handle, "len=", len(chunk))
                print("RAW", len(chunk), ":", _hex(chunk))
                try:
                    _pkt_dbg_next_ms = time.ticks_add(now_ms, 250)
                except Exception:
                    _pkt_dbg_next_ms = now_ms + 250
        except Exception:
            pass
    if len(chunk) < 16:
        print("! short notify", len(chunk))
        return
    try:
        clear = decrypt_packet(chunk, _key, _iv)
    except Exception as e:
        print("! decrypt error:", e, "raw:", _hex(chunk))
        return
    if clear is None:
        print("! decrypt returned None for len", len(chunk))
        return
    # Packet debug (throttled)
    if _DBG_PACKETS:
        try:
            now_ms = time.ticks_ms()
            if time.ticks_diff(now_ms, _pkt_dbg_next_ms) >= 0:
                print("CLR", len(clear), ":", _hex(clear))
                print("Type:", _analyze_packet_type(clear))
                try:
                    _pkt_dbg_next_ms = time.ticks_add(now_ms, 250)
                except Exception:
                    _pkt_dbg_next_ms = now_ms + 250
        except Exception:
            pass

    # Try solved detection on any plausible frame (handles headered and headerless)
    if len(clear) >= 17:
        try:
            solved = _is_solved_facelets(clear)
            if (_last_solved is None) or (solved != _last_solved):
                _last_solved = solved
                if solved:
                    print("✅ Cube solved")
                    _ui_text("Connected", "Solved!")
                    if _alarm_on and _audio:
                        try:
                            _audio.stop()
                        except Exception:
                            pass
                        _alarm_on = False
                        stop_cube_polling()
                else:
                    print("Cube not solved")
                    _ui_text("Connected", "Not solved")
        except Exception:
            pass

    # Move events (use headered types if present) and trigger facelets
    if len(clear) >= 16 and clear[0] == 0x55:
        # 16-byte packets could be moves or other events
        if clear[1] == 0x02 and len(clear) == 16:
            # 16B 0x02 move-variant
            mv = _parse_move_variant02(clear)
            if mv:
                try:
                    print("Move 0x02:", mv[0], "serial", mv[1])
                except Exception:
                    pass
            _ui_text("Connected", "Move…")
            _schedule_facelets_poll(150)
        elif clear[1] == 0x01:
            # Standard move packet
            _ui_text("Connected", "Move…")
            _schedule_facelets_poll(150)
    # Track facelets serial and timestamp for periodic polling
    if len(clear) >= 19 and clear[0] == 0x55 and clear[1] == 0x02:
        try:
            serial = int.from_bytes(clear[2:4], 'little')
            if serial != _last_facelets_serial:
                _last_facelets_serial = serial
            _last_facelets_ms = time.ticks_ms()
        except Exception:
            pass

# --- IRQ ---------------------------------------------------------------------

def _irq(event, data):
    global _conn, _svc_ranges, _char_queue, _notify_handles, _key, _iv, _connecting, _audio, _alarm_on, _cmd_handle, _state_handle, _did_send_initial_facelets, _rx_buf, _facelets_retry_count, _facelets_retry_next_ms, _facelets_rate_next_ms, _scan_dbg_next_ms
    global _char_discover_in_progress, _char_discover_start_ms, _char_discover_item
    global _service_discover_in_progress, _service_discover_start_ms, _service_discover_pending
    global _ble_next_ok_ms, _notify_queue, _notify_drop_count, _cccd_queue, _discovery_complete_pending
    global _state_cccd_enabled, _initial_facelets_deadline_ms, _polling

    # Scan results
    if _is_scan_result_event(event, data):
        addr_type, addr, adv_type, rssi, adv_data = data
        mac_h = _mac_norm_from_le(addr)  # human-friendly order
        mac_d = _mac_direct(addr)        # direct byte order
        if DEBUG_SCAN:
            try:
                now_ms = time.ticks_ms()
                if time.ticks_diff(now_ms, _scan_dbg_next_ms) >= 0:
                    print("{:4d} dBm | {} | raw {}".format(rssi, mac_h, mac_d))
                    try:
                        _scan_dbg_next_ms = time.ticks_add(now_ms, DEBUG_SCAN_RATE_MS)
                    except Exception:
                        _scan_dbg_next_ms = now_ms + DEBUG_SCAN_RATE_MS
            except Exception:
                pass
        if ((_norm(mac_h) == _norm(KNOWN_MAC)) or (_norm(mac_d) == _norm(KNOWN_MAC))) and (_conn is None) and (not _connecting):
            print("Found cube @", mac_h, "(raw", mac_d + ")", "RSSI", rssi)
            _connecting = True
            try:
                ble.gap_scan(None)  # stop scanning immediately
            except:
                pass
            # Connect using the original little-endian addr bytes
            try:
                ble.gap_connect(addr_type, bytes(addr))
            except Exception as e:
                print("connect err:", e)

    elif event == _IRQ_SCAN_DONE:
        print("Scan done.")
        if _polling and _conn is None:
            if _connecting:
                _ui_text("Connecting...", "")
            else:
                _ui_text("Rescanning...", "")
                # restart scanning indefinitely while polling is active
                try:
                    ble.gap_scan(0, 30000, 30000, True)
                except Exception as e:
                    print("scan restart err:", e)
        else:
            _ui_text("Scan done", "")

    # Connection events
    elif event == _IRQ_PERIPHERAL_CONNECT:
        conn_handle, addr_type, addr = data
        if _conn is None:
            _conn = conn_handle
            try:
                print("Connected:", _mac_norm_from_le(addr))
            except Exception:
                print("Connected")
            _ui_text("Connected", "Listening…")
            # Reset discovery/command flags on fresh connection
            _did_send_initial_facelets = False
            _cmd_handle = None
            _state_handle = None
            _state_cccd_enabled = False
            _initial_facelets_deadline_ms = 0
            # Begin service discovery immediately to prevent disconnect
            _svc_ranges = []
            _char_queue = []
            _notify_handles = []
            _rx_buf = b""
            _char_discover_in_progress = False
            _ble_next_ok_ms = 0
            # Reset deferred retry state
            _facelets_retry_count = 0
            _facelets_retry_next_ms = 0
            _facelets_rate_next_ms = 0
            # Derive encryption keys from peer MAC
            try:
                mac_h = _mac_norm_from_le(addr)
                _key, _iv = derive_key_iv_from_mac(mac_h)
            except Exception as e:
                print("Key derivation failed:", e)
            # Kick off service discovery
            try:
                ble.gattc_discover_services(_conn)
            except Exception as e:
                print("service discovery error:", e)

    elif event == _IRQ_PERIPHERAL_DISCONNECT:
        conn_handle, addr_type, addr = data
        if conn_handle == _conn:
            print("Disconnected.")
            _conn = None
            _connecting = False
            _ui_text("Disconnected", "")
            # Keep alarm sounding on disconnect; user must solve or press button to stop
            # Reset buffers and discovery state
            _rx_buf = b""
            _cmd_handle = None
            _state_handle = None
            _did_send_initial_facelets = False
            _state_cccd_enabled = False
            _initial_facelets_deadline_ms = 0
            _svc_ranges = []
            _char_queue = []
            _notify_handles = []
            _char_discover_in_progress = False
            _ble_next_ok_ms = 0
            # Reset deferred retry state
            _facelets_retry_count = 0
            _facelets_retry_next_ms = 0
            _facelets_rate_next_ms = 0
            # restart scanning after disconnect only if polling is active
            if _polling:
                try:
                    ble.gap_scan(0, 30000, 30000, True)
                except Exception as e:
                    print("scan restart err:", e)

    # Service discovery
    elif event == _IRQ_GATTC_SERVICE_RESULT:
        conn_handle, start_handle, end_handle, uuid = data
        if conn_handle == _conn:
            _svc_ranges.append((start_handle, end_handle))

    elif event == _IRQ_GATTC_SERVICE_DONE:
        conn_handle, status = data
        if conn_handle == _conn:
            # queue all discovered service ranges and kick off first char discovery
            _char_queue = list(_svc_ranges)
            print("Services:", len(_char_queue), "ranges")
            _start_next_char_discovery()
            # Defer starting discovery to the main loop to avoid EALREADY inside IRQ
            try:
                _ble_next_ok_ms = time.ticks_add(time.ticks_ms(), 50)
            except Exception:
                _ble_next_ok_ms = (globals().get('_ble_next_ok_ms') or 0) + 50

    # Characteristic discovery (one range at a time)
    elif event == _IRQ_GATTC_CHARACTERISTIC_RESULT:
        conn_handle, def_handle, value_handle, properties, uuid = data
        if conn_handle == _conn:
            # Match by UUIDs
            try:
                if uuid == STATE_UUID:
                    _state_handle = value_handle
                    if properties & (FLAG_NOTIFY | FLAG_INDICATE):
                        _notify_handles.append(value_handle)
                    print("  STATE char @", value_handle)
                elif uuid == CMD_UUID:
                    _cmd_handle = value_handle
                    print("  CMD   char @", value_handle)
                else:
                    # Fallback: enable notify/indicate for any other chars too
                    if properties & (FLAG_NOTIFY | FLAG_INDICATE):
                        _notify_handles.append(value_handle)
                        print("  NOTIFY/INDICATE char @", value_handle)
                # If we have both handles and haven't requested facelets yet, schedule it
                if (_cmd_handle is not None) and (_state_handle is not None) and (not _did_send_initial_facelets):
                    globals()['_initial_facelets_pending'] = True
            except Exception as e:
                # On some ports, uuid equality can be finicky; still enable notifies/indicates
                if properties & (FLAG_NOTIFY | FLAG_INDICATE):
                    _notify_handles.append(value_handle)
                    print("  NOTIFY/INDICATE char @", value_handle, "(uuid cmp err)", e)

    elif event == _IRQ_GATTC_CHARACTERISTIC_DONE:
        conn_handle, status = data
        if conn_handle == _conn:
            # After finishing one range, queue any pending CCCDs for main-loop enabling
            if _notify_handles:
                try:
                    _cccd_queue.extend(_notify_handles)
                    _notify_handles = []
                except Exception:
                    # Fallback: enable directly if extend fails
                    while _notify_handles:
                        vh = _notify_handles.pop(0)
                        _cccd_queue.append(vh)

            # If we've already found both CMD and STATE, stop further discovery to avoid EALREADY
            if (_cmd_handle is not None) and (_state_handle is not None):
                _char_queue = []
                _discovery_complete_pending = True
            else:
                # Continue to next range only if still needed
                _start_next_char_discovery()
            # If discovery finished and we have a CMD handle, request facelets once
            if not _char_queue and (_cmd_handle is not None) and (not _did_send_initial_facelets):
                # Mark pending; main loop will schedule and print
                _initial_facelets_pending = True
                # Ensure at least a couple retries if first request is missed (handled in main loop scheduling)
                try:
                    if _facelets_retry_count < 2:
                        _facelets_retry_count = 2
                except Exception:
                    pass

    # Notifications (enqueue for processing in main loop to avoid IRQ latency)
    elif event == _IRQ_GATTC_NOTIFY:
        conn_handle, value_handle, notify_data = data
        try:
            chunk = bytes(notify_data)
            if len(_notify_queue) < 16:
                _notify_queue.append((conn_handle, value_handle, chunk))
            else:
                _notify_drop_count += 1
        except Exception:
            pass
    elif event == _IRQ_GATTC_INDICATE:
        conn_handle, value_handle, indicate_data = data
        try:
            chunk = bytes(indicate_data)
            if len(_notify_queue) < 16:
                _notify_queue.append((conn_handle, value_handle, chunk))
            else:
                _notify_drop_count += 1
        except Exception:
            pass

# --- Run ---------------------------------------------------------------------

def run():
    global ble, _audio, _alarm_on
    print("=== CUBE ALARM STARTING ===")
    try:
        if ble is None:
            ble = bluetooth.BLE()
        ble.active(True)
        print("BLE: active")
    except Exception as e:
        print("BLE init failed:", e)
        return
    print("Pico W BLE central — GAN decrypt test")
    _ui_init()
    _buttons_init()
    ble.irq(_irq)
    # Pre-initialize audio but do not start until alarm fires
    try:
        if _audio is None:
            _audio = AudioAlarm(10, 11, 9)
    except Exception as e:
        print("Audio init failed:", e)
    _ui_text("Ready", "Set alarm")
    # Cooperative main loop to service buttons, audio, and deferred facelets requests
    while True:
        _poll_tick()
        time.sleep_ms(5)

# No auto-run on import; call run() manually when imported as a module.
if __name__ == "__main__":
    run()
