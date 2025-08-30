# main.py — Pico W BLE central for GAN cube
# Requires gan_mpy.py with: derive_key_iv_from_mac(mac_str) and decrypt_packet(cipher_bytes, key, iv)

print("=== CUBE ALARM STARTING ===")

try:
    import ubluetooth as bluetooth
    print("BLE: Using ubluetooth")
except ImportError:
    import bluetooth
    print("BLE: Using bluetooth")
import time
import _thread
from micropython import const
from machine import Pin, I2C
import ssd1306
from gan_mpy import derive_key_iv_from_mac, decrypt_packet, encrypt_packet
from audio_alarm import AudioAlarm

# --- Config ------------------------------------------------------------------

SCAN_MS     = const(10000)  # 10 s active scan
KNOWN_MAC   = "CF:AA:79:C9:96:9C"  # <- your cube's public MAC (normal big‑endian)
DEBUG_SCAN  = const(1)

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
FLAG_NOTIFY                       = getattr(bluetooth, "FLAG_NOTIFY", const(0x10))

# --- Globals -----------------------------------------------------------------

ble = bluetooth.BLE()
ble.active(True)

_key = None
_iv  = None
_rx_buf = b""

# Discovery state
_svc_ranges = []      # [(start, end)]
_char_queue = []      # [(start, end)] yet to process
_notify_handles = []  # value handles with NOTIFY
_conn = None
_connecting = False
_audio = None
_alarm_on = False

# GAN characteristic handles
_cmd_handle = None
_state_handle = None
_did_send_initial_facelets = False

# Deferred command retry (handled in UI loop, not inside BLE IRQ)
_facelets_retry_count = 0
_facelets_retry_next_ms = 0

# Rate limiting for facelets polling after moves (ms)
_facelets_rate_next_ms = 0
# Enable detailed facelets debugging logs
_DBG_FACELETS = True

# OLED UI (128x32 I2C1 GP2/GP3)
_oled = None
_ui_line1 = ""
_ui_line2 = ""
_ui_dirty = False
_ui_thread_running = False
_buttons_thread_running = False
_btn_a = None
_btn_b = None
_btn_a_last = 1
_btn_b_last = 1
_btn_a_next_ok_ms = 0
_btn_b_next_ok_ms = 0

def _ui_text(line1="", line2=""):
    # Only mark desired UI state; actual drawing happens in background thread
    global _ui_line1, _ui_line2, _ui_dirty
    _ui_line1 = line1 or ""
    _ui_line2 = line2 or ""
    _ui_dirty = True

def _ui_draw(now_tuple=None):
    if _oled is None:
        return
    try:
        if now_tuple is None:
            now_tuple = time.localtime()
        hh, mm, ss = now_tuple[3], now_tuple[4], now_tuple[5]
        t = "%02d:%02d:%02d" % (hh, mm, ss)
        _oled.fill(0)
        _oled.text(t, 0, 0)
        if _ui_line1:
            _oled.text(_ui_line1[:16], 0, 10)
        if _ui_line2:
            _oled.text(_ui_line2[:16], 0, 20)
        _oled.show()
    except Exception as e:
        # Avoid crashing UI loop on transient I2C errors
        print("OLED draw err:", e)

def _ui_loop():
    global _ui_dirty, _ui_thread_running, _btn_a_last, _btn_b_last, _btn_a_next_ok_ms, _btn_b_next_ok_ms, _facelets_retry_count, _facelets_retry_next_ms
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
                if _btn_b_last == 1 and b == 0 and time.ticks_diff(now_ms, _btn_b_next_ok_ms) >= 0:
                    send_request_reset()
                    _btn_b_next_ok_ms = time.ticks_add(now_ms, 200)
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
                    _facelets_retry_count -= 1
                    _facelets_retry_next_ms = time.ticks_add(now_ms, 200)
                    try:
                        print("Facelets retry ->", ok, "remaining", _facelets_retry_count)
                    except Exception:
                        pass
        except Exception:
            pass
        # Tight-ish loop to keep audio fed and buttons responsive
        time.sleep_ms(5)

def _ui_init():
    global _oled, _ui_thread_running
    try:
        i2c = I2C(1, sda=Pin(2), scl=Pin(3), freq=100000)
        _oled = ssd1306.SSD1306_I2C(128, 32, i2c, addr=0x3C)
        _ui_text("Scanning...", "Twist to wake")
    except Exception as e:
        print("OLED init failed:", e)
        _oled = None
    # Skip background UI thread to avoid core1 conflicts
    print("UI: Skipping thread to avoid core1 conflicts")

def _buttons_init():
    global _btn_a, _btn_b, _btn_a_last, _btn_b_last, _buttons_thread_running, _btn_a_next_ok_ms, _btn_b_next_ok_ms
    try:
        _btn_a = Pin(14, Pin.IN, Pin.PULL_UP)
        _btn_b = Pin(15, Pin.IN, Pin.PULL_UP)
        _btn_a_last = _btn_a.value()
        _btn_b_last = _btn_b.value()
        t0 = time.ticks_ms()
        _btn_a_next_ok_ms = t0
        _btn_b_next_ok_ms = t0
        # No separate button thread; buttons are polled in _ui_loop to avoid core1 contention
    except Exception as e:
        print("Buttons init failed:", e)
        _btn_a = None
        _btn_b = None

def _buttons_loop():
    # Simple edge-detect on pull-up buttons: send commands on press
    global _btn_a_last, _btn_b_last
    while True:
        try:
            if _btn_a is not None:
                a = _btn_a.value()
                if _btn_a_last == 1 and a == 0:
                    send_request_facelets()
                _btn_a_last = a
            if _btn_b is not None:
                b = _btn_b.value()
                if _btn_b_last == 1 and b == 0:
                    send_request_reset()
                _btn_b_last = b
        except Exception:
            pass
        time.sleep_ms(80)


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

def _is_solved_facelets(clear: bytes) -> bool:
    """Return True if a decrypted packet indicates solved state (19B compressed bit fields)."""
    try:
        # GAN protocol: 19-byte packets are facelets packets
        if len(clear) < 19:
            return False

        # Convert the packet to a bit string once, matching backend logic for reliability.
        bit_string = _bits_from_bytes(clear)

        # Parse using correct bit positions from reference driver
        cp = []
        co = []
        ep = []
        eo = []

        # CP (Corners 0-6): 3 bits each, starting at bit 40.
        for i in range(7):
            cp.append(get_bits(bit_string, 40 + i * 3, 3))
        # CO (Corners 0-6): 2 bits each, starting at bit 61.
        for i in range(7):
            co.append(get_bits(bit_string, 61 + i * 2, 2))

        # EP (Edges 0-10): 4 bits each, starting at bit 75.
        for i in range(11):
            ep.append(get_bits(bit_string, 77 + i * 4, 4))
        # EO (Edges 0-10): 1 bit each, starting at bit 121.
        for i in range(11):
            eo.append(get_bits(bit_string, 121 + i, 1))

        # The last piece is calculated from the sum of the others.
        cp.append(28 - sum(cp))
        co.append((3 - (sum(co) % 3)) % 3)
        ep.append(66 - sum(ep))
        eo.append((2 - (sum(eo) % 2)) % 2)

        # A solved cube has all permutations and orientations in order (0,1,2,3... and all 0s)
        is_cp_solved = (len(cp) == 8 and set(cp) == set(range(8)) and all(cp[i] == i for i in range(8)))
        is_co_solved = (len(co) == 8 and all(o == 0 for o in co))
        is_ep_solved = (len(ep) == 12 and set(ep) == set(range(12)) and all(ep[i] == i for i in range(12)))
        is_eo_solved = (len(eo) == 12 and all(o == 0 for o in eo))

        return is_cp_solved and is_co_solved and is_ep_solved and is_eo_solved

    except Exception as e:
        try:
            print("DBG facelets error:", e)
        except Exception:
            pass
        return False

def _debug_facelets(clear: bytes):
    """Debug helper: print CP/CO/EP/EO arrays from compressed bit fields."""
    try:
        # Per memory, any 19-byte packet is a facelets packet. No header check needed.
        if len(clear) < 19:
            return

        # Convert the packet to a bit string once for reliable parsing.
        bit_string = _bits_from_bytes(clear)

        cp = []
        co = []
        ep = []
        eo = []

        # CP (Corners 0-6): 3 bits each, starting at bit 40.
        for i in range(7):
            cp.append(get_bits(bit_string, 40 + i * 3, 3))
        # CO (Corners 0-6): 2 bits each, starting at bit 61.
        for i in range(7):
            co.append(get_bits(bit_string, 61 + i * 2, 2))

        # EP (Edges 0-10): 4 bits each, starting at bit 75.
        for i in range(11):
            ep.append(get_bits(bit_string, 77 + i * 4, 4))
        # EO (Edges 0-10): 1 bit each, starting at bit 121.
        for i in range(11):
            eo.append(get_bits(bit_string, 121 + i, 1))
        # The last piece is calculated from the sum of the others.
        cp.append(28 - sum(cp))
        co.append((3 - (sum(co) % 3)) % 3)
        ep.append(66 - sum(ep))
        eo.append((2 - (sum(eo) % 2)) % 2)

        # Check if parsing produces valid values
        valid_cp = len(cp) == 8 and set(cp) == set(range(8))
        valid_co = len(co) == 8 and all(0 <= x <= 2 for x in co)
        valid_ep = len(ep) == 12 and set(ep) == set(range(12))
        valid_eo = len(eo) == 12 and all(0 <= x <= 1 for x in eo)

        print("--- FACELETS DEBUG ---")
        print("CP:", cp, "(valid:", valid_cp, ")")
        print("CO:", co, "(valid:", valid_co, ")")
        print("EP:", ep, "(valid:", valid_ep, ")")
        print("EO:", eo, "(valid:", valid_eo, ")")
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

def _send_command_payload(payload: bytes) -> bool:
    """Encrypt and write a 16/32B payload to the command characteristic."""
    global _conn, _cmd_handle
    if _conn is None or _cmd_handle is None:
        print("! Cannot send: no connection/cmd handle")
        return False
    if not _key or not _iv:
        print("! Cannot send: keys not ready")
        return False
    try:
        enc = encrypt_packet(payload, _key, _iv)
        if not enc:
            print("! Encrypt failed or invalid length")
            return False
        # mode=1: write without response
        ble.gattc_write(_conn, _cmd_handle, enc, 1)
        print("TX ENC", len(enc), ":", _hex(enc))
        return True
    except Exception as e:
        print("! gattc_write err:", e)
        return False

def _schedule_facelets_poll(delay_ms=50):
    """Rate-limited scheduler to request facelets shortly after a move notification.

    Avoids writing inside IRQ by deferring to the UI loop via existing retry mechanism.
    """
    global _facelets_retry_count, _facelets_retry_next_ms, _facelets_rate_next_ms
    try:
        now_ms = time.ticks_ms()
        # Rate limit
        if time.ticks_diff(now_ms, _facelets_rate_next_ms) < 0:
            return
        # Ensure at least one retry is queued
        if _facelets_retry_count <= 0:
            _facelets_retry_count = 1
        # Schedule for near future
        try:
            if (_facelets_retry_next_ms == 0) or (time.ticks_diff(_facelets_retry_next_ms, now_ms) < 0):
                _facelets_retry_next_ms = time.ticks_add(now_ms, delay_ms)
        except Exception:
            _facelets_retry_next_ms = now_ms + delay_ms
        # Next allowed poll time
        try:
            _facelets_rate_next_ms = time.ticks_add(now_ms, 250)
        except Exception:
            _facelets_rate_next_ms = now_ms + 250
        try:
            print("Facelets poll scheduled")
        except Exception:
            pass
    except Exception:
        pass

def send_request_facelets() -> bool:
    """Send REQUEST_FACELETS (0x02) command (16 bytes)."""
    payload = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    _ui_text("Connected", "Cmd:Face")
    return _send_command_payload(payload)

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
    # Write 0x0001 to CCCD (value_handle + 1) to enable notifications.
    # mode=1 (write-without-response) is fine for CCCD on most stacks.
    try:
        ble.gattc_write(conn_handle, value_handle + 1, b"\x01\x00", 1)
        print("  CCCD enabled @", value_handle + 1)
    except Exception as e:
        print("  CCCD write failed:", e)

def _start_next_char_discovery():
    """Pop next service range and start characteristic discovery (one at a time)."""
    global _char_queue
    if not _char_queue or _conn is None:
        return
    start, end = _char_queue.pop(0)
    try:
        ble.gattc_discover_characteristics(_conn, start, end)
    except Exception as e:
        # If EALREADY ever appears, wait a tick and retry once
        print("  char discover err:", e)
        time.sleep_ms(50)
        try:
            ble.gattc_discover_characteristics(_conn, start, end)
        except Exception as e2:
            print("  char discover retry failed:", e2)

def _on_notify(conn_handle, value_handle, data):
    # Decrypt each notification payload directly (supports 16–20+ byte frames)
    global _alarm_on
    if conn_handle != _conn:
        return
    if not _key or not _iv:
        return
    # If we know the state characteristic, ignore other notifies
    if (_state_handle is not None) and (value_handle != _state_handle):
        return
    chunk = bytes(data)
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
    # Good frames usually start with 0x55
    print("CLR", len(clear), ":", _hex(clear))
    # Update simple UI based on packet type - match backend logic
    if len(clear) == 19:
        # Per memory, any 19-byte packet is a facelets packet.
        if _DBG_FACELETS:
            _debug_facelets(clear)

        solved = _is_solved_facelets(clear)
        if solved:
            print("✅ Cube solved")
            _ui_text("Connected", "Solved!")
            # Stop alarm when solved
            if _alarm_on and _audio:
                try:
                    _audio.stop()
                except Exception:
                    pass
                _alarm_on = False
    elif len(clear) >= 16:
        # 16-byte packets could be moves or other events
        if len(clear) >= 2 and clear[0] == 0x55 and clear[1] == 0x02:
            # 16B 0x02 move-variant
            mv = _parse_move_variant02(clear)
            if mv:
                try:
                    print("Move 0x02:", mv[0], "serial", mv[1])
                except Exception:
                    pass
            _ui_text("Connected", "Move…")
            _schedule_facelets_poll(80)
        elif len(clear) >= 2 and clear[0] == 0x55 and clear[1] == 0x01:
            # Move packet
            _ui_text("Connected", "Move…")
            _schedule_facelets_poll(80)

# --- IRQ ---------------------------------------------------------------------

def _irq(event, data):
    global _conn, _svc_ranges, _char_queue, _notify_handles, _key, _iv, _connecting, _audio, _alarm_on, _cmd_handle, _state_handle, _did_send_initial_facelets, _rx_buf, _facelets_retry_count, _facelets_retry_next_ms, _facelets_rate_next_ms

    # Scan results
    if _is_scan_result_event(event, data):
        addr_type, addr, adv_type, rssi, adv_data = data
        mac_h = _mac_norm_from_le(addr)  # human-friendly order
        mac_d = _mac_direct(addr)        # direct byte order
        if DEBUG_SCAN:
            print("{:4d} dBm | {} | raw {}".format(rssi, mac_h, mac_d))
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
        if _conn is None:
            if _connecting:
                _ui_text("Connecting...", "")
            else:
                _ui_text("Rescanning...", "")
                # restart scanning indefinitely
                try:
                    ble.gap_scan(0, 30000, 30000, True)
                except Exception as e:
                    print("scan restart err:", e)
        else:
            _ui_text("Scan done", "")

    # Connection events
    elif event == _IRQ_PERIPHERAL_CONNECT:
        conn_handle, addr_type, addr = data
        _conn = conn_handle
        _connecting = False
        mac = _mac_norm_from_le(addr)
        print("Connected:", mac, "handle", conn_handle)
        try:
            _key, _iv = derive_key_iv_from_mac(mac)
            print("Key/IV ready.")
            if _DBG_FACELETS:
                try:
                    print("Key[:6] =", _hex(_key[:6]), "IV[:6] =", _hex(_iv[:6]))
                except Exception:
                    pass
        except Exception as e:
            print("Key derivation failed:", e)
            return
        _ui_text("Connected", "Listening…")
        # Reset discovery/command flags on fresh connection
        _did_send_initial_facelets = False
        _cmd_handle = None
        _state_handle = None
        # Start alarm tone upon connection
        try:
            if _audio is None:
                _audio = AudioAlarm(10, 11, 9)
            if _audio and getattr(_audio, 'ok', False) and not _alarm_on:
                _audio.start()
                _alarm_on = True
                _ui_text("Connected", "Alarm!")
        except Exception as e:
            print("Audio start failed:", e)
        # Begin service discovery
        _svc_ranges = []
        _char_queue = []
        _notify_handles = []
        _rx_buf = b""
        # Reset deferred retry state
        _facelets_retry_count = 0
        _facelets_retry_next_ms = 0
        _facelets_rate_next_ms = 0
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
            # Ensure alarm is stopped on disconnect
            if _alarm_on and _audio:
                try:
                    _audio.stop()
                except Exception:
                    pass
                _alarm_on = False
            # Reset buffers and discovery state
            _rx_buf = b""
            _cmd_handle = None
            _state_handle = None
            _did_send_initial_facelets = False
            _svc_ranges = []
            _char_queue = []
            _notify_handles = []
            # Reset deferred retry state
            _facelets_retry_count = 0
            _facelets_retry_next_ms = 0
            _facelets_rate_next_ms = 0
            # restart scanning after disconnect
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

    # Characteristic discovery (one range at a time)
    elif event == _IRQ_GATTC_CHARACTERISTIC_RESULT:
        conn_handle, def_handle, value_handle, properties, uuid = data
        if conn_handle == _conn:
            # Match by UUIDs
            try:
                if uuid == STATE_UUID:
                    _state_handle = value_handle
                    if properties & FLAG_NOTIFY:
                        _notify_handles.append(value_handle)
                    print("  STATE char @", value_handle)
                elif uuid == CMD_UUID:
                    _cmd_handle = value_handle
                    print("  CMD   char @", value_handle)
                else:
                    # Fallback: enable notify for any other NOTIFY chars too
                    if properties & FLAG_NOTIFY:
                        _notify_handles.append(value_handle)
                        print("  NOTIFY char @", value_handle)
            except Exception as e:
                # On some ports, uuid equality can be finicky; still enable notifies
                if properties & FLAG_NOTIFY:
                    _notify_handles.append(value_handle)
                    print("  NOTIFY char @", value_handle, "(uuid cmp err)", e)

    elif event == _IRQ_GATTC_CHARACTERISTIC_DONE:
        conn_handle, status = data
        if conn_handle == _conn:
            # After finishing one range, start the next, and enable CCCD
            # (enable once we have at least one NOTIFY handle)
            while _notify_handles:
                vh = _notify_handles.pop(0)
                _enable_notify(_conn, vh)
            _start_next_char_discovery()
            # If discovery finished and we have a CMD handle, request facelets once
            if not _char_queue and (_cmd_handle is not None) and (not _did_send_initial_facelets):
                ok = send_request_facelets()
                _did_send_initial_facelets = True
                print("Initial facelets requested:", ok)
                if not ok:
                    # Schedule up to 3 retries outside IRQ
                    try:
                        _facelets_retry_count = 3
                        _facelets_retry_next_ms = time.ticks_add(time.ticks_ms(), 200)
                    except Exception:
                        _facelets_retry_count = 3

    # Notifications (forward to handler)
    elif event == _IRQ_GATTC_NOTIFY:
        conn_handle, value_handle, notify_data = data
        _on_notify(conn_handle, value_handle, notify_data)

# --- Run ---------------------------------------------------------------------

def run():
    print("Pico W BLE central — GAN decrypt test")
    _ui_init()
    _buttons_init()
    ble.irq(_irq)
    # Active scan with wide window (interval=window to be continuously listening)
    # ble.gap_scan(duration_ms, interval_us, window_us, active)
    _ui_text("Scanning...", "Twist to wake")
    # Scan in 10s windows, auto-rescan in IRQ if not connected
    ble.gap_scan(SCAN_MS, 30000, 30000, True)
    print("Scanning {} ms windows… auto-rescanning until found.".format(SCAN_MS))

# Auto-run enabled for testing
run()
