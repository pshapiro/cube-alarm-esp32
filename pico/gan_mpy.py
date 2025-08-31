# gan_mpy.py — MicroPython helpers for GAN cube streams (Pico W)
try:
    from ucryptolib import aes
except ImportError:
    # Fallback alias on some ports
    from cryptolib import aes

BASE_KEY = bytes([0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11, 0x12, 0x53])
BASE_IV  = bytes([0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12, 0x02, 0x43])

def derive_key_iv_from_mac(mac_address: str):
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()
    # For Pico W BLE (state/facelets notifications), using the MAC bytes in
    # display order (no reversal) yields frames with 0x55 headers post-decrypt.
    if len(mac_clean) == 12:
        salt = bytes.fromhex(mac_clean)
    elif len(mac_clean) == 32:
        salt = bytes.fromhex(mac_clean[:12])
    else:
        raise ValueError("Invalid MAC/UUID format: %r" % mac_address)

    key = bytearray(BASE_KEY)
    iv  = bytearray(BASE_IV)
    for i in range(6):
        # 0xFF modulo per JavaScript implementation
        key[i] = (BASE_KEY[i] + salt[i]) % 0xFF
        iv[i]  = (BASE_IV[i] + salt[i]) % 0xFF
    return bytes(key), bytes(iv)

def _cbc(key, iv):
    # mode=2 is CBC in MicroPython
    return aes(key, 2, iv)

def _dec_last_first(src: bytes, key: bytes, iv: bytes) -> bytes:
    n = len(src)
    buf = bytearray(src)
    # decrypt trailing 16 if present
    if n > 16:
        end = n - 16
        c = _cbc(key, iv)
        try:
            buf[end:end+16] = c.decrypt(bytes(buf[end:end+16]))
        except Exception:
            return src
    # decrypt leading 16
    c = _cbc(key, iv)
    try:
        buf[0:16] = c.decrypt(bytes(buf[0:16]))
    except Exception:
        return src
    return bytes(buf)

def _dec_first_last(src: bytes, key: bytes, iv: bytes) -> bytes:
    n = len(src)
    buf = bytearray(src)
    # decrypt leading 16
    c = _cbc(key, iv)
    try:
        buf[0:16] = c.decrypt(bytes(buf[0:16]))
    except Exception:
        return src
    # decrypt trailing 16 if present
    if n > 16:
        end = n - 16
        c = _cbc(key, iv)
        try:
            buf[end:end+16] = c.decrypt(bytes(buf[end:end+16]))
        except Exception:
            return src
    return bytes(buf)

def decrypt_packet(pkt: bytes, key: bytes, iv: bytes) -> bytes:
    n = len(pkt)
    if n < 16:
        return None
    # Heuristics: if it already looks like a GAN frame, return as-is
    try:
        if pkt and pkt[0] == 0x55 and (n >= 2):
            return pkt
    except Exception:
        pass
    # Try backend order (last->first) first
    d1 = _dec_last_first(pkt, key, iv)
    try:
        if d1 and d1[0] == 0x55:
            return d1
    except Exception:
        pass
    # Try alternate (first->last)
    d2 = _dec_first_last(pkt, key, iv)
    try:
        if d2 and d2[0] == 0x55:
            return d2
    except Exception:
        pass
    # As a fallback, return d1 even if headerless; higher layers may still parse
    return d1

def encrypt_packet(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt command data using dual-chunk CBC, matching backend behavior.

    - For 16-byte packets: single CBC encrypt.
    - For 32-byte packets: encrypt first 16, then last 16, reusing the same IV for each.
    """
    n = len(data)
    if n < 16:
        return None
    buf = bytearray(data)
    c = _cbc(key, iv)
    buf[0:16] = c.encrypt(bytes(buf[0:16]))
    if n > 16:
        end_off = n - 16
        c = _cbc(key, iv)
        buf[end_off:end_off+16] = c.encrypt(bytes(buf[end_off:end_off+16]))
    return bytes(buf)
