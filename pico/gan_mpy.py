# gan_mpy.py — MicroPython helpers for GAN cube streams (Pico W)
from ucryptolib import aes

BASE_KEY = bytes([0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11, 0x12, 0x53])
BASE_IV  = bytes([0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12, 0x02, 0x43])

def derive_key_iv_from_mac(mac_address: str):
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()
    
    # Match backend exactly - use first 12 chars for UUID format
    if len(mac_clean) == 12:
        # Traditional MAC address format (AA:BB:CC:DD:EE:FF)
        salt = bytes.fromhex(mac_clean)
    elif len(mac_clean) == 32:
        # UUID format from macOS BLE - use FIRST 12 hex chars (6 bytes) for this cube variant
        salt = bytes.fromhex(mac_clean[:12])  # Match backend: [:12] not [-12:]
    else:
        raise ValueError("Invalid MAC/UUID format: %r" % mac_address)
        
    # Match backend exactly - reverse salt bytes (MicroPython compatible)
    n = len(salt)
    salt = bytes([salt[i] for i in range(n - 1, -1, -1)])

    key = bytearray(BASE_KEY)
    iv  = bytearray(BASE_IV)
    for i in range(6):
        # Match backend exactly - % 0xFF
        key[i] = (BASE_KEY[i] + salt[i]) % 0xFF
        iv[i]  = (BASE_IV[i] + salt[i]) % 0xFF
    return bytes(key), bytes(iv)

def _cbc(key, iv):
    # mode=2 is CBC in MicroPython
    return aes(key, 2, iv)

def decrypt_packet(pkt: bytes, key: bytes, iv: bytes) -> bytes:
    n = len(pkt)
    if n < 16:
        return None
    buf = bytearray(pkt)
    
    # To prevent any state corruption in ucryptolib, decrypt the two chunks
    # completely independently. The backend decrypts LAST then FIRST.
    first_chunk_decrypted = None
    last_chunk_decrypted = None

    # 1. Decrypt last chunk (if it exists) into a temporary variable
    if n > 16:
        end_off = n - 16
        c1 = _cbc(key, iv)
        try:
            last_chunk_decrypted = c1.decrypt(bytes(buf[end_off:end_off+16]))
        except Exception as e:
            print("! AES decrypt error (last chunk):", e)
            return pkt

    # 2. Decrypt first chunk into a temporary variable
    c2 = _cbc(key, iv)
    try:
        first_chunk_decrypted = c2.decrypt(bytes(buf[0:16]))
    except Exception as e:
        print("! AES decrypt error (first chunk):", e)
        return pkt

    # 3. Now, write the decrypted chunks back into the buffer
    if last_chunk_decrypted:
        end_off = n - 16
        buf[end_off:end_off+16] = last_chunk_decrypted
    if first_chunk_decrypted:
        buf[0:16] = first_chunk_decrypted
        
    return bytes(buf)

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