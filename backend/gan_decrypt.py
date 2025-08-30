# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
from __future__ import annotations
import json, re
import time
from typing import List, Tuple, Dict, Optional, NamedTuple
from dataclasses import dataclass
from lzstring import LZString
from Crypto.Cipher import AES

# Source: https://github.com/afedotov/gan-web-bluetooth/blob/master/src/gan.js
# De-obfuscated, then ported to Python. The lzstring decompression was failing,
# so the keys have been pre-decoded and hardcoded here.
_DECODED_KEYS = [
    [8, 5, 1, 6, 4, 7, 2, 0, 11, 13, 15, 12, 14, 9, 3, 10],
    [8, 5, 1, 6, 4, 7, 2, 0, 11, 13, 15, 12, 14, 9, 3, 10],
    [1, 6, 8, 3, 5, 10, 12, 15, 0, 2, 4, 7, 9, 11, 13, 14],
    [1, 6, 8, 3, 5, 10, 12, 15, 0, 2, 4, 7, 9, 11, 13, 14],
]

# Face mappings
FACE_NAMES = ['U', 'R', 'F', 'D', 'L', 'B']
MOVE_NAMES = ['U', 'R', 'F', 'D', 'L', 'B', "U'", "R'", "F'", "D'", "L'", "B'"]

# Solved state constant - standard color arrangement (URFDLB)
# Used for detecting when the cube returns to the factory solved state
SOLVED_STATE = "UUUUUUUUURRRRRRRRRFFFFFFFFFDDDDDDDDDLLLLLLLLLBBBBBBBBB"

# Corner and edge facelet mappings (from JavaScript implementation)
CORNER_FACELET_MAP = [
    [8, 9, 20],   # URF
    [6, 18, 38],  # UFL
    [0, 36, 47],  # ULB
    [2, 45, 11],  # UBR
    [29, 26, 15], # DFR
    [27, 44, 24], # DLF
    [33, 53, 42], # DBL
    [35, 17, 51], # DRB
]

EDGE_FACELET_MAP = [
    [5, 10],   # UR
    [7, 19],   # UF
    [3, 37],   # UL
    [1, 46],   # UB
    [32, 16],  # DR
    [28, 25],  # DF
    [30, 43],  # DL
    [34, 52],  # DB
    [23, 12],  # FR
    [21, 41],  # FL
    [50, 39],  # BL
    [48, 14],  # BR
]

@dataclass
class CubeMove:
    """Represents a single cube move with all metadata."""
    face: int  # 0-5: U, R, F, D, L, B
    direction: int  # 0=CW, 1=CCW
    move: str  # String notation like "R'" or "U"
    serial: int  # Serial number from cube (0-255)
    local_timestamp: Optional[float]  # Host timestamp
    cube_timestamp: Optional[int]  # Cube internal timestamp
    
    @property
    def face_name(self) -> str:
        return FACE_NAMES[self.face]
        
    def to_dict(self) -> Dict:
        return {
            'face': self.face,
            'direction': self.direction, 
            'move': self.move,
            'serial': self.serial,
            'local_timestamp': self.local_timestamp,
            'cube_timestamp': self.cube_timestamp
        }

@dataclass
class CubeState:
    """Represents the complete cube state."""
    # Corner Permutation: 8 elements, values from 0 to 7
    CP: List[int]
    # Corner Orientation: 8 elements, values from 0 to 2  
    CO: List[int]
    # Edge Permutation: 12 elements, values from 0 to 11
    EP: List[int]
    # Edge Orientation: 12 elements, values from 0 to 1
    EO: List[int]
    
    @classmethod
    def solved(cls) -> 'CubeState':
        """Return a solved cube state."""
        return cls(
            CP=list(range(8)),
            CO=[0] * 8,
            EP=list(range(12)),
            EO=[0] * 12
        )
    
    def is_solved(self) -> bool:
        """Check if the cube is in solved state."""
        return (self.CP == list(range(8)) and
                self.CO == [0] * 8 and
                self.EP == list(range(12)) and
                self.EO == [0] * 12)

@dataclass
class CubeEvent:
    """Base class for all cube events."""
    timestamp: float
    event_type: str

@dataclass
class MoveEvent(CubeEvent):
    """Move event with cube move data."""
    move: CubeMove
    
    def __init__(self, move: CubeMove, timestamp: Optional[float] = None):
        super().__init__(timestamp or time.time(), "MOVE")
        self.move = move

@dataclass
class FaceletsEvent(CubeEvent):
    """Facelets state event."""
    serial: int
    facelets: str  # Kociemba notation
    state: CubeState
    
    def __init__(self, serial: int, facelets: str, state: CubeState, timestamp: Optional[float] = None):
        super().__init__(timestamp or time.time(), "FACELETS")
        self.serial = serial
        self.facelets = facelets
        self.state = state

@dataclass
class BatteryEvent(CubeEvent):
    """Battery level event."""
    battery_level: int  # 0-100
    
    def __init__(self, battery_level: int, timestamp: Optional[float] = None):
        super().__init__(timestamp or time.time(), "BATTERY")
        self.battery_level = battery_level

@dataclass
class HardwareEvent(CubeEvent):
    """Hardware information event."""
    hardware_name: Optional[str] = None
    software_version: Optional[str] = None
    hardware_version: Optional[str] = None
    product_date: Optional[str] = None
    gyro_supported: Optional[bool] = None
    
    def __init__(self, timestamp: Optional[float] = None, **kwargs):
        super().__init__(timestamp or time.time(), "HARDWARE")
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

@dataclass
class SolvedEvent(CubeEvent):
    """Cube solved state event."""
    serial: int
    
    def __init__(self, serial: int, timestamp: Optional[float] = None):
        super().__init__(timestamp or time.time(), "SOLVED")
        self.serial = serial

def derive_key_iv(mac_address: str) -> Tuple[bytes, bytes]:
    """Derive AES key and IV from MAC address (salt-based approach matching JavaScript)."""
    # Base key and IV from JavaScript GAN_ENCRYPTION_KEYS[0]
    base_key = bytes([0x01, 0x02, 0x42, 0x28, 0x31, 0x91, 0x16, 0x07, 0x20, 0x05, 0x18, 0x54, 0x42, 0x11, 0x12, 0x53])
    base_iv = bytes([0x11, 0x03, 0x32, 0x28, 0x21, 0x01, 0x76, 0x27, 0x20, 0x95, 0x78, 0x14, 0x32, 0x12, 0x02, 0x43])
    
    # Extract MAC bytes as salt (handle both MAC and UUID formats)
    # BREAKTHROUGH: This specific GAN356 i Carry 2 variant uses FIRST 12 chars of UUID, not last 12!
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()
    
    if len(mac_clean) == 12:
        # Traditional MAC address format (AA:BB:CC:DD:EE:FF)
        salt = bytes.fromhex(mac_clean)
    elif len(mac_clean) == 32:
        # UUID format from macOS BLE - use FIRST 12 hex chars (6 bytes) for this cube variant
        salt = bytes.fromhex(mac_clean[:12])  # Changed from [-12:] to [:12]
    else:
        raise ValueError(f"Invalid MAC/UUID format: {mac_address} (cleaned: {mac_clean})")
    
    # JavaScript reverses MAC bytes once while extracting, then again when building salt.
    # Net result: SALT = reversed(MAC bytes) relative to usual "AA:BB:CC:DD:EE:FF" order.
    salt = salt[::-1]
    
    # Apply salt to first 6 bytes of key and IV (matching JavaScript exactly)
    key = bytearray(base_key)
    iv = bytearray(base_iv)
    for i in range(6):
        key[i] = (base_key[i] + salt[i]) % 0xFF
        iv[i] = (base_iv[i] + salt[i]) % 0xFF
    
    return bytes(key), bytes(iv)

def _aes(key: bytes) -> AES:  # AES‑128 ECB helper
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    return AES.new(key, AES.MODE_ECB)

def decrypt_packet(raw: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt a GAN notification using JavaScript-matching dual-chunk approach.
    
    JavaScript implementation decrypts:
    1. 16-byte chunk at start (offset 0)
    2. 16-byte chunk at end (offset length-16) if length > 16
    
    This matches the GanGen2CubeEncrypter.decrypt() method.
    """
    if len(raw) < 16:
        raise ValueError('Data must be at least 16 bytes long')
    
    # Create a copy to decrypt in-place
    result = bytearray(raw)
    
    # JavaScript decrypts the **last** 16-byte block first, then the first.
    # The IV is reused for both decryptions, matching gan-web-bluetooth.

    # 1. Decrypt trailing 16-byte chunk (if present)
    if len(result) > 16:
        end_offset = len(result) - 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        chunk = cipher.decrypt(result[end_offset:end_offset + 16])
        result[end_offset:end_offset + 16] = chunk

    # 2. Decrypt leading 16-byte chunk
    cipher = AES.new(key, AES.MODE_CBC, iv)
    chunk = cipher.decrypt(result[0:16])
    result[0:16] = chunk
    
    return bytes(result)

def encrypt_packet(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt a command packet using JavaScript-matching dual-chunk approach.
    
    JavaScript implementation encrypts:
    1. 16-byte chunk at start (offset 0)
    2. 16-byte chunk at end (offset length-16) if length > 16
    
    This matches the GanGen2CubeEncrypter.encrypt() method.
    """
    if len(data) < 16:
        raise ValueError('Data must be at least 16 bytes long')
    
    # Create a copy to encrypt in-place
    result = bytearray(data)
    
    # JavaScript encrypts the **first** 16-byte block first, then the last.
    # The IV is reused for both encryptions, matching gan-web-bluetooth.

    # 1. Encrypt leading 16-byte chunk
    cipher = AES.new(key, AES.MODE_CBC, iv)
    chunk = cipher.encrypt(result[0:16])
    result[0:16] = chunk

    # 2. Encrypt trailing 16-byte chunk (if present)
    if len(result) > 16:
        end_offset = len(result) - 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        chunk = cipher.encrypt(result[end_offset:end_offset + 16])
        result[end_offset:end_offset + 16] = chunk

    return bytes(result)

class ProtocolMessageView:
    """Binary view helper that allows reading arbitrary bit-length words from a byte sequence (similar to JS GanProtocolMessageView)."""

    def __init__(self, message: bytes):
        # Pre-compute full bit string once – faster than repeated bin() calls later on.
        self._bits = ''.join(f'{b:08b}' for b in message)

    def get_bit_word(self, start_bit: int, bit_length: int, little_endian: bool = False) -> int:
        """Return the integer represented by `bit_length` bits starting at `start_bit`.

        If `little_endian` is True and bit_length is a multiple of 8, bytes are interpreted
        in little-endian order (identical to DataView.getUint16/32 in JS version).
        """
        if bit_length <= 0:
            raise ValueError("bit_length must be positive")
        end_bit = start_bit + bit_length
        if end_bit > len(self._bits):
            raise ValueError("Requested bits exceed message length")

        # For <=8 bits we can slice directly.
        if bit_length <= 8:
            return int(self._bits[start_bit:end_bit], 2)

        # For 16/32 bits replicate JS behaviour with optional little endian.
        if bit_length in (16, 32):
            # Collect bytes (big-endian bit order in _bits string)
            byte_values = [int(self._bits[i:i+8], 2) for i in range(start_bit, end_bit, 8)]
            if little_endian:
                byte_values.reverse()
            value = 0
            for b in byte_values:
                value = (value << 8) | b
            return value

        # Generic (rare) path – just parse as big-endian bit string.
        return int(self._bits[start_bit:end_bit], 2)

def is_move_packet(clear: bytes) -> bool:
    """Heuristically decide if a decrypted Gen-2/3 packet contains move data."""
    if not clear:
        return False

    # Gen-3 packets start with 0x55 frame header.
    if clear[0] == 0x55:
        # Require at least header+type+serial+len
        if len(clear) < 4:
            return False
        msg_type = clear[1]
        if msg_type not in (0x01, 0x02):
            return False
        # Keep header and type bytes so downstream bit positions match

    # Legacy / header-stripped checks
    if len(clear) < 16:
        return False

    # At least 16 bytes required for any valid packet we parse
    if len(clear) < 16:
        return False
    # Only 0x01 packets are MOVE events (JavaScript: eventType == 0x01)
    # 0x02 packets are FACELETS events, not moves
    # Handle both 16-byte and 18-byte 0x01 packets
    if clear[1] == 0x01 and len(clear) >= 16:
        try:
            view = ProtocolMessageView(clear)
            face_bits = view.get_bit_word(74, 6)  # Face at bit 74 (6 bits)
            face_map = [2, 32, 8, 1, 16, 4]  # JavaScript face mapping
            is_valid_move = face_bits in face_map
            if not is_valid_move:
                print(f"❓ Unknown face bits: 0x{face_bits:02x} (len={len(clear)})")
            return is_valid_move
        except Exception as e:
            print(f"❌ Error checking move packet: {e}")
            return False
    
    # No other packet types are moves
    return False

# Simple code map derived from real cube capture (16-byte 0x01 packets)
# Updated with current session codes (cube state dependent)
_SIMPLE_CODE_MAP = {
    # Original codes (from earlier session)
    0x0c: "U", 0x0e: "U'",
    0x0f: "R", 0x10: "R'",
    0x15: "L", 0x16: "L'",
    0x17: "D", 0x18: "D'",
    0x19: "B", 0x1b: "B'",
    0x1d: "F", 0x21: "F'",
    # Current session codes (2025-07-20)
    0xbb: "U",   # Current U clockwise
    0xbd: "U'",  # Current U counter-clockwise
    0xbf: "R",   # Current R clockwise
    0xc1: "R'",  # Current R counter-clockwise (inferred)
    0xc5: "L",   # Current L clockwise
    0xc7: "L'",  # Current L counter-clockwise
    0xc9: "D",   # Current D clockwise
    0xcd: "D'",  # Current D counter-clockwise
    0xd1: "B",   # Current B clockwise
    0xd5: "B'",  # Current B counter-clockwise
    0xd9: "F",   # Current F clockwise
    0xe7: "F'",  # Current F counter-clockwise
}


def parse_move_enhanced(clear: bytes) -> CubeMove:
    """Enhanced move parser that extracts all move metadata including serial numbers."""
    
    # Debug: show decrypted packet header
    # print(f"📦 Decrypted packet: {clear.hex()}")
    # Debug individual bytes for move analysis
    # if len(clear) >= 6:
    #     print(f"📊 raw bytes slice: b3={clear[3]:02x}  b4={clear[4]:02x}  b5={clear[5]:02x}")
    
    # Handle Gen3 header (0x55) – first byte header, second byte packet type 0x01 "move".
    if clear and clear[0] == 0x55:
        if len(clear) < 4:
            raise ValueError("Truncated Gen3 packet")
        if clear[1] not in (0x01, 0x02):
            raise ValueError(f"Unexpected packet type 0x{clear[1]:02x}")
        # Leave header/type untouched for bit offsets
    
    if not is_move_packet(clear):
        raise ValueError(f"Packet does not contain move data (len={len(clear)})")
    
    if len(clear) < 16:
        raise ValueError(f"Message too short for move parsing: {len(clear)} bytes")
    
    # JavaScript-style parsing for 16-byte packets (event type 0x01)
    if clear[1] == 0x01 and len(clear) == 16:
        view = ProtocolMessageView(clear)
        
        # Extract direction and face using JavaScript bit positions
        direction = view.get_bit_word(72, 2)  # Direction at bit 72 (2 bits)
        face_bits = view.get_bit_word(74, 6)  # Face at bit 74 (6 bits)
        
        # JavaScript face mapping: [2, 32, 8, 1, 16, 4] -> [U, R, F, D, L, B]
        face_map = [2, 32, 8, 1, 16, 4]
        try:
            face = face_map.index(face_bits)
            face_char = "URFDLB"[face]
            direction_char = " '"[direction] if direction < 2 else "?"
            move_str = (face_char + direction_char).strip()
            
            # Extract serial and timestamp
            cube_timestamp = view.get_bit_word(24, 32, little_endian=True)
            serial = view.get_bit_word(56, 16, little_endian=True)
            
            return CubeMove(face=face, direction=direction, move=move_str,
                            serial=serial, local_timestamp=time.time(), cube_timestamp=cube_timestamp)
        except ValueError:
            print(f"❓ Unknown face bits: 0x{face_bits:02x}")
            return None

    # Special simple-table parsing for variant that uses eventType 0x02 with move byte
    if clear[1] == 0x02:
        move_byte = clear[5]
        table = ["B","B'","F","F'","U","U'","D","D'","R","R'","L","L'"]
        # If obvious move code (0-0x0B) not found, try reversing tail (keep first 2 bytes)
        if move_byte > 0x0B:
            rev = clear[0:2] + clear[:1:-1]
            move_byte = rev[5]
            if move_byte > 0x0B:
                raise ValueError(f"Invalid move byte 0x{move_byte:02x} even after reversal")
            clear = rev
        move_str = table[move_byte]
        face = "URFDLB".index(move_str[0])
        direction = 1 if "'" in move_str else 0
        serial = int.from_bytes(clear[2:4], "little")
        # print(f"🆕 Parsed 0x02 variant: serial={serial}, move={move_str}")  # Too verbose
        return CubeMove(face=face, direction=direction, move=move_str,
                        serial=serial, local_timestamp=time.time(), cube_timestamp=None)

    # Use ProtocolMessageView for standard Gen3 bit-field extraction
    view = ProtocolMessageView(clear)

    # Attempt to parse using canonical JS bit positions
    serial = view.get_bit_word(56, 16, little_endian=True)
    direction = view.get_bit_word(72, 2)
    face_bits = view.get_bit_word(74, 6)

    # If face_bits come back zero, try a fallback: reverse decrypted bytes (excluding 0x55 header) and parse again.
    if face_bits == 0:
        reversed_clear = clear[0:1] + clear[:0:-1]  # keep header byte 0x55 at front, reverse the rest
        view_rev = ProtocolMessageView(reversed_clear)
        serial_rev = view_rev.get_bit_word(56, 16, little_endian=True)
        direction_rev = view_rev.get_bit_word(72, 2)
        face_bits_rev = view_rev.get_bit_word(74, 6)
        if face_bits_rev in [1,2,4,8,16,32]:
            print("🔁 Byte-reversed parsing produced valid face bits")
            clear = reversed_clear
            view = view_rev
            serial = serial_rev
            direction = direction_rev
            face_bits = face_bits_rev

    # Validate face_bits
    if face_bits not in [2,32,8,1,16,4]:
        raise ValueError(f"Invalid face bits 0x{face_bits:02x}")

    face = [2,32,8,1,16,4].index(face_bits)
    move_str = FACE_NAMES[face] + ("'" if direction == 1 else "")

    print(f"🔍 Parsed JS mapping: serial={serial}, face={FACE_NAMES[face]}, dir={direction}")

    if face_bits == 0:
        # Try some other common positions
        alt_positions = [(24, 6), (32, 6), (40, 6), (48, 6), (64, 6), (80, 6)]
        for bit_pos, bit_len in alt_positions:
            test_face_bits = view.get_bit_word(bit_pos, bit_len)
            if test_face_bits in [1, 2, 4, 8, 16, 32]:  # Valid face bit patterns
                print(f"🔍 Found valid face_bits=0x{test_face_bits:02x} at bit position {bit_pos}")
                face_bits = test_face_bits
                # Also try to find direction at nearby positions
                for dir_offset in [-2, -1, 1, 2]:
                    test_direction = view.get_bit_word(bit_pos + dir_offset, 2)
                    if test_direction in [0, 1]:  # Valid direction values
                        direction = test_direction
                        print(f"🔍 Found direction={direction} at bit position {bit_pos + dir_offset}")
                        break
                break
    
    # Debug logging
    print(f"🔍 Parsed: serial={serial}, direction={direction}, face_bits=0x{face_bits:02x}")
    
    # JavaScript face mapping: [2, 32, 8, 1, 16, 4] maps to "URFDLB"
    face_map = [2, 32, 8, 1, 16, 4]
    try:
        face = face_map.index(face_bits)  # This gives us index into "URFDLB"
        print(f"🔍 Face mapped: face_bits=0x{face_bits:02x} -> face={face} ({FACE_NAMES[face]})")
    except ValueError:
        # Fallback if face_bits doesn't match expected values
        print(f"⚠️ Unknown face_bits: 0x{face_bits:02x}, using fallback")
        face = 0  # Default to U
    
    # Create move string notation
    move_str = FACE_NAMES[face] + ("'" if direction == 1 else "")
    
    # Extract timestamps
    cube_timestamp = None
    if len(clear) >= 20:
        cube_timestamp = int.from_bytes(clear[18:20], 'little') * 10
    
    return CubeMove(
        face=face,
        direction=direction,
        move=move_str,
        serial=serial,
        local_timestamp=time.time(),
        cube_timestamp=cube_timestamp
    )

def parse_move(clear: bytes) -> Dict:
    """Legacy parser for backward compatibility."""
    try:
        move = parse_move_enhanced(clear)
        return move.to_dict()
    except Exception:
        # Fallback to original simple parser
        face_chars = 'BURFLD'
        move_byte = clear[5] if len(clear) > 5 else 0
        
        if move_byte == 0: face_name = 'B'
        elif move_byte == 2: face_name = 'F'
        elif move_byte == 4: face_name = 'U' 
        elif move_byte == 6: face_name = 'D'
        elif move_byte == 8: face_name = 'R'
        elif move_byte == 10: face_name = 'L'
        else: face_name = 'B'
        
        return {
            "face": face_chars.index(face_name),
            "dir": 1 if move_byte % 2 == 1 else 0,
            "ts": int.from_bytes(clear[18:20], 'little') * 10 if len(clear) >= 20 else 0,
            "serial": clear[1] if len(clear) > 1 else 0,
            "move": face_name + ("'" if move_byte % 2 == 1 else "")
        }

# ---------------- Cube state ↔ facelets helpers ----------------
CORNER_FACELET_MAP = [
    (8, 9, 20),   # URF
    (6, 18, 38),  # UFL
    (0, 36, 47),  # ULB
    (2, 45, 11),  # UBR
    (29, 26, 15), # DFR
    (27, 44, 24), # DLF
    (33, 53, 42), # DBL
    (35, 17, 51), # DRB
]

EDGE_FACELET_MAP = [
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

FACES_ORDER = "URFDLB"

def to_kociemba_facelets(cp: List[int], co: List[int], ep: List[int], eo: List[int]) -> str:
    """Convert CP/CO/EP/EO arrays to 54-char facelet string (same as JS utils.toKociembaFacelets)."""
    facelets: List[str] = [FACES_ORDER[i // 9] for i in range(54)]

    # Corners
    for i in range(8):
        for p in range(3):
            facelets[CORNER_FACELET_MAP[i][(p + co[i]) % 3]] = FACES_ORDER[CORNER_FACELET_MAP[cp[i]][p] // 9]

    # Edges
    for i in range(12):
        for p in range(2):
            facelets[EDGE_FACELET_MAP[i][(p + eo[i]) % 2]] = FACES_ORDER[EDGE_FACELET_MAP[ep[i]][p] // 9]

    return ''.join(facelets)

# ---------------- Facelets packet parsing (Gen3) ----------------

def _sum(arr: List[int]) -> int:
    return sum(arr)

def parse_facelets_event(clear: bytes) -> Optional[FaceletsEvent]:
    """Parse Gen3 FACELETS event (magic 0x55, eventType 0x02)."""
    if len(clear) < 20 or clear[0] != 0x55:
        return None

    # Event type byte is second (index 1)
    if clear[1] != 0x02:
        return None

    view = ProtocolMessageView(clear)

    # Serial is 16-bit little-endian starting at bit 24
    serial = view.get_bit_word(24, 16, little_endian=True)

    # Parse CP/CO/EP/EO according to JS GanGen3ProtocolDriver
    cp: List[int] = []
    co: List[int] = []
    ep: List[int] = []
    eo: List[int] = []

    # Corners 0-6 (3 bits each) start at bit 40, stride 3
    for i in range(7):
        cp.append(view.get_bit_word(40 + i * 3, 3))
        co.append(view.get_bit_word(61 + i * 2, 2))
    cp.append(28 - _sum(cp))
    co.append((3 - (_sum(co) % 3)) % 3)

    # Edges 0-10 (4 bits each) start at bit 77, stride 4
    for i in range(11):
        ep.append(view.get_bit_word(77 + i * 4, 4))
        eo.append(view.get_bit_word(121 + i, 1))
    ep.append(66 - _sum(ep))
    eo.append((2 - (_sum(eo) % 2)) % 2)

    state = CubeState(CP=cp, CO=co, EP=ep, EO=eo)
    facelets = to_kociemba_facelets(cp, co, ep, eo)

    return FaceletsEvent(
        serial=serial,
        facelets=facelets,
        state=state
    )

def parse_battery_event(clear: bytes) -> Optional[BatteryEvent]:
    """Parse a battery level event from decrypted packet."""
    if len(clear) < 4:
        return None
        
    # Battery level is typically in byte 2 or 3
    battery_level = clear[2] if clear[2] <= 100 else clear[3]
    
    return BatteryEvent(battery_level=min(battery_level, 100))

def parse_hardware_event(packet: bytes) -> Optional[HardwareEvent]:
    """Parse hardware information event from packet."""
    try:
        clear = decrypt_packet(packet)
        if len(clear) < 16:
            return None
        
        # Hardware events are typically longer packets with specific structure
        # This is a placeholder - actual parsing would depend on packet format
        return HardwareEvent()
        
    except Exception as e:
        print(f"❌ Error parsing hardware event: {e}")
        return None

def parse_facelets_event(clear: bytes) -> Optional[FaceletsEvent]:
    """Parse facelets state event from already-decrypted packet."""
    try:
        if len(clear) < 16:
            return None
        
        # Check if this is a facelets packet (0x02 event type)
        if clear[0] != 0x55 or clear[1] != 0x02:
            return None
            
        # Extract serial number
        view = ProtocolMessageView(clear)
        serial = view.get_bit_word(24, 16, little_endian=True)
        
        # Parse cube state from packet (simplified - would need full implementation)
        # For now, we'll extract what we can and build a basic facelets string
        facelets = extract_facelets_from_packet(clear)
        
        return FaceletsEvent(
            serial=serial,
            facelets=facelets,
            state=CubeState(CP=[0]*8, CO=[0]*8, EP=[0]*12, EO=[0]*12)  # Placeholder solved state
        )
        
    except Exception as e:
        print(f"❌ Error parsing facelets event: {e}")
        return None

def extract_facelets_from_packet(clear: bytes) -> str:
    """Extract facelets string from decrypted packet using Gen3 protocol."""
    if len(clear) < 19:
        return SOLVED_STATE  # Default to solved if packet too short
    
    # Parse using Gen3 protocol (based on JavaScript implementation)
    view = ProtocolMessageView(clear)
    
    # Corner/Edge Permutation/Orientation
    cp = []
    co = []
    ep = []
    eo = []
    
    # Corners - extract 7 values, calculate 8th
    for i in range(7):
        cp.append(view.get_bit_word(40 + i * 3, 3))
        co.append(view.get_bit_word(61 + i * 2, 2))
    cp.append(28 - sum(cp))  # 8th corner permutation
    co.append((3 - (sum(co) % 3)) % 3)  # 8th corner orientation
    
    # Edges - extract 11 values, calculate 12th
    for i in range(11):
        ep.append(view.get_bit_word(77 + i * 4, 4))
        eo.append(view.get_bit_word(121 + i, 1))
    ep.append(66 - sum(ep))  # 12th edge permutation
    eo.append((2 - (sum(eo) % 2)) % 2)  # 12th edge orientation
    
    # Convert to Kociemba facelets string
    return to_kociemba_facelets(cp, co, ep, eo)

def to_kociemba_facelets(cp: list, co: list, ep: list, eo: list) -> str:
    """Convert Corner/Edge Permutation/Orientation cube state to Kociemba facelets string.
    
    Based on JavaScript implementation from gan-web-bluetooth library.
    
    Args:
        cp: Corner Permutation (8 values)
        co: Corner Orientation (8 values)
        ep: Edge Permutation (12 values)
        eo: Edge Orientation (12 values)
    
    Returns:
        54-character facelets string in Kociemba notation
    """
    faces = "URFDLB"
    facelets = []
    
    # Initialize facelets array with face centers
    for i in range(54):
        facelets.append(faces[i // 9])
    
    # Apply corner permutations and orientations
    for i in range(8):
        for p in range(3):
            facelet_idx = CORNER_FACELET_MAP[i][(p + co[i]) % 3]
            corner_face_idx = CORNER_FACELET_MAP[cp[i]][p] // 9
            facelets[facelet_idx] = faces[corner_face_idx]
    
    # Apply edge permutations and orientations
    for i in range(12):
        for p in range(2):
            facelet_idx = EDGE_FACELET_MAP[i][(p + eo[i]) % 2]
            edge_face_idx = EDGE_FACELET_MAP[ep[i]][p] // 9
            facelets[facelet_idx] = faces[edge_face_idx]
    
    return ''.join(facelets)

def is_solved_state(facelets: str) -> bool:
    """Check if facelets string represents solved state."""
    return facelets == SOLVED_STATE

def is_solved_packet(packet: bytes) -> bool:
    """Check if packet represents a solved state event."""
    try:
        clear = decrypt_packet(packet)
        if len(clear) < 16:
            return False
        
        # DISABLED: 18-byte solved packet detection was causing false positives
        # The cube sends 20-byte move packets that were being misidentified as solved packets
        # Only rely on facelets-based solved detection for now
        return False
        
    except Exception:
        return False

def parse_solved_event(packet: bytes) -> Optional[SolvedEvent]:
    """Parse solved state event from 18-byte 0x01 packet."""
    try:
        clear = decrypt_packet(packet)
        if not is_solved_packet(packet):
            return None
        
        # Extract serial number from the packet (similar to move packets)
        view = ProtocolMessageView(clear)
        serial = view.get_bit_word(56, 16, little_endian=True)
        
        return SolvedEvent(serial=serial)
        
    except Exception as e:
        print(f"❌ Error parsing solved event: {e}")
        return None
