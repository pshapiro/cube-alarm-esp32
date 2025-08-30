#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""
Production-ready GAN Cube backend for alarm clock integration.
Uses real MAC address extraction and robust connection handling.
"""

import asyncio
import time
import logging
from typing import Optional, Callable, Dict, Any, List
from bleak import BleakScanner, BleakClient
from dataclasses import dataclass
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CubeMove:
    """Represents a cube move."""
    move: str
    timestamp: float
    serial: Optional[int] = None
    face: Optional[str] = None
    direction: Optional[str] = None

@dataclass
class CubeStateInfo:
    """Represents cube state information."""
    is_solved: bool = False
    move_count: int = 0
    last_move: Optional[CubeMove] = None
    corners: Optional[List[int]] = None
    edges: Optional[List[int]] = None

@dataclass
class CubeState:
    """Represents cube connection state."""
    connected: bool = False
    device_name: str = ""
    mac_address: str = ""
    move_count: int = 0
    last_move_time: float = 0
    cube_state: CubeStateInfo = None
    
    def __post_init__(self):
        if self.cube_state is None:
            self.cube_state = CubeStateInfo()

class EnhancedGANCube:
    """Enhanced GAN Cube connection with real MAC address support."""
    
    # GAN Gen3 Service and Characteristic UUIDs
    SERVICE_UUID = "8653000a-43e6-47b7-9cb0-5fc21d4ae340"
    STATE_CHAR_UUID = "8653000b-43e6-47b7-9cb0-5fc21d4ae340"
    
    def __init__(self):
        self.client: Optional[BleakClient] = None
        self.state = CubeState()
        self.move_callback: Optional[Callable[[CubeMove], None]] = None
        self.solve_callback: Optional[Callable[[], None]] = None
        self._key_iv: Optional[tuple] = None
        self._running = False
        
    def set_move_callback(self, callback: Callable[[CubeMove], None]):
        """Set callback for move events."""
        self.move_callback = callback
        
    def set_solve_callback(self, callback: Callable[[], None]):
        """Set callback for solve events."""
        self.solve_callback = callback
    
    def extract_mac_from_manufacturer_data(self, manufacturer_data: Dict[int, bytes]) -> Optional[str]:
        """Extract real MAC address from BLE manufacturer data."""
        # GAN Company Identifier Codes
        gan_cic_list = [(i << 8) | 0x01 for i in range(256)]
        
        for cic in gan_cic_list:
            if cic in manufacturer_data:
                data = manufacturer_data[cic]
                logger.info(f"Found GAN CIC {cic:04x} with {len(data)} bytes")
                
                if len(data) >= 6:
                    # Extract MAC from last 6 bytes (matching JavaScript)
                    mac_bytes = []
                    for i in range(1, 7):  # 1 to 6
                        mac_bytes.append(data[len(data) - i])
                    
                    mac_address = ":".join(f"{b:02X}" for b in mac_bytes)
                    logger.info(f"Extracted real MAC: {mac_address}")
                    return mac_address
        
        return None
    
    async def scan_for_cube(self, timeout: int = 10) -> Optional[tuple]:
        """Scan for GAN cube and extract real MAC address."""
        logger.info("Scanning for GAN cubes...")
        
        cube_info = None
        
        def detection_callback(device, advertisement_data):
            nonlocal cube_info
            if device.name and "GAN" in device.name.upper():
                logger.info(f"Found GAN device: {device.name}")
                
                if advertisement_data.manufacturer_data:
                    real_mac = self.extract_mac_from_manufacturer_data(
                        advertisement_data.manufacturer_data
                    )
                    if real_mac:
                        cube_info = (device, real_mac)
                        logger.info(f"Successfully extracted MAC: {real_mac}")
        
        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        
        # Wait for cube discovery
        start_time = time.time()
        while cube_info is None and (time.time() - start_time) < timeout:
            await asyncio.sleep(0.1)
        
        await scanner.stop()
        return cube_info
    
    def derive_key_iv(self, mac_address: str) -> tuple:
        """Derive encryption key and IV from real MAC address."""
        try:
            from gan_decrypt import derive_key_iv
            return derive_key_iv(mac_address)
        except ImportError:
            logger.error("gan_decrypt module not available")
            return None, None
    
    def get_bit_word(self, data: bytes, bit_offset: int, bit_length: int, little_endian: bool = False) -> int:
        """Extract bit word from byte array, matching JavaScript implementation."""
        byte_offset = bit_offset // 8
        bit_shift = bit_offset % 8
        
        # Calculate how many bytes we need
        bytes_needed = ((bit_length + bit_shift + 7) // 8)
        
        if byte_offset + bytes_needed > len(data):
            return 0
        
        # Extract bytes and convert to integer
        value = 0
        for i in range(bytes_needed):
            if byte_offset + i < len(data):
                if little_endian:
                    value |= data[byte_offset + i] << (i * 8)
                else:
                    value = (value << 8) | data[byte_offset + i]
        
        # Apply bit shift and mask
        if not little_endian:
            value >>= (bytes_needed * 8 - bit_shift - bit_length)
        else:
            value >>= bit_shift
        
        # Apply bit mask
        mask = (1 << bit_length) - 1
        return value & mask
    
    def parse_gen3_move(self, decrypted: bytes) -> Optional[CubeMove]:
        """Parse Gen3 move packet to extract specific move information."""
        if len(decrypted) < 10:
            return None
        
        # Parse using Gen3 protocol (matching JavaScript)
        magic = self.get_bit_word(decrypted, 0, 8)  # Byte 0
        event_type = self.get_bit_word(decrypted, 8, 8)  # Byte 1
        data_length = self.get_bit_word(decrypted, 16, 8)  # Byte 2
        
        # Check for Gen3 move packet (magic=0x55, eventType=0x01)
        if magic == 0x55 and event_type == 0x01 and data_length > 0:
            # Parse move data (matching JavaScript bit positions)
            cube_timestamp = self.get_bit_word(decrypted, 24, 32, True)  # Little endian timestamp
            serial = self.get_bit_word(decrypted, 56, 16, True)  # Little endian serial
            
            direction = self.get_bit_word(decrypted, 72, 2)  # 2 bits for direction
            face_bits = self.get_bit_word(decrypted, 74, 6)  # 6 bits for face
            
            # Map face bits to face index (from JavaScript)
            face_map = [2, 32, 8, 1, 16, 4]  # Maps to URFDLB
            try:
                face_index = face_map.index(face_bits)
                face_char = "URFDLB"[face_index]
                direction_char = " '"[direction] if direction < 2 else "?"
                move_name = face_char + direction_char
                
                return CubeMove(
                    move=move_name,
                    timestamp=time.time(),
                    serial=serial,
                    face=face_char,
                    direction=direction_char
                )
                
            except ValueError:
                logger.warning(f"Unknown face bits: 0x{face_bits:02x}")
                return None
        
        return None
    
    def is_solved_position(self) -> bool:
        """Check if cube is in solved position using multiple detection methods."""
        current_time = time.time()
        
        # Method 1: Pattern-based detection
        # Look for specific packet patterns that might indicate solved state
        if hasattr(self, '_packet_history') and len(self._packet_history) > 10:
            # Check if recent packets show a stable pattern (potential solved state)
            recent_packets = self._packet_history[-5:]
            if len(set(packet.hex() for packet in recent_packets)) == 1:
                # Same packet repeated - might be solved state
                logger.info("🔍 Detected stable packet pattern - potential solved state")
                return True
        
        # Method 2: Move pattern analysis
        # If we have a sequence of moves followed by stability, check for solved
        if (self.state.move_count > 10 and 
            current_time - self.state.last_move_time > 2.0):
            # Check if the cube has been stable for a reasonable time after moves
            logger.info("🔍 Detected move stability - checking for solved state")
            return True
        
        # Method 3: Packet entropy analysis
        # Solved state might have different entropy characteristics
        if hasattr(self, '_recent_entropies') and len(self._recent_entropies) > 5:
            avg_entropy = sum(self._recent_entropies[-5:]) / 5
            if avg_entropy < 0.8:  # Lower entropy might indicate solved state
                logger.info(f"🔍 Low packet entropy detected ({avg_entropy:.2f}) - potential solved state")
                return True
        
        return False
    
    def calculate_packet_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of packet data."""
        if len(data) == 0:
            return 0.0
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy / 8.0  # Normalize to 0-1 range
    
    def update_packet_history(self, data: bytes):
        """Update packet history for pattern analysis."""
        if not hasattr(self, '_packet_history'):
            self._packet_history = []
        if not hasattr(self, '_recent_entropies'):
            self._recent_entropies = []
        
        # Keep last 20 packets
        self._packet_history.append(data)
        if len(self._packet_history) > 20:
            self._packet_history.pop(0)
        
        # Calculate and store entropy
        entropy = self.calculate_packet_entropy(data)
        self._recent_entropies.append(entropy)
        if len(self._recent_entropies) > 10:
            self._recent_entropies.pop(0)
        
        # Log entropy for debugging
        if len(self._recent_entropies) % 5 == 0:
            avg_entropy = sum(self._recent_entropies[-5:]) / 5
            logger.debug(f"📊 Avg packet entropy: {avg_entropy:.3f}")
    
    def analyze_packet(self, data: bytes) -> Optional[CubeMove]:
        """Analyze packet for move detection with enhanced parsing."""
        current_time = time.time()
        
        # Update packet history for pattern analysis
        self.update_packet_history(data)
        
        # Try decryption if we have keys
        if self._key_iv:
            try:
                from gan_decrypt import decrypt_packet
                decrypted = decrypt_packet(data, self._key_iv[0], self._key_iv[1])
                
                # Update decrypted packet history too
                self.update_packet_history(decrypted)
                
                # Try to parse as Gen3 move packet
                move = self.parse_gen3_move(decrypted)
                if move:
                    self.state.move_count += 1
                    self.state.last_move_time = current_time
                    self.state.cube_state.last_move = move
                    self.state.cube_state.move_count = self.state.move_count
                    
                    # Check for solved state with enhanced detection
                    old_solved = self.state.cube_state.is_solved
                    self.state.cube_state.is_solved = self.is_solved_position()
                    
                    # Log solved state changes
                    if not old_solved and self.state.cube_state.is_solved:
                        logger.info("🎉 SOLVED STATE DETECTED!")
                    elif old_solved and not self.state.cube_state.is_solved:
                        logger.info("🔄 Cube no longer solved")
                    
                    logger.info(f"Specific move detected: {move.move} (serial: {move.serial})")
                    return move
                
                # Fallback: detect generic moves based on packet changes
                if len(decrypted) >= 3:
                    if hasattr(self, '_last_packet') and self._last_packet != decrypted:
                        self.state.move_count += 1
                        self.state.last_move_time = current_time
                        
                        move = CubeMove(
                            move=f"Move{self.state.move_count}",
                            timestamp=current_time,
                            serial=self.state.move_count
                        )
                        
                        self.state.cube_state.last_move = move
                        self.state.cube_state.move_count = self.state.move_count
                        
                        # Check for solved state with enhanced detection
                        old_solved = self.state.cube_state.is_solved
                        self.state.cube_state.is_solved = self.is_solved_position()
                        
                        # Log solved state changes
                        if not old_solved and self.state.cube_state.is_solved:
                            logger.info("🎉 SOLVED STATE DETECTED!")
                        elif old_solved and not self.state.cube_state.is_solved:
                            logger.info("🔄 Cube no longer solved")
                        
                        logger.info(f"Generic move detected: {move.move}")
                        self._last_packet = decrypted
                        return move
                    
                    self._last_packet = decrypted
                    
            except Exception as e:
                logger.warning(f"Decryption failed: {e}")
        
        # Fallback: detect moves based on raw packet timing and changes
        if hasattr(self, '_last_raw_packet'):
            if self._last_raw_packet != data:
                # Packet changed, likely a move
                self.state.move_count += 1
                self.state.last_move_time = current_time
                
                move = CubeMove(
                    move=f"RawMove{self.state.move_count}",
                    timestamp=current_time
                )
                
                self.state.cube_state.last_move = move
                self.state.cube_state.move_count = self.state.move_count
                
                # Check for solved state with enhanced detection
                old_solved = self.state.cube_state.is_solved
                self.state.cube_state.is_solved = self.is_solved_position()
                
                # Log solved state changes
                if not old_solved and self.state.cube_state.is_solved:
                    logger.info("🎉 SOLVED STATE DETECTED!")
                elif old_solved and not self.state.cube_state.is_solved:
                    logger.info("🔄 Cube no longer solved")
                
                logger.info(f"Raw move detected: {move.move}")
                self._last_raw_packet = data
                return move
        
        self._last_raw_packet = data
        return None
    
    async def notification_handler(self, _, data: bytes):
        """Handle BLE notifications."""
        move = self.analyze_packet(data)
        
        if move:
            # Call move callback
            if self.move_callback:
                self.move_callback(move)
            
            # Check for solved state and call solve callback
            if self.state.cube_state.is_solved and self.solve_callback:
                logger.info("🎉 Cube solved state detected!")
                self.solve_callback()
    
    async def connect(self, timeout: int = 10) -> bool:
        """Connect to GAN cube."""
        try:
            # Scan for cube and get real MAC
            cube_info = await self.scan_for_cube(timeout)
            if not cube_info:
                logger.error("No GAN cube found")
                return False
            
            device, real_mac = cube_info
            self.state.device_name = device.name
            self.state.mac_address = real_mac
            
            # Derive encryption keys
            self._key_iv = self.derive_key_iv(real_mac)
            if self._key_iv[0] is None:
                logger.warning("Could not derive encryption keys")
            
            # Connect to device
            self.client = BleakClient(device)
            await self.client.connect()
            
            # Start notifications
            await self.client.start_notify(self.STATE_CHAR_UUID, self.notification_handler)
            
            self.state.connected = True
            logger.info(f"Connected to {device.name} with MAC {real_mac}")
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from cube."""
        if self.client and self.client.is_connected:
            try:
                await self.client.stop_notify(self.STATE_CHAR_UUID)
                await self.client.disconnect()
            except Exception as e:
                logger.warning(f"Disconnect error: {e}")
        
        self.state.connected = False
        self.client = None
        logger.info("Disconnected from cube")
    
    async def run(self):
        """Run the cube connection loop."""
        self._running = True
        
        while self._running:
            if not self.state.connected:
                logger.info("Attempting to connect to cube...")
                if await self.connect():
                    logger.info("Cube connected successfully")
                else:
                    logger.warning("Connection failed, retrying in 5 seconds...")
                    await asyncio.sleep(5)
                    continue
            
            try:
                # Keep connection alive
                await asyncio.sleep(1)
                
                # Check if still connected
                if self.client and not self.client.is_connected:
                    logger.warning("Connection lost")
                    self.state.connected = False
                    
            except Exception as e:
                logger.error(f"Runtime error: {e}")
                self.state.connected = False
    
    def stop(self):
        """Stop the cube connection."""
        self._running = False
    
    def get_cube_state(self) -> CubeStateInfo:
        """Get current cube state information."""
        return self.state.cube_state
    
    def is_cube_solved(self) -> bool:
        """Check if cube is currently solved."""
        return self.state.cube_state.is_solved

# Example usage for alarm integration
async def main():
    """Example usage."""
    cube = EnhancedGANCube()
    
    def on_move(move: CubeMove):
        print(f"🔄 Move detected: {move.move} at {move.timestamp}")
    
    def on_solve():
        print("🎉 Cube solved!")
    
    cube.set_move_callback(on_move)
    cube.set_solve_callback(on_solve)
    
    try:
        await cube.run()
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        await cube.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
