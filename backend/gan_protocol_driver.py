# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""
Enhanced GAN Cube Protocol Driver
Implements robust move tracking, serial number handling, and missed move recovery
based on the gan-web-bluetooth JavaScript implementation.
"""

from __future__ import annotations
import asyncio
import time
from typing import List, Dict, Optional, Callable, Any
from collections import deque
from dataclasses import dataclass
from abc import ABC, abstractmethod

try:
    from .gan_decrypt import (
        CubeMove, CubeEvent, MoveEvent, FaceletsEvent, BatteryEvent, HardwareEvent, SolvedEvent,
        CubeState, parse_move_enhanced, parse_facelets_event, parse_battery_event,
        parse_hardware_event, parse_solved_event, is_solved_packet, decrypt_packet,
        is_move_packet, is_solved_state
    )
except ImportError:
    from gan_decrypt import (
        CubeMove, CubeEvent, MoveEvent, FaceletsEvent, BatteryEvent, HardwareEvent, SolvedEvent,
        CubeState, parse_move_enhanced, parse_facelets_event, parse_battery_event,
        parse_hardware_event, parse_solved_event, is_solved_packet, decrypt_packet,
        is_move_packet, is_solved_state
    )


class GanProtocolDriver(ABC):
    """Base class for GAN cube protocol drivers."""
    
    @abstractmethod
    async def handle_state_event(self, raw_connection: 'GanCubeRawConnection', 
                                event_message: bytes) -> List[CubeEvent]:
        """Handle binary event messages from cube device."""
        pass
    
    @abstractmethod
    def create_command_message(self, command: Dict[str, Any]) -> Optional[bytes]:
        """Create binary command message for cube device."""
        pass


class GanGen3ProtocolDriver(GanProtocolDriver):
    """
    Driver implementation for GAN Gen3 protocol, supported cubes:
    - GAN356 i Carry 2
    """
    
    def __init__(self):
        self.serial = -1
        self.last_serial = -1
        self.last_local_timestamp: Optional[float] = None
        self.move_buffer: deque[CubeEvent] = deque(maxlen=100)  # FIFO buffer for moves
        self.last_solved_state: Optional[bool] = None  # Track solved state changes
        
    def create_command_message(self, command: Dict[str, Any]) -> Optional[bytes]:
        """Create binary command message for cube device."""
        cmd_type = command.get("type")
        
        if cmd_type == "REQUEST_HARDWARE":
            return bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        elif cmd_type == "REQUEST_FACELETS":
            return bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        elif cmd_type == "REQUEST_BATTERY":
            return bytes([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        elif cmd_type == "REQUEST_RESET":
            # Gen3 reset command from JavaScript implementation
            reset_cmd = bytes([0x68, 0x05, 0x05, 0x39, 0x77, 0x00, 0x00, 0x01, 
                              0x23, 0x45, 0x67, 0x89, 0xAB, 0x00, 0x00, 0x00])
            print(f"🔧 DEBUG: Creating reset command: {reset_cmd.hex()}")
            return reset_cmd
        
        return None
    
    async def request_move_history(self, conn: 'GanCubeRawConnection', 
                                  serial: int, count: int) -> None:
        """Private cube command for requesting move history."""
        # Create move history request command
        cmd = bytes([0x05, serial, count, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        await conn.send_command_message(cmd)
    
    def is_serial_in_range(self, start: int, end: int, serial: int, 
                          closed_start: bool = False, closed_end: bool = False) -> bool:
        """
        Check if circular serial number (modulo 256) fits into (start,end) serial number range.
        By default range is open, set closed_start / closed_end to make it closed.
        """
        # Handle circular serial numbers (0-255)
        if start <= end:
            if closed_start and closed_end:
                return start <= serial <= end
            elif closed_start:
                return start <= serial < end
            elif closed_end:
                return start < serial <= end
            else:
                return start < serial < end
        else:  # Wrap around case
            if closed_start and closed_end:
                return serial >= start or serial <= end
            elif closed_start:
                return serial >= start or serial < end
            elif closed_end:
                return serial > start or serial <= end
            else:
                return serial > start or serial < end
    
    def inject_missed_move_to_buffer(self, move_event: CubeEvent) -> None:
        """Used to inject missed moves to FIFO buffer."""
        self.move_buffer.append(move_event)
    
    async def evict_move_buffer(self, conn: Optional['GanCubeRawConnection'] = None) -> List[CubeEvent]:
        """
        Evict move events from FIFO buffer until missing move event detected.
        In case of missing move, and if connection is provided, submit request for move history to fill gap in buffer.
        """
        events = []
        
        while self.move_buffer:
            event = self.move_buffer[0]
            
            if isinstance(event, MoveEvent):
                expected_serial = (self.last_serial + 1) % 256
                
                if event.move.serial == expected_serial:
                    # Move is in sequence, evict it
                    self.move_buffer.popleft()
                    events.append(event)
                    self.last_serial = event.move.serial
                    self.last_local_timestamp = event.move.local_timestamp
                else:
                    # Missing move detected
                    if conn and self.is_serial_in_range(self.last_serial, event.move.serial, expected_serial):
                        # Request missing moves
                        missing_count = (event.move.serial - expected_serial) % 256
                        await self.request_move_history(conn, expected_serial, missing_count)
                    break
            else:
                # Non-move event, just evict
                self.move_buffer.popleft()
                events.append(event)
        
        return events
    
    async def check_if_move_missed(self, conn: 'GanCubeRawConnection') -> None:
        """Used in response to periodic facelets event to check if any moves missed."""
        if self.last_local_timestamp and time.time() - self.last_local_timestamp > 5.0:
            # No moves for 5 seconds, request recent move history
            await self.request_move_history(conn, (self.last_serial + 1) % 256, 10)
    
    async def _track_move_for_solved_detection(self, conn: 'GanCubeConnection', move: CubeMove, events: List[CubeEvent]) -> None:
        """Track moves and detect when cube returns to solved state."""
        # Skip if this is not a proper GanCubeConnection object
        if not hasattr(conn, '_last_move_serial'):
            return
            
        # Skip if this is a duplicate serial (already processed)
        if move.serial == conn._last_move_serial:
            return
        
        conn._last_move_serial = move.serial
        prime_mark = "'" if move.direction == 1 else ""
        move_notation = f"{move.face}{prime_mark}"
        
        # Add move to history (keep last 50 moves for efficiency)
        conn._move_history.append(move_notation)
        if len(conn._move_history) > 50:
            conn._move_history.pop(0)
        
        # Mark as not solved when any move is made
        if conn._is_solved:
            conn._is_solved = False
            print(f"🔄 Cube scrambled with move: {move_notation}")
        
        # Check for solved state using move cancellation patterns
        if self._check_solved_by_move_cancellation(conn._move_history):
            if not conn._is_solved:  # Only trigger if not already marked as solved
                conn._is_solved = True
                print(f"🎉 Cube solved! Last move: {move_notation}")
                
                # Create and emit solved event
                solved_event = SolvedEvent(
                    timestamp=time.time(),
                    facelets="UUUUUUUUURRRRRRRRRDDDDDDDDDLLLLLLLLLFFFFFFFFBBBBBBBBB",  # Solved state
                    state=CubeState.solved()
                )
                events.append(solved_event)
    
    def _check_solved_by_move_cancellation(self, move_history: List[str]) -> bool:
        """Check if recent moves indicate cube is solved using move cancellation patterns."""
        if len(move_history) < 2:
            return False
        
        # Check for immediate cancellation (e.g., U followed by U')
        last_move = move_history[-1]
        second_last = move_history[-2]
        
        # Parse moves
        def parse_move(move_str):
            if move_str.endswith("'"):
                return move_str[:-1], True  # face, is_prime
            else:
                return move_str, False
        
        last_face, last_prime = parse_move(last_move)
        second_face, second_prime = parse_move(second_last)
        
        # Check for direct cancellation (U followed by U', or U' followed by U)
        if last_face == second_face and last_prime != second_prime:
            print(f"🔍 Move cancellation detected: {second_last} → {last_move}")
            return True
        
        # Check for 4-move cycles (U U U U = solved, or U' U' U' U' = solved)
        if len(move_history) >= 4:
            last_4 = move_history[-4:]
            if all(move == last_4[0] for move in last_4):
                face, is_prime = parse_move(last_4[0])
                print(f"🔍 4-move cycle detected: {' '.join(last_4)}")
                return True
        
        return False
    
    async def handle_state_event(self, conn: 'GanCubeRawConnection', 
                                event_message: bytes) -> List[CubeEvent]:
        """Handle binary event messages from cube device."""
        events = []
        
        if len(event_message) < 16:
            return events
        
        # Extract packet type from byte 1 (JavaScript: eventType = msg.getBitWord(8, 8))
        packet_type = event_message[1] if len(event_message) > 1 else 0
        magic_byte = event_message[0] if len(event_message) > 0 else 0
        
        try:
            # Import here to avoid circular imports
            try:
                from .gan_decrypt import is_move_packet
            except ImportError:
                from gan_decrypt import is_move_packet
            
            # First attempt to parse as Gen3 facelets event (may be >16 bytes)
            facelets_evt = parse_facelets_event(event_message)
            if facelets_evt:
                events.append(facelets_evt)
                await self.check_if_move_missed(conn)

            if is_move_packet(event_message):
                move = parse_move_enhanced(event_message)
                if move:
                    # Check for duplicate serial numbers (like JavaScript implementation)
                    if move.serial != self.serial:
                        # Update serial tracking (like JavaScript: this.serial = serial)
                        self.last_serial = self.serial
                        self.serial = move.serial
                        self.last_local_timestamp = time.time()
                        move_event = MoveEvent(move, timestamp=time.time())
                    
                        # Add to buffer for ordering
                        self.move_buffer.append(move_event)

                        # Always emit the move immediately so callers get timely updates
                        events.append(move_event)
                        
                        # Additionally evict any subsequently ordered moves (fills gaps)
                        ordered_events = await self.evict_move_buffer(conn)
                        events.extend(ordered_events)
                    # else: Skip duplicate move packets with same serial (no action needed)
            elif len(event_message) == 19 and packet_type == 0x02:
                # 19-byte 0x02 packets are FACELETS events (cube state)
                # event_message is already decrypted by handle_notification
                facelets_event = parse_facelets_event(event_message)
                if facelets_event:
                    events.append(facelets_event)
                    
                    # DEBUG: Log facelets string and solved state check
                    print(f"🔍 DEBUG: Full facelets: {facelets_event.facelets}")
                    current_solved_state = is_solved_state(facelets_event.facelets)
                    print(f"🔍 DEBUG: is_solved_state() = {current_solved_state}, last_solved = {getattr(self, 'last_solved_state', None)}")
                    
                    # Only emit solved event if state changed from not-solved to solved
                    print(f"🔍 DEBUG: Checking solve transition: current={current_solved_state}, last={self.last_solved_state}")
                    print(f"🔍 DEBUG: Condition check: current_solved_state={current_solved_state}, last_solved_state != True = {self.last_solved_state != True}")
                    print(f"🔍 DEBUG: Overall condition: {current_solved_state and self.last_solved_state != True}")
                    
                    if current_solved_state and self.last_solved_state != True:
                        print("🎉 Cube solved! Creating SolvedEvent")
                        solved_event = SolvedEvent(serial=facelets_event.serial, timestamp=time.time())
                        events.append(solved_event)
                        print(f"🔍 DEBUG: SolvedEvent created and added to events list (total events: {len(events)})")
                    else:
                        print(f"🚫 DEBUG: No solve event - condition not met")
                    
                    # Update tracked solved state
                    self.last_solved_state = current_solved_state
                    
                    await self.check_if_move_missed(conn)
            
            elif len(event_message) == 16:
                # 16-byte packets are typically command responses or status
                # Try to parse as different event types
                if packet_type == 0x04:  # Battery event
                    battery_event = parse_battery_event(event_message)
                    if battery_event:
                        events.append(battery_event)
                        
                elif packet_type == 0x05:  # Hardware event
                    hardware_event = parse_hardware_event(event_message)
                    if hardware_event:
                        events.append(hardware_event)
                else:
                    pass  # Silently ignore other 16-byte status packets
                        
            # Check for solved state packets (18-byte 0x01 packets)
            elif is_solved_packet(event_message):
                solved_event = parse_solved_event(event_message)
                if solved_event:
                    print(f"🎉 Cube solved! (serial: {solved_event.serial})")
                    events.append(solved_event)
                        
            else:
                # Debug: Log unknown packets with full details for analysis
                packet_hex = event_message.hex()
                print(f"❓ Unknown packet type: len={len(event_message)}, type=0x{packet_type:02x}, magic=0x{magic_byte:02x}")
                print(f"   Packet: {packet_hex}")
                
                # Check if this might be a solved state or special event
                if magic_byte == 0x55:
                    print(f"   Valid magic byte - may be special event type 0x{packet_type:02x}")

        except Exception as e:
            print(f"❌ Error parsing event: {e}")
            print(f"   Packet: {event_message.hex()}")
        
        return events


@dataclass
class GanCubeRawConnection:
    """Raw connection interface for internal use."""
    
    send_command_message: Callable[[bytes], Any]
    disconnect: Callable[[], Any]


class GanCubeConnection:
    """
    Connection object representing connection API and state.
    Enhanced with robust move tracking and state management.
    """
    
    def __init__(self, device_name: str, device_mac: str, 
                 raw_connection: GanCubeRawConnection,
                 protocol_driver: GanProtocolDriver,
                 key: bytes = None, iv: bytes = None):
        self.device_name = device_name
        self.device_mac = device_mac
        self._raw_connection = raw_connection
        self._protocol_driver = protocol_driver
        self._event_callbacks: List[Callable[[CubeEvent], None]] = []
        self._cube_state = CubeState.solved()
        self._move_count = 0
        self._last_solved_move_count = 0
        self._key = key
        self._iv = iv
        
        # Move-based solved state tracking
        self._move_history: List[str] = []
        self._is_solved = True  # Assume cube starts solved
        self._last_move_serial = None
        
    def add_event_callback(self, callback: Callable[[CubeEvent], None]) -> None:
        """Add callback for cube events."""
        self._event_callbacks.append(callback)
    
    def remove_event_callback(self, callback: Callable[[CubeEvent], None]) -> None:
        """Remove event callback."""
        if callback in self._event_callbacks:
            self._event_callbacks.remove(callback)
    
    async def handle_notification(self, data: bytes, key: bytes, iv: bytes) -> None:
        """Handle BLE notification with enhanced processing."""
        try:
            # Decrypt the packet
            decrypted = decrypt_packet(data, key, iv)
            
            # Process through protocol driver
            events = await self._protocol_driver.handle_state_event(self._raw_connection, decrypted)
            
            # Handle each event
            for event in events:
                await self._process_event(event)
                
                # Notify callbacks
                for callback in self._event_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(event)
                        else:
                            callback(event)
                    except Exception as e:
                        print(f"Error in event callback: {e}")
                        
        except Exception as e:
            print(f"Error handling notification: {e}")
    
    async def _process_event(self, event: CubeEvent) -> None:
        """Process individual cube events."""
        if isinstance(event, MoveEvent):
            self._move_count += 1
            # Apply move to cube state (simplified - full implementation would track actual state)
            # For now, just check if we're back to solved based on move count
            if self._move_count > self._last_solved_move_count and self._cube_state.is_solved():
                # Potential solve - in real implementation, would verify actual cube state
                pass
                
        elif isinstance(event, FaceletsEvent):
            self._cube_state = event.state
            if event.state.is_solved():
                self._last_solved_move_count = self._move_count
    
    def is_solved(self) -> bool:
        """Check if cube is currently solved."""
        return self._cube_state.is_solved()
    
    def get_move_count(self) -> int:
        """Get total move count."""
        return self._move_count
    
    async def send_cube_command(self, command: Dict[str, Any]) -> None:
        """Send command to the cube."""
        cmd_message = self._protocol_driver.create_command_message(command)
        if cmd_message:
            # Encrypt the command before sending
            if self._key and self._iv:
                from gan_decrypt import encrypt_packet
                encrypted_message = encrypt_packet(cmd_message, self._key, self._iv)
                print(f"🔐 DEBUG: Encrypted command: {encrypted_message.hex()}")
                await self._raw_connection.send_command_message(encrypted_message)
            else:
                print("⚠️ WARNING: No encryption keys available, sending raw command")
                await self._raw_connection.send_command_message(cmd_message)
    
    async def disconnect(self) -> None:
        """Close this connection."""
        await self._raw_connection.disconnect()
    
    async def request_battery_level(self) -> None:
        """Request current battery level."""
        await self.send_cube_command({"type": "REQUEST_BATTERY"})
    
    async def request_hardware_info(self) -> None:
        """Request hardware information."""
        await self.send_cube_command({"type": "REQUEST_HARDWARE"})
    
    async def reset_cube_state(self) -> None:
        """Reset cube to solved state."""
        await self.send_cube_command({"type": "REQUEST_RESET"})
        self._cube_state = CubeState.solved()
        self._move_count = 0
        self._last_solved_move_count = 0
