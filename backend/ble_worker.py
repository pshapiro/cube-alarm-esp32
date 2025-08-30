# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
from __future__ import annotations
import os
import asyncio
import time
import threading
from typing import Optional, Callable, List, Tuple

from bleak import BleakScanner, BleakClient, BleakError
from flask_socketio import SocketIO

try:
    from .gan_decrypt import derive_key_iv, decrypt_packet, parse_move, CubeEvent, MoveEvent, FaceletsEvent
    from .gan_protocol_driver import GanGen3ProtocolDriver, GanCubeConnection, GanCubeRawConnection
except ImportError:
    from gan_decrypt import derive_key_iv, decrypt_packet, parse_move, CubeEvent, MoveEvent, FaceletsEvent
    from gan_protocol_driver import GanGen3ProtocolDriver, GanCubeConnection, GanCubeRawConnection

# GAN Gen3 Service and Characteristic UUIDs (for GAN356 i Carry 2)
SERVICE_UUID = "8653000a-43e6-47b7-9cb0-5fc21d4ae340"
STATE_CHAR_UUID = "8653000b-43e6-47b7-9cb0-5fc21d4ae340"
COMMAND_CHAR_UUID = "8653000c-43e6-47b7-9cb0-5fc21d4ae340"

# Global state
socketio: Optional[SocketIO] = None
_connection: Optional[GanCubeConnection] = None
_key_iv: Optional[Tuple[bytes, bytes]] = None
_solve_callbacks: List[Callable[[], None]] = []
_move_callbacks: List[Callable[[dict], None]] = []
_connection_callbacks: List[Callable[[bool], None]] = []
_connection_time: Optional[float] = None  # Track when cube was connected
_CONNECTION_SOLVED_DELAY = 0.5  # Reduced from 1.0 to 0.5 seconds for faster alarm response

# Enhanced configuration - optimized for faster connection
VALID_LENGTHS = (18, 20)
RECONNECT_DELAY = 2  # Reduced from 5 to 2 seconds
SCAN_TIMEOUT = 5     # Reduced from 10 to 5 seconds  
MAX_RECONNECT_ATTEMPTS = 2  # Reduced from 3 to 2 attempts

# Manual override mapping of device names (or address fragments) to real MAC
_REAL_MAC_OVERRIDE: dict[str, str] = {
    "GANicV2S_969C": "CF:AA:79:C9:96:9C",  # User's cube
}


def _log(msg: str):
    """Enhanced logging with timestamps."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=True)

def add_solve_callback(callback: Callable[[], None]) -> None:
    """Add a callback to be called when cube is solved."""
    global _solve_callbacks
    _log(f"🎯 DEBUG: Registering solve callback: {callback}")
    _solve_callbacks.append(callback)
    _log(f"🎯 DEBUG: Total solve callbacks now: {len(_solve_callbacks)}")

def add_move_callback(callback: Callable[[dict], None]) -> None:
    """Add a callback to be called when cube move is detected."""
    global _move_callbacks
    _move_callbacks.append(callback)

def add_connection_callback(callback: Callable[[bool], None]) -> None:
    """Add a callback to be called when cube connection status changes."""
    global _connection_callbacks
    _log(f"🎯 DEBUG: Registering connection callback: {callback}")
    _connection_callbacks.append(callback)
    _log(f"🎯 DEBUG: Total connection callbacks now: {len(_connection_callbacks)}")

def get_current_solved_state() -> bool:
    """Get the current solved state from the protocol driver."""
    global _connection
    if _connection and hasattr(_connection, '_protocol_driver'):
        # Check the protocol driver's last solved state
        protocol_driver = _connection._protocol_driver
        if hasattr(protocol_driver, 'last_solved_state'):
            return protocol_driver.last_solved_state or False
    return False

def remove_solve_callback(callback: Callable[[], None]) -> None:
    """Remove solve callback."""
    global _solve_callbacks
    if callback in _solve_callbacks:
        _solve_callbacks.remove(callback)

def remove_move_callback(callback: Callable[[dict], None]) -> None:
    """Remove move callback."""
    global _move_callbacks
    if callback in _move_callbacks:
        _move_callbacks.remove(callback)

async def reset_cube_state() -> bool:
    """Send REQUEST_RESET command to cube to reset internal state to solved."""
    global _connection
    
    if not _connection:
        _log("❌ No cube connection available for reset")
        return False
    
    try:
        _log("🔄 Sending REQUEST_RESET command to cube...")
        await _connection.send_cube_command({"type": "REQUEST_RESET"})
        _log("✅ Reset command sent successfully")
        return True
    except Exception as e:
        _log(f"❌ Error sending reset command: {e}")
        return False

# Global flag for reset command
_reset_requested = False

def reset_cube_state_sync() -> bool:
    """Request a cube reset to be processed in the main BLE loop."""
    global _reset_requested, _connection
    
    if not _connection:
        _log("❌ No cube connection available for reset")
        return False
    
    try:
        _log("🔄 Requesting cube reset...")
        _reset_requested = True
        
        # Wait for the reset to be processed (up to 5 seconds)
        start_time = time.time()
        while _reset_requested and time.time() - start_time < 5.0:
            time.sleep(0.1)
        
        if _reset_requested:
            _log("❌ Reset request timed out")
            _reset_requested = False
            return False
        else:
            _log("✅ Reset request completed")
            return True
            
    except Exception as e:
        _log(f"❌ Error requesting reset: {e}")
        _reset_requested = False
        return False

async def _process_reset_requests() -> None:
    """Process pending reset requests in the main BLE loop."""
    global _reset_requested, _connection
    
    if _reset_requested and _connection:
        try:
            _log("🔄 Processing reset request in BLE loop...")
            await _connection.send_cube_command({"type": "REQUEST_RESET"})
            _log("✅ Reset command sent to cube in BLE loop")
        except Exception as e:
            _log(f"❌ Error sending reset in BLE loop: {e}")
        finally:
            _reset_requested = False

def get_connection() -> Optional[GanCubeConnection]:
    """Get current cube connection."""
    return _connection

def is_cube_solved() -> bool:
    """Check if cube is currently solved."""
    return _connection.is_solved() if _connection else False

async def _handle_cube_event(event: CubeEvent) -> None:
    """Enhanced event handler with solve detection and callbacks."""
    global socketio, _solve_callbacks, _move_callbacks, _connection_time
    
    if isinstance(event, MoveEvent):
        move_dict = event.move.to_dict()
        _log(f"🔄 Move: {event.move.move} (serial: {event.move.serial})")
        
        # Emit to Socket.IO if available
        if socketio:
            socketio.emit("move", move_dict)
        
        # Call move callbacks
        for callback in _move_callbacks:
            try:
                callback(move_dict)
            except Exception as e:
                _log(f"❌ Error in move callback: {e}")
        
        # Check for solve after move
        if _connection and _connection.is_solved():
            _log("🎉 Cube solved!")  # Re-enabled from working commit 977e6c4
            if socketio:
                socketio.emit("solved", {"timestamp": time.time()})
            
            # Call solve callbacks
            _log(f"🎯 DEBUG: Calling {len(_solve_callbacks)} solve callbacks")
            for callback in _solve_callbacks:
                try:
                    _log(f"🎯 DEBUG: Calling solve callback: {callback}")
                    callback()
                    _log(f"✅ DEBUG: Solve callback completed successfully")
                except Exception as e:
                    _log(f"❌ Error in solve callback: {e}")
    
    elif isinstance(event, FaceletsEvent):
        _log(f"Facelets update (serial: {event.serial})")
        
        # Check if cube is solved based on facelets state
        if event.state.is_solved():
            _log(f"🎉 Cube solved! (detected from facelets state)")
            
            # Check connection delay before processing solved event (but allow during alarms)
            connection_delay = _connection_time and (time.time() - _connection_time) < _CONNECTION_SOLVED_DELAY
            if connection_delay:
                # Check if there are active alarms - if so, allow immediate solve detection
                try:
                    import requests
                    response = requests.get('http://localhost:5001/api/alarms/active', timeout=0.5)
                    active_alarms = response.json() if response.status_code == 200 else []
                    has_active_alarms = len(active_alarms) > 0
                    
                    if has_active_alarms:
                        _log(f"✅ Allowing solved event despite connection delay - active alarm detected ({time.time() - _connection_time:.1f}s < {_CONNECTION_SOLVED_DELAY}s)")
                    else:
                        _log(f"🚫 Ignoring solved event - too soon after connection ({time.time() - _connection_time:.1f}s < {_CONNECTION_SOLVED_DELAY}s)")
                        return
                except Exception as e:
                    # If we can't check alarms, use the original delay logic
                    _log(f"🚫 Ignoring solved event - too soon after connection ({time.time() - _connection_time:.1f}s < {_CONNECTION_SOLVED_DELAY}s) [alarm check failed: {e}]")
                    return
            
            if socketio:
                socketio.emit("solved", {"timestamp": time.time()})
            
            # Call solve callbacks
            _log(f"🎯 DEBUG: Calling {len(_solve_callbacks)} solve callbacks for facelets-based solved detection")
            for callback in _solve_callbacks:
                try:
                    _log(f"🎯 DEBUG: Calling solve callback: {callback}")
                    callback()
                    _log(f"✅ DEBUG: Solve callback completed successfully")
                except Exception as e:
                    _log(f"❌ Error in solve callback: {e}")
    
    elif event.event_type == "SOLVED":
        _log(f"Event: {event.event_type}")
        
        # Check if we should ignore solved events immediately after connection (but allow during alarms)
        connection_delay = _connection_time and (time.time() - _connection_time) < _CONNECTION_SOLVED_DELAY
        if connection_delay:
            # Check if there are active alarms - if so, allow immediate solve detection
            try:
                import requests
                response = requests.get('http://localhost:5001/api/alarms/active', timeout=0.5)
                active_alarms = response.json() if response.status_code == 200 else []
                has_active_alarms = len(active_alarms) > 0
                
                if has_active_alarms:
                    _log(f"✅ Allowing solved event despite connection delay - active alarm detected ({time.time() - _connection_time:.1f}s < {_CONNECTION_SOLVED_DELAY}s)")
                else:
                    _log(f"🚫 Ignoring solved event - too soon after connection ({time.time() - _connection_time:.1f}s < {_CONNECTION_SOLVED_DELAY}s)")
                    return
            except Exception as e:
                # If we can't check alarms, use the original delay logic
                _log(f"🚫 Ignoring solved event - too soon after connection ({time.time() - _connection_time:.1f}s < {_CONNECTION_SOLVED_DELAY}s) [alarm check failed: {e}]")
                return
        else:
            _log(f"✅ Accepting solved event - {time.time() - (_connection_time or 0):.1f}s after connection")
        
        if socketio:
            socketio.emit("solved", {"timestamp": event.timestamp})
        
        # Call solve callbacks for SolvedEvent objects from protocol driver
        _log(f"🎯 DEBUG: Calling {len(_solve_callbacks)} solve callbacks for SolvedEvent")
        for callback in _solve_callbacks:
            try:
                _log(f"🎯 DEBUG: Calling solve callback: {callback}")
                callback()
                _log(f"✅ DEBUG: Solve callback completed successfully")
            except Exception as e:
                _log(f"❌ Error in solve callback: {e}")
    
    else:
        _log(f"Event: {event.event_type}")
        if socketio:
            socketio.emit("event", {
                "type": event.event_type,
                "timestamp": event.timestamp
            })

async def _create_raw_connection(client: BleakClient) -> GanCubeRawConnection:
    """Create raw connection wrapper for protocol driver."""
    
    async def send_command(message: bytes) -> None:
        """Send command to cube."""
        try:
            _log(f"🔧 DEBUG: Sending {len(message)} bytes to cube: {message.hex()}")
            await client.write_gatt_char(COMMAND_CHAR_UUID, message)
            _log(f"✅ DEBUG: Command sent successfully")
        except Exception as e:
            _log(f"❌ Error sending command: {e}")
    
    async def disconnect() -> None:
        """Disconnect from cube."""
        try:
            await client.disconnect()
        except Exception as e:
            _log(f"❌ Error disconnecting: {e}")
    
    return GanCubeRawConnection(
        send_command_message=send_command,
        disconnect=disconnect
    )

async def _notify_handler(_, data: bytes) -> None:
    """Enhanced BLE notification handler with robust processing."""
    global _connection, _key_iv
    
    if not _connection or not _key_iv:
        return
    
    # Log packet info for debugging (disabled for cleaner output)
    # _log(f"📦 Received packet: {len(data)} bytes - {data.hex()[:32]}{'...' if len(data) > 16 else ''}")
    
    # Handle all packet lengths, not just move packets
    try:
        await _connection.handle_notification(data, _key_iv[0], _key_iv[1])
    except Exception as e:
        _log(f"❌ Error processing notification (len={len(data)}): {e}")
        # Don't log raw data for every error to avoid spam
        if len(data) not in [16, 18, 19, 20]:
            _log(f"   Raw data: {data.hex()}")

def _extract_mac_from_manufacturer(advertisement_data) -> Optional[str]:
    """Return MAC string like CF:AA:79:C9:96:9C from manufacturer data matching GAN cubes (company id 0x0001)."""
    mdata = advertisement_data.manufacturer_data or {}
    if 0x0001 not in mdata:
        return None
    payload: bytes = mdata[0x0001]
    if len(payload) < 6:
        return None
    mac_bytes = payload[0:6]
    # Format as XX:XX:XX:XX:XX:XX (same ordering as JS which later reverses again)
    return ':'.join(f"{b:02X}" for b in mac_bytes)

async def _discover_cube(timeout: int = SCAN_TIMEOUT):
    """Scan for BLE devices and return (device, real_mac) for the first GAN cube found."""
    _log(f"🔍 Scanning for GAN cubes ({timeout}s)...")
    global _real_mac_map

    # Reset map each scan
    _real_mac_map = {}

    async with BleakScanner(detection_callback=lambda d, a: _real_mac_map.__setitem__(d.address, _extract_mac_from_manufacturer(a))) as scanner:
        # Scan until timeout or until we captured a real MAC for at least one GAN device
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            await asyncio.sleep(0.1)  # Reduced from 0.2 to 0.1 for faster detection
            # quick check: any captured mac with non-zero bytes and GAN name?
            for d in scanner.discovered_devices:
                mac = _real_mac_map.get(d.address)
                if mac and mac[:2] != "00" and d.name and any(p in d.name.upper() for p in ["GAN", "MG", "AICUBE"]):
                    _log(f"🚀 Found target cube quickly: {d.name} with MAC {mac}")
                    end_time = asyncio.get_event_loop().time()  # break outer loop
                    break
        devices = scanner.discovered_devices

    # Debug list
    _log(f"Found {len(devices)} devices:")
    for d in devices:
        _log(f"  • {(d.name or 'Unknown')} [{d.address}]")

    # Prefer explicit env MAC (real manufacturer MAC). Find matching manufacturer MAC or just first GAN cube.
    mac_env = os.getenv("CUBE_MAC")
    if mac_env:
        # try manufacturer map
        for d in devices:
            man_mac = _real_mac_map.get(d.address)
            if man_mac and man_mac.upper() == mac_env.upper():
                _log(f"✅ Using env CUBE_MAC for {d.name} [{d.address}]")
                return d, mac_env
        # fallback: first GAN device by name
        for d in devices:
            if d.name and "GAN" in d.name.upper():
                _log(f"⚠️ Manufacturer MAC not seen; using env CUBE_MAC with {d.name} [{d.address}]")
                return d, mac_env

    # First GAN-prefixed device with a valid manufacturer MAC
    for d in devices:
        if d.name and any(p in d.name.upper() for p in ["GAN", "MG", "AICUBE"]):
            mac = _real_mac_map.get(d.address)
            if mac and mac[:2] != "00":
                _log(f"🐝 Manufacturer MAC captured: {mac} for {d.address}")
                return d, mac

    # Override: use hardcoded mapping if available
    for d in devices:
        if d.name and d.name in _REAL_MAC_OVERRIDE:
            mac = _REAL_MAC_OVERRIDE[d.name]
            _log(f"🛠 Using override MAC for {d.name}: {mac}")
            return d, mac

    # Fallback: if we at least discovered a GAN device by name but did not capture a manufacturer MAC,
    # return that device with real_mac = None so that the code will still attempt to connect using the
    # BLE address (key derivation will fall back to UUID-based salt which works on most systems).
    for d in devices:
        if d.name and any(p in d.name.upper() for p in ["GAN", "MG", "AICUBE"]):
            _log(f"⚠️ No manufacturer MAC captured; falling back to BLE address for {d.name} [{d.address}]")
            return d, None

    _log("❌ No GAN cubes found that match filter criteria")
    return None, None

async def _connect_to_cube(device, real_mac: Optional[str]) -> Optional[GanCubeConnection]:
    """Enhanced cube connection with retry logic."""
    global _key_iv, _connection_time
    
    _log(f"🔗 Connecting to {device.name} [{device.address}]...")
    mac_for_key = real_mac or device.address
    _log(f"🔑 Using MAC {mac_for_key} for key derivation")
    _key_iv = derive_key_iv(mac_for_key)
    
    for attempt in range(MAX_RECONNECT_ATTEMPTS):
        try:
            client = BleakClient(device)
            await client.connect()
            
            # Verify services are available
            services = client.services
            target_service = None
            for service in services:
                if service.uuid.lower() == SERVICE_UUID.lower():
                    target_service = service
                    break
            
            if not target_service:
                _log(f"❌ Target service {SERVICE_UUID} not found")
                await client.disconnect()
                return None
            
            # Create protocol driver and connection
            protocol_driver = GanGen3ProtocolDriver()
            raw_connection = await _create_raw_connection(client)
            
            connection = GanCubeConnection(
                device_name=device.name or "Unknown",
                device_mac=device.address,
                raw_connection=raw_connection,
                protocol_driver=protocol_driver,
                key=_key_iv[0],
                iv=_key_iv[1]
            )
            
            # Add event callback
            connection.add_event_callback(_handle_cube_event)
            
            # Start notifications
            await client.start_notify(STATE_CHAR_UUID, _notify_handler)
            
            _log("✅ Connected successfully! Move the cube to see events.")
            
            # Track connection time to prevent false solved detection
            _connection_time = time.time()
            
            # Call connection callbacks to notify connected status
            global _connection_callbacks
            _log(f"🎯 DEBUG: Calling {len(_connection_callbacks)} connection callbacks (connected=True)")
            for callback in _connection_callbacks:
                try:
                    callback(True)
                    _log(f"✅ DEBUG: Connection callback completed successfully")
                except Exception as e:
                    _log(f"❌ Error in connection callback: {e}")
            
            # Request initial hardware info and battery level
            await connection.request_hardware_info()
            await connection.request_battery_level()
            
            return connection
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc().strip()
            _log(
                f"❌ Connection attempt {attempt + 1} failed: {type(e).__name__}: {e}\n{error_details}"
            )
            if attempt < MAX_RECONNECT_ATTEMPTS - 1:
                _log(f"⏳ Retrying in {RECONNECT_DELAY}s...")
                await asyncio.sleep(RECONNECT_DELAY)
            else:
                _log("❌ Max connection attempts reached")
    
    return None

async def _ble_loop() -> None:
    """Enhanced main BLE loop with robust error handling."""
    global _connection
    
    while True:
        try:
            # Discover cube and real MAC
            device, real_mac = await _discover_cube()
            if not device:
                _log(f"⏳ No cube found. Retrying in {RECONNECT_DELAY}s...")  # Use shorter delay
                await asyncio.sleep(RECONNECT_DELAY)  # Reduced from SCAN_TIMEOUT to RECONNECT_DELAY
                continue
            
            # Connect to cube
            _connection = await _connect_to_cube(device, real_mac)
            if not _connection:
                _log(f"⏳ Connection failed. Retrying in {RECONNECT_DELAY}s...")
                await asyncio.sleep(RECONNECT_DELAY)
                continue
            
            # Keep connection alive and process reset requests
            try:
                while True:
                    # Check for reset requests (but don't process continuously)
                    await _process_reset_requests()
                    
                    # Sleep longer to avoid busy waiting and command spam
                    await asyncio.sleep(1.0)
                    
            except asyncio.CancelledError:
                _log("🛑 BLE loop cancelled")
                break
        except Exception as e:
            _log(f"❌ BLE loop error: {e}")
            await asyncio.sleep(RECONNECT_DELAY)
        finally:
            # Clean up connection
            if _connection:
                try:
                    await _connection.disconnect()
                except Exception as e:
                    _log(f"❌ Error during cleanup: {e}")
                _connection = None
        
        _log(f"⏳ Reconnecting in {RECONNECT_DELAY}s...")
        await asyncio.sleep(RECONNECT_DELAY)

# Public API -----------------------------------------------------

# Global variables for BLE worker control
_ble_task: Optional[asyncio.Task] = None
_ble_loop_running = False
_stop_ble_event: Optional[asyncio.Event] = None

def start_ble_worker(socketio_ref: Optional[SocketIO] = None) -> bool:
    """Start the BLE worker in a separate thread. Returns True if started successfully."""
    global socketio, _ble_loop_running
    
    if _ble_loop_running:
        _log("⚠️ BLE worker already running")
        return True
    
    socketio = socketio_ref
    _log("🚀 Starting BLE worker for alarm...")
    
    def run_ble_worker():
        """Run BLE worker in thread."""
        global _ble_loop_running, _stop_ble_event
        try:
            _ble_loop_running = True
            # Create a new stop event bound to this thread's event loop
            _stop_ble_event = asyncio.Event()
            asyncio.run(_ble_loop_with_stop())
        except Exception as e:
            _log(f"❌ BLE worker error: {e}")
        finally:
            _ble_loop_running = False
    
    # Start BLE worker in daemon thread
    ble_thread = threading.Thread(target=run_ble_worker, daemon=True)
    ble_thread.start()
    
    return True

def stop_ble_worker() -> bool:
    """Stop the BLE worker to save battery. Returns True if stopped successfully."""
    global _ble_loop_running, _stop_ble_event
    
    if not _ble_loop_running:
        _log("⚠️ BLE worker not running")
        return True
    
    _log("🛑 Stopping BLE worker to save battery...")
    if _stop_ble_event:
        _stop_ble_event.set()
    
    # Give it a moment to stop gracefully
    import time
    time.sleep(1)
    
    return True

def is_ble_worker_running() -> bool:
    """Check if BLE worker is currently running."""
    return _ble_loop_running

async def _ble_loop_with_stop():
    """BLE loop that can be stopped via _stop_ble_event."""
    global _connection, _stop_ble_event
    
    _log("🚀 Starting enhanced GAN cube BLE worker...")
    _log(f"📡 Target service: {SERVICE_UUID}")
    _log(f"📊 State characteristic: {STATE_CHAR_UUID}")
    _log(f"📤 Command characteristic: {COMMAND_CHAR_UUID}")
    
    # Safety: ensure stop event exists
    if _stop_ble_event is None:
        _stop_ble_event = asyncio.Event()

    while not _stop_ble_event.is_set():
        try:
            # Scan for cube
            device, real_mac = await _discover_cube()
            if not device:
                _log(f"⏳ No cube found. Retrying in {SCAN_TIMEOUT}s...")
                try:
                    await asyncio.wait_for(_stop_ble_event.wait(), timeout=SCAN_TIMEOUT)
                    break  # Stop event was set
                except asyncio.TimeoutError:
                    continue  # Continue scanning
            
            # Connect to cube
            _connection = await _connect_to_cube(device, real_mac)
            if not _connection:
                _log(f"⏳ Connection failed. Retrying in {RECONNECT_DELAY}s...")
                try:
                    await asyncio.wait_for(_stop_ble_event.wait(), timeout=RECONNECT_DELAY)
                    break  # Stop event was set
                except asyncio.TimeoutError:
                    continue  # Continue trying to connect
            
            # Keep connection alive and process reset requests
            try:
                while not _stop_ble_event.is_set():
                    # Check for reset requests
                    await _process_reset_requests()
                    
                    # Sleep with stop check
                    try:
                        await asyncio.wait_for(_stop_ble_event.wait(), timeout=1.0)
                        break  # Stop event was set
                    except asyncio.TimeoutError:
                        continue  # Keep running
                        
            except asyncio.CancelledError:
                _log("🛑 BLE loop cancelled")
                break
        except Exception as e:
            _log(f"❌ BLE loop error: {e}")
            if _stop_ble_event.is_set():
                break
            try:
                await asyncio.wait_for(_stop_ble_event.wait(), timeout=RECONNECT_DELAY)
                break  # Stop event was set
            except asyncio.TimeoutError:
                continue  # Continue with error recovery
        finally:
            # Clean up connection
            if _connection:
                try:
                    await _connection.disconnect()
                except Exception as e:
                    _log(f"❌ Error during cleanup: {e}")
                _connection = None
        
        if _stop_ble_event.is_set():
            break
        
        _log(f"⏳ Reconnecting in {RECONNECT_DELAY}s...")
        try:
            await asyncio.wait_for(_stop_ble_event.wait(), timeout=RECONNECT_DELAY)
            break  # Stop event was set
        except asyncio.TimeoutError:
            continue  # Continue reconnection loop
    
    _log("🛑 BLE worker stopped")

def run(socketio_ref: Optional[SocketIO] = None) -> None:
    """Enhanced blocking call that starts the BLE listener with robust error handling."""
    global socketio
    socketio = socketio_ref
    
    _log("🚀 Starting enhanced GAN cube BLE worker...")
    _log(f"📡 Target service: {SERVICE_UUID}")
    _log(f"📊 State characteristic: {STATE_CHAR_UUID}")
    _log(f"📤 Command characteristic: {COMMAND_CHAR_UUID}")
    
    try:
        asyncio.run(_ble_loop())
    except KeyboardInterrupt:
        _log("🛑 Stopped by user")
    except Exception as e:
        _log(f"❌ Fatal error: {e}")
        raise

if __name__ == "__main__":
    run()
