#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""
Alarm Clock Server with WebSocket support for GAN Cube integration.
Provides REST API for alarm management and WebSocket for real-time updates.
"""

import asyncio
import json
import logging
from datetime import datetime, time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import threading


from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import schedule

from cube_worker import GanCubeWorker
from gan_decrypt import CubeMove, SolvedEvent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Smart BLE Connection Strategy - no global cube worker needed

@dataclass
class Alarm:
    """Represents an alarm clock entry."""
    id: str
    time: str  # Format: "HH:MM"
    days: List[str]  # ["monday", "tuesday", etc.]
    enabled: bool
    label: str
    requires_cube_solve: bool = True
    is_active: bool = False  # Currently ringing
    created_at: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

class AlarmManager:
    """Manages alarm scheduling and triggering."""
    
    def __init__(self):
        self.alarms: Dict[str, Alarm] = {}
        self.active_alarms: Set[str] = set()
        self.cube_solved = False
        self.cube_connected = False
        self.last_cube_state = ""
        
        # Initialize shared audio manager for Pi audio playback
        try:
            from pi_audio import PiAudioManager
            self.audio_manager = PiAudioManager()
            logger.info("🔊 Initialized shared PiAudioManager instance")
        except Exception as e:
            logger.warning(f"⚠️ Could not initialize PiAudioManager: {e}")
            self.audio_manager = None
        
    def add_alarm(self, alarm: Alarm) -> bool:
        """Add a new alarm."""
        self.alarms[alarm.id] = alarm
        if alarm.enabled:
            self._schedule_alarm(alarm)
        return True
    
    def update_alarm(self, alarm_id: str, updates: dict) -> bool:
        """Update an existing alarm."""
        if alarm_id not in self.alarms:
            return False
        
        alarm = self.alarms[alarm_id]
        
        # Update fields
        for key, value in updates.items():
            if hasattr(alarm, key):
                setattr(alarm, key, value)
        
        # Reschedule if needed
        if alarm.enabled:
            self._schedule_alarm(alarm)
        else:
            self._unschedule_alarm(alarm)
        
        return True
    
    def delete_alarm(self, alarm_id: str) -> bool:
        """Delete an alarm."""
        if alarm_id not in self.alarms:
            return False
        
        self._unschedule_alarm(self.alarms[alarm_id])
        del self.alarms[alarm_id]
        return True
    
    def get_alarms(self) -> List[Dict]:
        """Get all alarms."""
        return [asdict(alarm) for alarm in self.alarms.values()]

    def get_active_alarms(self) -> List[Dict]:
        """Return a list of currently active alarms."""
        return [asdict(self.alarms[alarm_id])
                for alarm_id in self.active_alarms
                if alarm_id in self.alarms]
    
    def trigger_alarm(self, alarm_id: str):
        """Trigger an alarm."""
        if alarm_id not in self.alarms:
            return
        
        alarm = self.alarms[alarm_id]
        alarm.is_active = True
        self.active_alarms.add(alarm_id)
        
        logger.info(f"🚨 Alarm triggered: {alarm.label} at {alarm.time}")
        
        # CRITICAL: Ensure BLE worker is running for cube solve detection
        from ble_worker import start_ble_worker, is_ble_worker_running
        if not is_ble_worker_running():
            logger.info("🔍 ALARM: Starting BLE worker to detect cube solve")
            start_ble_worker()
        else:
            logger.info("🔍 ALARM: BLE worker already running for cube solve detection")
        
        # Start playing alarm sound locally (for Raspberry Pi deployment)
        self._start_alarm_sound(alarm_id)
        
        # Emit to all connected clients
        socketio.emit('alarm_triggered', {
            'alarm': asdict(alarm),
            'timestamp': datetime.now().isoformat()
        })
    
    def stop_alarm(self, alarm_id: str, solved_by_cube: bool = False):
        """Stop an active alarm."""
        if alarm_id not in self.alarms:
            return False
        
        alarm = self.alarms[alarm_id]
        if not alarm.is_active:
            return False
        
        alarm.is_active = False
        self.active_alarms.discard(alarm_id)
        
        logger.info(f"⏰ Alarm stopped: {alarm.label} {'by cube solve' if solved_by_cube else 'manually'}")
        
        # Stop playing alarm sound locally
        self._stop_alarm_sound(alarm_id)
        
        # Check if we should stop BLE worker to save battery
        self._check_ble_worker_shutdown()
        
        # Emit to all connected clients
        socketio.emit('alarm_stopped', {
            'alarm': asdict(alarm),
            'solved_by_cube': solved_by_cube,
            'timestamp': datetime.now().isoformat()
        })
        
        return True
    
    def on_cube_solved(self):
        """Handle cube solved event."""
        self.cube_solved = True
        logger.info("🎉 Cube solved! Checking for active alarms...")
        logger.info(f"🔍 DEBUG: Active alarms: {list(self.active_alarms)}")
        
        # Stop all active alarms that require cube solve
        for alarm_id in list(self.active_alarms):
            alarm = self.alarms[alarm_id]
            logger.info(f"🔍 DEBUG: Checking alarm {alarm_id}: requires_cube_solve={alarm.requires_cube_solve}")
            if alarm.requires_cube_solve:
                logger.info(f"🚨 DEBUG: Stopping alarm {alarm_id} due to cube solved")
                self.stop_alarm(alarm_id, solved_by_cube=True)
        
        # Emit cube state update
        socketio.emit('cube_solved', {
            'timestamp': datetime.now().isoformat()
        })
    
    def on_cube_move(self, move: CubeMove):
        """Handle cube move event."""
        self.cube_solved = False
        
        # Emit cube move update
        socketio.emit('cube_move', {
            'face': move.face,
            'direction': move.direction,
            'timestamp': datetime.now().isoformat()
        })
    
    def on_cube_connected(self, connected: bool):
        """Handle cube connection status."""
        self.cube_connected = connected
        logger.info(f"📱 Cube {'connected' if connected else 'disconnected'}")
        
        socketio.emit('cube_connected', {
            'connected': connected,
            'timestamp': datetime.now().isoformat()
        })
    
    def _pre_alarm_ble_activation(self, alarm_id: str):
        """Activate BLE worker 10 seconds before alarm to ensure connection."""
        logger.info(f"🔋 Pre-alarm BLE activation for alarm {alarm_id}")
        
        # Import BLE worker control functions
        from ble_worker import start_ble_worker, is_ble_worker_running
        
        if not is_ble_worker_running():
            logger.info("🚀 Starting BLE worker for upcoming alarm...")
            start_ble_worker(socketio)
        else:
            logger.info("⚠️ BLE worker already running")
    
    def _check_ble_worker_shutdown(self):
        """Check if BLE worker should be stopped to save battery."""
        # Import BLE worker control functions
        from ble_worker import stop_ble_worker, is_ble_worker_running
        
        # If no active alarms and BLE worker is running, stop it to save battery
        if not self.active_alarms and is_ble_worker_running():
            logger.info("🔋 No active alarms - stopping BLE worker to save battery")
            stop_ble_worker()
        elif self.active_alarms:
            logger.info(f"🔋 Keeping BLE worker running - {len(self.active_alarms)} active alarms")
    
    def _start_alarm_sound(self, alarm_id: str):
        """Start playing alarm sound locally using Pi Audio Manager."""
        try:
            if not self.audio_manager:
                logger.error("❌ No audio manager available for alarm sound")
                return
            
            alarm = self.alarms.get(alarm_id)
            alarm_label = alarm.label if alarm else "Unknown Alarm"
            
            # Use shared PiAudioManager instance to start alarm sound
            success = self.audio_manager.play_alarm_sound(alarm_id)
            if success:
                logger.info(f"🔊 Started alarm sound for: {alarm_label}")
            else:
                logger.error(f"❌ Failed to start alarm sound for: {alarm_label}")
            
        except Exception as e:
            logger.error(f"❌ Error starting alarm sound: {e}")
    
    def _stop_alarm_sound(self, alarm_id: str):
        """Stop playing alarm sound locally using Pi Audio Manager."""
        try:
            if not self.audio_manager:
                logger.error("❌ No audio manager available to stop alarm sound")
                return
            
            alarm = self.alarms.get(alarm_id)
            alarm_label = alarm.label if alarm else "Unknown Alarm"
            
            # Use shared PiAudioManager instance to stop alarm sound
            success = self.audio_manager.stop_alarm_sound(alarm_id)
            if success:
                logger.info(f"🔇 Stopped alarm sound for: {alarm_label}")
            else:
                logger.error(f"❌ Failed to stop alarm sound for: {alarm_label}")
            
        except Exception as e:
            logger.error(f"❌ Error stopping alarm sound: {e}")
    
    def _schedule_alarm(self, alarm: Alarm):
        """Schedule an alarm with the scheduler."""
        # Clear existing schedule for this alarm
        self._unschedule_alarm(alarm)
        
        # Calculate pre-alarm time (10 seconds before alarm)
        from datetime import datetime, timedelta
        alarm_time = datetime.strptime(alarm.time, "%H:%M")
        pre_alarm_time = alarm_time - timedelta(seconds=10)
        pre_alarm_time_str = pre_alarm_time.strftime("%H:%M:%S")
        
        # Schedule for each day
        for day in alarm.days:
            # Schedule pre-alarm BLE activation (10 seconds before)
            getattr(schedule.every(), day.lower()).at(pre_alarm_time_str).do(
                self._pre_alarm_ble_activation, alarm.id
            ).tag(f"{alarm.id}_pre")
            
            # Schedule actual alarm
            getattr(schedule.every(), day.lower()).at(alarm.time).do(
                self.trigger_alarm, alarm.id
            ).tag(alarm.id)
    
    def _unschedule_alarm(self, alarm: Alarm):
        """Remove alarm from scheduler."""
        schedule.clear(alarm.id)  # Clear main alarm
        schedule.clear(f"{alarm.id}_pre")  # Clear pre-alarm BLE activation

# Global instances
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
alarm_manager = AlarmManager()

# REST API Routes
@app.route('/api/alarms', methods=['GET'])
def get_alarms():
    """Get all alarms."""
    return jsonify(alarm_manager.get_alarms())

@app.route('/api/alarms/active', methods=['GET'])
def get_active_alarms():
    """Get all currently active alarms."""
    return jsonify(alarm_manager.get_active_alarms())

@app.route('/api/alarms', methods=['POST'])
def create_alarm():
    """Create a new alarm."""
    data = request.json
    
    # Generate ID if not provided
    if 'id' not in data:
        data['id'] = f"alarm_{datetime.now().timestamp()}"
    
    try:
        alarm = Alarm(**data)
        success = alarm_manager.add_alarm(alarm)
        
        if success:
            socketio.emit('alarm_created', asdict(alarm))
            return jsonify(asdict(alarm)), 201
        else:
            return jsonify({'error': 'Failed to create alarm'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/alarms/<alarm_id>', methods=['PUT'])
def update_alarm(alarm_id):
    """Update an existing alarm."""
    data = request.json
    success = alarm_manager.update_alarm(alarm_id, data)
    
    if success:
        alarm = alarm_manager.alarms[alarm_id]
        socketio.emit('alarm_updated', asdict(alarm))
        return jsonify(asdict(alarm))
    else:
        return jsonify({'error': 'Alarm not found'}), 404

@app.route('/api/alarms/<alarm_id>', methods=['DELETE'])
def delete_alarm(alarm_id):
    """Delete an alarm."""
    success = alarm_manager.delete_alarm(alarm_id)
    
    if success:
        socketio.emit('alarm_deleted', {'id': alarm_id})
        return '', 204
    else:
        return jsonify({'error': 'Alarm not found'}), 404

@app.route('/api/alarms/<alarm_id>/stop', methods=['POST'])
def stop_alarm(alarm_id):
    """Manually stop an active alarm."""
    success = alarm_manager.stop_alarm(alarm_id, solved_by_cube=False)
    
    if success:
        return jsonify({'message': 'Alarm stopped'})
    else:
        return jsonify({'error': 'Alarm not found or not active'}), 404

@app.route('/api/alarms/stop', methods=['POST'])
def stop_all_alarms():
    """Stop all active alarms."""
    from flask import request
    logger.info(f"🛑 DEBUG: /api/alarms/stop called - stopping all active alarms")
    logger.info(f"🛑 DEBUG: Request from IP: {request.remote_addr}")
    logger.info(f"🛑 DEBUG: Request headers: {dict(request.headers)}")
    logger.info(f"🛑 DEBUG: Request method: {request.method}")
    logger.info(f"🛑 DEBUG: Request data: {request.get_data()}")
    logger.info(f"🛑 DEBUG: Active alarms before stop: {list(alarm_manager.active_alarms)}")
    
    stopped_count = 0
    for alarm_id in list(alarm_manager.active_alarms):
        logger.info(f"🛑 DEBUG: Stopping alarm {alarm_id} via general stop endpoint")
        if alarm_manager.stop_alarm(alarm_id, solved_by_cube=False):
            stopped_count += 1
    
    logger.info(f"🛑 DEBUG: Stopped {stopped_count} alarms via general stop endpoint")
    return jsonify({'message': f'Stopped {stopped_count} active alarms'})

@app.route('/api/cube/status', methods=['GET'])
def get_cube_status():
    """Get current cube connection and solved status."""
    return jsonify({
        'connected': alarm_manager.cube_connected,
        'solved': alarm_manager.cube_solved
    })

@app.route('/api/cube/reset', methods=['POST'])
def reset_cube_state():
    """Reset cube state to solved (like official GAN app)."""
    try:
        logger.info("🔄 Reset cube state requested")
        if cube_worker:
            logger.info(f"📱 Cube worker available: {type(cube_worker)}")
            # Force cube state to solved
            cube_worker.force_solved_state()
            socketio.emit('cube_solved')
            logger.info("✅ Cube state reset successful")
            return jsonify({'success': True, 'message': 'Cube state reset to solved'})
        else:
            logger.error("❌ Cube worker not available")
            return jsonify({'error': 'Cube worker not available'}), 500
    except Exception as e:
        logger.error(f"❌ Error resetting cube state: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/cube/connect', methods=['POST'])
def connect_cube():
    """Manually start the BLE worker to connect to the cube."""
    try:
        from ble_worker import start_ble_worker, is_ble_worker_running
        if is_ble_worker_running():
            logger.info("🔋 BLE worker already running - connect request ignored")
            return jsonify({'status': 'already_running'})

        start_ble_worker(socketio)
        logger.info("🚀 BLE worker started via manual connect request")
        return jsonify({'status': 'connecting'})
    except Exception as e:
        logger.error(f"❌ Error starting BLE worker: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/cube/disconnect', methods=['POST'])
def disconnect_cube():
    """Stop the BLE worker to disconnect from the cube."""
    try:
        from ble_worker import stop_ble_worker, is_ble_worker_running
        if not is_ble_worker_running():
            logger.info("🔋 BLE worker not running - disconnect request ignored")
            return jsonify({'status': 'not_running'})

        stop_ble_worker()
        logger.info("🛑 BLE worker stopped via manual disconnect request")
        return jsonify({'status': 'disconnecting'})
    except Exception as e:
        logger.error(f"❌ Error stopping BLE worker: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status."""
    return jsonify({
        'cube_connected': alarm_manager.cube_connected,
        'cube_solved': alarm_manager.cube_solved,
        'active_alarms': len(alarm_manager.active_alarms),
        'total_alarms': len(alarm_manager.alarms),
        'timestamp': datetime.now().isoformat()
    })

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.info("Client connected")
    emit('status', {
        'cube_connected': alarm_manager.cube_connected,
        'cube_solved': alarm_manager.cube_solved,
        'active_alarms': len(alarm_manager.active_alarms),
        'alarms': alarm_manager.get_alarms()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info("Client disconnected")

# Cube Worker Integration

def setup_ble_callbacks():
    """Set up BLE callbacks for smart connection strategy (no continuous worker)."""
    # Import BLE worker functions to register callbacks directly
    from ble_worker import add_solve_callback, add_move_callback, add_connection_callback
    
    # Set up event callbacks directly with BLE worker (bypass cube worker)
    def on_move_direct(move_dict):
        """Direct callback from BLE worker to alarm manager."""
        try:
            # Convert dict to CubeMove object like cube worker does
            move_obj = CubeMove(
                face=move_dict.get('face', 0),
                direction=move_dict.get('direction', 0),
                move=move_dict.get('move', ''),
                serial=move_dict.get('serial', 0),
                local_timestamp=move_dict.get('local_timestamp'),
                cube_timestamp=move_dict.get('cube_timestamp')
            )
            alarm_manager.on_cube_move(move_obj)
        except Exception as e:
            logger.error(f"❌ Error in direct move callback: {e}")
        
    def on_solved_direct():
        """Direct callback from BLE worker to alarm manager."""
        try:
            logger.info("🎯 DEBUG: Received solved event DIRECTLY from BLE worker!")
            alarm_manager.on_cube_solved()
        except Exception as e:
            logger.error(f"❌ Error in direct solved callback: {e}")
    
    def on_connected_direct(connected: bool):
        """Direct callback from BLE worker to alarm manager for connection status."""
        try:
            logger.info(f"🎯 DEBUG: Received connection event DIRECTLY from BLE worker: {connected}")
            alarm_manager.on_cube_connected(connected)
        except Exception as e:
            logger.error(f"❌ Error in direct connection callback: {e}")
    
    # Register callbacks DIRECTLY with BLE worker
    logger.info("🎯 DEBUG: Registering callbacks DIRECTLY with BLE worker")
    add_move_callback(on_move_direct)
    add_solve_callback(on_solved_direct)
    add_connection_callback(on_connected_direct)
    
    # Smart BLE Connection Strategy: Don't start BLE worker immediately
    # It will be started automatically 10 seconds before each alarm
    logger.info("🔋 Smart BLE strategy: BLE worker will start only when needed for alarms")
    logger.info("💡 This saves cube battery by avoiding continuous polling")

def run_scheduler():
    """Run the alarm scheduler in a separate thread."""
    while True:
        schedule.run_pending()
        threading.Event().wait(1)

if __name__ == '__main__':
    # Smart BLE Connection Strategy: Setup callbacks but don't start BLE worker
    # BLE worker will be started automatically 10 seconds before each alarm
    setup_ble_callbacks()
    
    # Start scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    logger.info("🚀 Starting Rubik's Cube Alarm Server...")
    logger.info("🔋 Smart BLE strategy enabled - BLE worker starts only when needed")
    logger.info("⏰ Scheduler started")
    logger.info("🌐 API server starting on http://localhost:5001")
    
    # Run Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, allow_unsafe_werkzeug=True)
