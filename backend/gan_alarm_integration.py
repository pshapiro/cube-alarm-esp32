#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CubeAlarm-Custom-Attribution
# Copyright (c) 2025 Paul Shapiro
"""
GAN Cube Alarm Integration Module
Connects the enhanced GAN cube backend with the Flask-SocketIO alarm system.
"""

import asyncio
import logging
import threading
from typing import Optional, Callable
from flask_socketio import SocketIO

from .enhanced_gan_cube import EnhancedGANCube, CubeMove, CubeStateInfo

logger = logging.getLogger(__name__)

class GANCubeAlarmIntegration:
    """Integration between GAN cube and alarm system."""
    
    def __init__(self, socketio: Optional[SocketIO] = None):
        self.socketio = socketio
        self.cube = EnhancedGANCube()
        self.alarm_dismissed = False
        self.solve_callbacks = []
        self.move_callbacks = []
        self._cube_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Set up cube callbacks
        self.cube.set_move_callback(self._on_cube_move)
        self.cube.set_solve_callback(self._on_cube_solved)
    
    def add_solve_callback(self, callback: Callable[[], None]):
        """Add callback for when cube is solved."""
        self.solve_callbacks.append(callback)
    
    def add_move_callback(self, callback: Callable[[dict], None]):
        """Add callback for cube moves."""
        self.move_callbacks.append(callback)
    
    def remove_solve_callback(self, callback: Callable[[], None]):
        """Remove solve callback."""
        if callback in self.solve_callbacks:
            self.solve_callbacks.remove(callback)
    
    def remove_move_callback(self, callback: Callable[[dict], None]):
        """Remove move callback."""
        if callback in self.move_callbacks:
            self.move_callbacks.remove(callback)
    
    def _on_cube_move(self, move: CubeMove):
        """Handle cube move events."""
        move_data = {
            'move': move.move,
            'timestamp': move.timestamp,
            'serial': move.serial,
            'face': move.face,
            'direction': move.direction
        }
        
        logger.info(f"🔄 Cube move: {move.move}")
        
        # Emit to SocketIO if available
        if self.socketio:
            self.socketio.emit('cube_move', move_data)
        
        # Call registered move callbacks
        for callback in self.move_callbacks:
            try:
                callback(move_data)
            except Exception as e:
                logger.error(f"Move callback error: {e}")
    
    def _on_cube_solved(self):
        """Handle cube solved events."""
        logger.info("🎉 CUBE SOLVED - DISMISSING ALARM!")
        self.alarm_dismissed = True
        
        # Emit to SocketIO if available
        if self.socketio:
            self.socketio.emit('cube_solved', {'timestamp': asyncio.get_event_loop().time()})
        
        # Call registered solve callbacks
        for callback in self.solve_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Solve callback error: {e}")
    
    def is_cube_solved(self) -> bool:
        """Check if cube is currently solved."""
        return self.cube.is_cube_solved()
    
    def get_cube_state(self) -> CubeStateInfo:
        """Get current cube state information."""
        return self.cube.get_cube_state()
    
    def get_connection_state(self) -> dict:
        """Get cube connection state."""
        return {
            'connected': self.cube.state.connected,
            'device_name': self.cube.state.device_name,
            'mac_address': self.cube.state.mac_address,
            'move_count': self.cube.state.move_count,
            'last_move_time': self.cube.state.last_move_time,
            'is_solved': self.is_cube_solved()
        }
    
    def reset_alarm_state(self):
        """Reset alarm dismissal state."""
        self.alarm_dismissed = False
        logger.info("Alarm state reset")
    
    async def _cube_loop(self):
        """Async cube connection loop."""
        try:
            await self.cube.run()
        except Exception as e:
            logger.error(f"Cube loop error: {e}")
    
    def _cube_thread_worker(self):
        """Thread worker for cube connection."""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run cube loop
            loop.run_until_complete(self._cube_loop())
        except Exception as e:
            logger.error(f"Cube thread error: {e}")
        finally:
            try:
                loop.close()
            except:
                pass
    
    def start(self):
        """Start the cube connection in a separate thread."""
        if self._running:
            logger.warning("Cube integration already running")
            return
        
        self._running = True
        self._cube_thread = threading.Thread(target=self._cube_thread_worker, daemon=True)
        self._cube_thread.start()
        logger.info("🚀 GAN Cube alarm integration started")
    
    def stop(self):
        """Stop the cube connection."""
        if not self._running:
            return
        
        self._running = False
        self.cube.stop()
        
        if self._cube_thread and self._cube_thread.is_alive():
            self._cube_thread.join(timeout=5)
        
        logger.info("🛑 GAN Cube alarm integration stopped")

# Global instance for easy access
_cube_integration: Optional[GANCubeAlarmIntegration] = None

def initialize_cube_integration(socketio: Optional[SocketIO] = None) -> GANCubeAlarmIntegration:
    """Initialize the global cube integration instance."""
    global _cube_integration
    if _cube_integration is None:
        _cube_integration = GANCubeAlarmIntegration(socketio)
    return _cube_integration

def get_cube_integration() -> Optional[GANCubeAlarmIntegration]:
    """Get the global cube integration instance."""
    return _cube_integration

def start_cube_monitoring(socketio: Optional[SocketIO] = None):
    """Start cube monitoring (convenience function)."""
    integration = initialize_cube_integration(socketio)
    integration.start()
    return integration

def stop_cube_monitoring():
    """Stop cube monitoring (convenience function)."""
    global _cube_integration
    if _cube_integration:
        _cube_integration.stop()

# Compatibility functions for existing alarm system
def add_solve_callback(callback: Callable[[], None]):
    """Add solve callback (compatibility function)."""
    integration = get_cube_integration()
    if integration:
        integration.add_solve_callback(callback)

def add_move_callback(callback: Callable[[dict], None]):
    """Add move callback (compatibility function)."""
    integration = get_cube_integration()
    if integration:
        integration.add_move_callback(callback)

def is_cube_solved() -> bool:
    """Check if cube is solved (compatibility function)."""
    integration = get_cube_integration()
    if integration:
        return integration.is_cube_solved()
    return False

def get_connection() -> Optional[dict]:
    """Get connection state (compatibility function)."""
    integration = get_cube_integration()
    if integration:
        return integration.get_connection_state()
    return None

# Example usage
if __name__ == "__main__":
    def on_solve():
        print("🎉 ALARM DISMISSED - CUBE SOLVED!")
    
    def on_move(move_data):
        print(f"🔄 Move: {move_data['move']}")
    
    # Start integration
    integration = start_cube_monitoring()
    integration.add_solve_callback(on_solve)
    integration.add_move_callback(on_move)
    
    try:
        # Keep running
        import time
        while True:
            time.sleep(1)
            state = integration.get_connection_state()
            if state['connected']:
                print(f"Connected: {state['move_count']} moves, solved: {state['is_solved']}")
    except KeyboardInterrupt:
        print("Stopping...")
        stop_cube_monitoring()
