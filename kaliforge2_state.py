#!/usr/bin/env python3
"""
KaliForge II - State Management & Configuration Persistence
Handles saving/loading configurations, state tracking, and rollback capabilities
"""

import json
import os
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, asdict
import hashlib

@dataclass
class SecurityModeState:
    """State representation of a security mode"""
    mode_name: str
    applied_at: str
    ufw_rules: List[str]
    services: List[str]
    sysctl_params: Dict[str, str]
    custom_configs: Dict[str, Any]
    checksum: str

@dataclass
class KaliForgeConfig:
    """Main KaliForge configuration"""
    user_name: str = ""
    ssh_port: str = "2222"
    profile: str = "standard"
    install_kde: bool = True
    pubkey: str = ""
    github_token: str = ""
    current_mode: str = "setup"
    created_at: str = ""
    last_modified: str = ""
    version: str = "2.0"

class StateManager:
    """Manages KaliForge II state persistence and rollback"""
    
    def __init__(self, state_dir: str = "/etc/kaliforge2"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # Secure the state directory
        try:
            os.chmod(self.state_dir, 0o700)
        except PermissionError:
            pass
        
        self.config_file = self.state_dir / "config.json"
        self.state_file = self.state_dir / "state.json"
        self.backup_dir = self.state_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        self.config = KaliForgeConfig()
        self.current_state = {}
        
        # Load existing configuration
        self.load_config()
        self.load_state()
    
    def save_config(self, config: Optional[KaliForgeConfig] = None) -> bool:
        """Save configuration to persistent storage"""
        if config:
            self.config = config
        
        self.config.last_modified = datetime.now().isoformat()
        
        try:
            # Create backup before saving
            self._backup_config()
            
            # Save configuration
            with open(self.config_file, 'w') as f:
                json.dump(asdict(self.config), f, indent=2)
            
            # Secure the config file
            os.chmod(self.config_file, 0o600)
            return True
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_error(f"Failed to save configuration", e)
            return False
    
    def load_config(self) -> KaliForgeConfig:
        """Load configuration from persistent storage"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                
                # Validate and migrate config if needed
                data = self._migrate_config(data)
                self.config = KaliForgeConfig(**data)
                
            except Exception as e:
                from kaliforge2_logger import get_logger
                get_logger().log_error(f"Failed to load configuration, using defaults", e)
                self.config = KaliForgeConfig()
        
        return self.config
    
    def save_state(self, state_data: Dict[str, Any]) -> bool:
        """Save current system state"""
        try:
            # Add metadata
            state_data.update({
                'timestamp': datetime.now().isoformat(),
                'version': '2.0',
                'checksum': self._calculate_checksum(state_data)
            })
            
            self.current_state = state_data
            
            # Create backup
            self._backup_state()
            
            # Save state
            with open(self.state_file, 'w') as f:
                json.dump(state_data, f, indent=2)
            
            os.chmod(self.state_file, 0o600)
            return True
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_error(f"Failed to save state", e)
            return False
    
    def load_state(self) -> Dict[str, Any]:
        """Load current system state"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    self.current_state = json.load(f)
                
                # Validate checksum
                if not self._validate_state_checksum(self.current_state):
                    from kaliforge2_logger import get_logger
                    get_logger().log_warning("State file checksum validation failed")
                
            except Exception as e:
                from kaliforge2_logger import get_logger
                get_logger().log_error(f"Failed to load state", e)
                self.current_state = {}
        
        return self.current_state
    
    def save_security_mode_state(self, mode_name: str, mode_config: Dict[str, Any]) -> bool:
        """Save detailed security mode state for rollback"""
        try:
            # Capture current system state
            current_state = self._capture_system_state()
            
            mode_state = SecurityModeState(
                mode_name=mode_name,
                applied_at=datetime.now().isoformat(),
                ufw_rules=mode_config.get('ufw_rules', []),
                services=mode_config.get('services', []),
                sysctl_params=mode_config.get('sysctl', {}),
                custom_configs=mode_config.get('custom', {}),
                checksum=self._calculate_checksum(current_state)
            )
            
            # Save to individual file
            mode_file = self.state_dir / f"mode_{mode_name}.json"
            with open(mode_file, 'w') as f:
                json.dump(asdict(mode_state), f, indent=2)
            
            os.chmod(mode_file, 0o600)
            
            # Update main state
            self.current_state['security_mode'] = asdict(mode_state)
            self.save_state(self.current_state)
            
            return True
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_error(f"Failed to save security mode state: {mode_name}", e)
            return False
    
    def get_rollback_points(self) -> List[Dict[str, Any]]:
        """Get available rollback points"""
        rollback_points = []
        
        # Check backup directory
        if self.backup_dir.exists():
            for backup_file in self.backup_dir.glob("state_*.json"):
                try:
                    with open(backup_file, 'r') as f:
                        backup_data = json.load(f)
                    
                    rollback_points.append({
                        'timestamp': backup_data.get('timestamp', 'unknown'),
                        'file': str(backup_file),
                        'mode': backup_data.get('security_mode', {}).get('mode_name', 'unknown'),
                        'config_version': backup_data.get('version', '1.0')
                    })
                    
                except Exception:
                    continue
        
        # Sort by timestamp (newest first)
        rollback_points.sort(key=lambda x: x['timestamp'], reverse=True)
        return rollback_points
    
    def rollback_to_point(self, backup_file: str) -> bool:
        """Rollback to a specific backup point"""
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                return False
            
            # Load backup state
            with open(backup_path, 'r') as f:
                backup_state = json.load(f)
            
            # Create current backup before rollback
            self._backup_state()
            
            # Restore state
            self.current_state = backup_state
            self.save_state(self.current_state)
            
            from kaliforge2_logger import get_logger
            get_logger().log_audit_event(
                'rollback',
                f'system_state:{backup_file}',
                'SUCCESS',
                {'backup_timestamp': backup_state.get('timestamp')}
            )
            
            return True
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_error(f"Failed to rollback to {backup_file}", e)
            return False
    
    def _backup_config(self):
        """Create backup of current configuration"""
        if self.config_file.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"config_{timestamp}.json"
            shutil.copy2(self.config_file, backup_file)
    
    def _backup_state(self):
        """Create backup of current state"""
        if self.state_file.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"state_{timestamp}.json"
            shutil.copy2(self.state_file, backup_file)
        
        # Clean old backups (keep last 20)
        self._clean_old_backups()
    
    def _clean_old_backups(self):
        """Clean old backup files"""
        try:
            backups = sorted(self.backup_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
            for old_backup in backups[20:]:  # Keep 20 most recent
                old_backup.unlink()
        except Exception:
            pass  # Non-critical
    
    def _capture_system_state(self) -> Dict[str, Any]:
        """Capture current system state for comparison"""
        import subprocess
        
        state = {}
        
        try:
            # UFW status
            result = subprocess.run(['ufw', 'status', 'numbered'], 
                                  capture_output=True, text=True, timeout=10)
            state['ufw_status'] = result.stdout
            
            # Services status
            services = ['ssh', 'fail2ban', 'ufw', 'postgresql', 'apache2']
            state['services'] = {}
            for service in services:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True, timeout=5)
                state['services'][service] = result.stdout.strip()
            
            # Sysctl parameters
            result = subprocess.run(['sysctl', '-a'], capture_output=True, text=True, timeout=10)
            state['sysctl'] = result.stdout
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_warning(f"Failed to capture complete system state", extra_data={'error': str(e)})
        
        return state
    
    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        """Calculate checksum of data for integrity verification"""
        # Remove checksum field if present to avoid circular reference
        clean_data = {k: v for k, v in data.items() if k != 'checksum'}
        data_str = json.dumps(clean_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _validate_state_checksum(self, state_data: Dict[str, Any]) -> bool:
        """Validate state data checksum"""
        stored_checksum = state_data.get('checksum')
        if not stored_checksum:
            return False
        
        calculated_checksum = self._calculate_checksum(state_data)
        return stored_checksum == calculated_checksum
    
    def _migrate_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate configuration from older versions"""
        # Add migration logic here as needed
        config_data.setdefault('version', '2.0')
        config_data.setdefault('created_at', datetime.now().isoformat())
        return config_data
    
    def export_config(self, export_path: str) -> bool:
        """Export configuration for sharing/backup"""
        try:
            export_data = {
                'kaliforge_version': '2.0',
                'exported_at': datetime.now().isoformat(),
                'config': asdict(self.config),
                'state_summary': {
                    'current_mode': self.current_state.get('security_mode', {}).get('mode_name', 'unknown'),
                    'last_modified': self.current_state.get('timestamp', 'unknown')
                }
            }
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_error(f"Failed to export configuration", e)
            return False
    
    def import_config(self, import_path: str) -> bool:
        """Import configuration from file"""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            # Validate import data
            if 'config' not in import_data:
                raise ValueError("Invalid configuration file format")
            
            # Create backup before import
            self._backup_config()
            
            # Import configuration
            self.config = KaliForgeConfig(**import_data['config'])
            self.save_config()
            
            from kaliforge2_logger import get_logger
            get_logger().log_audit_event(
                'config_import',
                f'config_file:{import_path}',
                'SUCCESS',
                {'imported_version': import_data.get('kaliforge_version', 'unknown')}
            )
            
            return True
            
        except Exception as e:
            from kaliforge2_logger import get_logger
            get_logger().log_error(f"Failed to import configuration from {import_path}", e)
            return False

# Global state manager instance
_global_state_manager = None

def get_state_manager() -> StateManager:
    """Get global state manager instance"""
    global _global_state_manager
    if _global_state_manager is None:
        _global_state_manager = StateManager()
    return _global_state_manager

def init_state_manager(state_dir: str = "/etc/kaliforge2") -> StateManager:
    """Initialize global state manager"""
    global _global_state_manager
    _global_state_manager = StateManager(state_dir)
    return _global_state_manager