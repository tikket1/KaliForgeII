#!/usr/bin/env python3
"""
KaliForge II - Logging System
Structured logging with rotation, security event tracking, and audit trails
"""

import logging
import logging.handlers
import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

class KaliForgeLogger:
    """Centralized logging system for KaliForge II"""
    
    def __init__(self, log_dir: str = "/var/log/kaliforge2"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Secure the log directory
        try:
            os.chmod(self.log_dir, 0o750)
        except PermissionError:
            pass  # Continue if we can't change permissions
        
        self.loggers = {}
        self.session_id = self._generate_session_id()
        
        # Setup different loggers
        self._setup_main_logger()
        self._setup_security_logger()
        self._setup_audit_logger()
        self._setup_error_logger()
        
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"kf2_{timestamp}_{os.getpid()}"
    
    def _setup_main_logger(self):
        """Setup main application logger"""
        logger = logging.getLogger('kaliforge2.main')
        logger.setLevel(logging.INFO)
        
        # Rotating file handler
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'kaliforge2_main.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(session)s] - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        self.loggers['main'] = logger
    
    def _setup_security_logger(self):
        """Setup security events logger"""
        logger = logging.getLogger('kaliforge2.security')
        logger.setLevel(logging.INFO)
        
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'kaliforge2_security.log',
            maxBytes=50*1024*1024,  # 50MB - security logs are important
            backupCount=10
        )
        
        # JSON formatter for security events
        formatter = SecurityEventFormatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        self.loggers['security'] = logger
    
    def _setup_audit_logger(self):
        """Setup audit trail logger"""
        logger = logging.getLogger('kaliforge2.audit')
        logger.setLevel(logging.INFO)
        
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'kaliforge2_audit.log',
            maxBytes=20*1024*1024,  # 20MB
            backupCount=20  # Keep more audit logs
        )
        
        formatter = AuditFormatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        self.loggers['audit'] = logger
    
    def _setup_error_logger(self):
        """Setup error logger with email notifications"""
        logger = logging.getLogger('kaliforge2.error')
        logger.setLevel(logging.ERROR)
        
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'kaliforge2_errors.log',
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(session)s] - %(filename)s:%(lineno)d - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        self.loggers['error'] = logger
    
    def log_info(self, message: str, category: str = 'main', extra_data: Optional[Dict[str, Any]] = None):
        """Log info message"""
        extra = {'session': self.session_id}
        if extra_data:
            extra.update(extra_data)
        self.loggers[category].info(message, extra=extra)
    
    def log_warning(self, message: str, category: str = 'main', extra_data: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        extra = {'session': self.session_id}
        if extra_data:
            extra.update(extra_data)
        self.loggers[category].warning(message, extra=extra)
    
    def log_error(self, message: str, exception: Optional[Exception] = None, category: str = 'error', extra_data: Optional[Dict[str, Any]] = None):
        """Log error message with optional exception"""
        extra = {'session': self.session_id}
        if extra_data:
            extra.update(extra_data)
        
        if exception:
            self.loggers[category].error(f"{message}: {str(exception)}", exc_info=True, extra=extra)
        else:
            self.loggers[category].error(message, extra=extra)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = 'INFO'):
        """Log security event"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'event_type': event_type,
            'severity': severity,
            'details': details,
            'user': os.getenv('SUDO_USER', os.getenv('USER', 'unknown'))
        }
        
        self.loggers['security'].info(json.dumps(event_data))
    
    def log_audit_event(self, action: str, resource: str, result: str, details: Optional[Dict[str, Any]] = None):
        """Log audit event"""
        audit_data = {
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'action': action,
            'resource': resource,
            'result': result,
            'user': os.getenv('SUDO_USER', os.getenv('USER', 'unknown')),
            'details': details or {}
        }
        
        self.loggers['audit'].info(json.dumps(audit_data))
    
    def log_mode_change(self, from_mode: str, to_mode: str, success: bool, details: Optional[Dict[str, Any]] = None):
        """Log security mode change"""
        self.log_security_event(
            'MODE_CHANGE',
            {
                'from_mode': from_mode,
                'to_mode': to_mode,
                'success': success,
                'details': details or {}
            },
            severity='HIGH' if success else 'CRITICAL'
        )
        
        self.log_audit_event(
            'security_mode_change',
            f'security_mode:{to_mode}',
            'SUCCESS' if success else 'FAILURE',
            {'from_mode': from_mode, 'to_mode': to_mode}
        )
    
    def log_bootstrap_event(self, phase: str, success: bool, details: Optional[Dict[str, Any]] = None):
        """Log bootstrap/installation events"""
        self.log_security_event(
            'BOOTSTRAP',
            {
                'phase': phase,
                'success': success,
                'details': details or {}
            },
            severity='MEDIUM'
        )
    
    def create_session_summary(self) -> Dict[str, Any]:
        """Create summary of current session"""
        return {
            'session_id': self.session_id,
            'start_time': datetime.now().isoformat(),
            'user': os.getenv('SUDO_USER', os.getenv('USER', 'unknown')),
            'log_directory': str(self.log_dir)
        }

class SecurityEventFormatter(logging.Formatter):
    """Custom formatter for security events"""
    
    def format(self, record):
        # Security events are already JSON formatted
        return record.getMessage()

class AuditFormatter(logging.Formatter):
    """Custom formatter for audit events"""
    
    def format(self, record):
        # Audit events are already JSON formatted
        return record.getMessage()

class ProgressLogger:
    """Logger for progress tracking during long operations"""
    
    def __init__(self, operation_name: str, total_steps: int, logger: KaliForgeLogger):
        self.operation_name = operation_name
        self.total_steps = total_steps
        self.current_step = 0
        self.logger = logger
        self.start_time = time.time()
        
        self.logger.log_info(f"Starting operation: {operation_name} ({total_steps} steps)")
    
    def step(self, step_name: str, details: Optional[Dict[str, Any]] = None):
        """Log a step completion"""
        self.current_step += 1
        progress_pct = (self.current_step / self.total_steps) * 100
        
        self.logger.log_info(
            f"Operation {self.operation_name} - Step {self.current_step}/{self.total_steps} ({progress_pct:.1f}%): {step_name}",
            extra_data={
                'operation': self.operation_name,
                'step': self.current_step,
                'total_steps': self.total_steps,
                'progress_percent': progress_pct,
                'step_name': step_name,
                'step_details': details or {}
            }
        )
    
    def complete(self, success: bool = True):
        """Mark operation as complete"""
        duration = time.time() - self.start_time
        
        self.logger.log_info(
            f"Operation {self.operation_name} {'completed successfully' if success else 'failed'} in {duration:.2f}s",
            extra_data={
                'operation': self.operation_name,
                'success': success,
                'duration_seconds': duration,
                'total_steps': self.total_steps
            }
        )

# Global logger instance
_global_logger = None

def get_logger() -> KaliForgeLogger:
    """Get global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = KaliForgeLogger()
    return _global_logger

def init_logger(log_dir: str = "/var/log/kaliforge2") -> KaliForgeLogger:
    """Initialize global logger"""
    global _global_logger
    _global_logger = KaliForgeLogger(log_dir)
    return _global_logger