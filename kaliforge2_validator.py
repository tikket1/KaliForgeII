#!/usr/bin/env python3
"""
KaliForge II - Input Validation & Sanitization
Comprehensive validation for all user inputs and system configurations
"""

import re
import ipaddress
import subprocess
import os
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
import base64

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class SecurityValidator:
    """Validates security-sensitive inputs and configurations"""
    
    # Allowed characters for different input types
    SAFE_USERNAME_PATTERN = re.compile(r'^[a-z][a-z0-9_-]{2,31}$')
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
    SSH_KEY_PATTERN = re.compile(r'^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+[A-Za-z0-9+/]+=*\s*.*$')
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        r'[;&|`$()]',  # Command injection
        r'\.\./',      # Directory traversal
        r'<script',    # XSS (just in case)
        r'union\s+select',  # SQL injection patterns
        r'drop\s+table',
        r'/etc/passwd',     # System file access
        r'/etc/shadow',
        r'rm\s+-rf',       # Dangerous commands
        r'chmod\s+777',
        r'\.{2,}',         # Multiple dots
    ]
    
    @classmethod
    def validate_username(cls, username: str) -> Tuple[bool, str]:
        """Validate username for security and system compatibility"""
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 32:
            return False, "Username must be 32 characters or less"
        
        if not cls.SAFE_USERNAME_PATTERN.match(username):
            return False, "Username can only contain lowercase letters, numbers, hyphens, and underscores, and must start with a letter"
        
        # Check against reserved names
        reserved_names = {
            'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp',
            'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list',
            'nobody', 'systemd-network', 'systemd-resolve', 'syslog',
            'admin', 'administrator', 'test', 'guest', 'kali'
        }
        
        if username.lower() in reserved_names:
            return False, f"Username '{username}' is reserved by the system"
        
        # Check if user already exists
        try:
            result = subprocess.run(['id', username], capture_output=True, text=True)
            if result.returncode == 0:
                return False, f"User '{username}' already exists on the system"
        except Exception:
            pass  # Unable to check, proceed
        
        return True, "Valid username"
    
    @classmethod
    def validate_ssh_port(cls, port: str) -> Tuple[bool, str]:
        """Validate SSH port number"""
        try:
            port_num = int(port)
        except ValueError:
            return False, "Port must be a number"
        
        if port_num < 1024:
            return False, "Port must be 1024 or higher (unprivileged ports)"
        
        if port_num > 65535:
            return False, "Port must be 65535 or lower"
        
        # Check if port is already in use
        try:
            result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
            if f":{port_num} " in result.stdout:
                return False, f"Port {port_num} is already in use"
        except Exception:
            pass  # Unable to check, proceed with warning
        
        # Warn about common ports
        common_ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL'}
        if port_num in common_ports:
            return True, f"Warning: Port {port_num} is commonly used for {common_ports[port_num]}"
        
        return True, "Valid port"
    
    @classmethod
    def validate_ssh_public_key(cls, key: str) -> Tuple[bool, str]:
        """Validate SSH public key format and security"""
        if not key.strip():
            return True, "SSH key is optional"  # Empty is OK
        
        key = key.strip()
        
        # Basic format check
        if not cls.SSH_KEY_PATTERN.match(key):
            return False, "Invalid SSH key format. Expected format: 'ssh-rsa AAAAB3... [comment]'"
        
        parts = key.split()
        if len(parts) < 2:
            return False, "SSH key must contain at least key type and key data"
        
        key_type = parts[0]
        key_data = parts[1]
        
        # Validate key type
        allowed_types = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
        if key_type not in allowed_types:
            return False, f"Unsupported key type '{key_type}'. Allowed types: {', '.join(allowed_types)}"
        
        # Validate base64 encoding
        try:
            base64.b64decode(key_data)
        except Exception:
            return False, "SSH key data is not valid base64"
        
        # Check key length (approximate)
        if key_type == 'ssh-rsa' and len(key_data) < 372:  # ~2048 bit RSA minimum
            return False, "RSA key appears to be too short (minimum 2048 bits recommended)"
        
        # Security recommendations
        if key_type == 'ssh-rsa':
            return True, "Valid SSH key (Note: Ed25519 keys are more secure than RSA)"
        elif key_type == 'ssh-ed25519':
            return True, "Valid SSH key (Ed25519 - excellent security)"
        else:
            return True, "Valid SSH key (ECDSA)"
    
    @classmethod
    def validate_github_token(cls, token: str) -> Tuple[bool, str]:
        """Validate GitHub token format"""
        if not token.strip():
            return True, "GitHub token is optional"
        
        token = token.strip()
        
        # GitHub token patterns
        if token.startswith('ghp_') and len(token) == 40:  # Personal access token
            return True, "Valid GitHub personal access token format"
        elif token.startswith('gho_') and len(token) == 40:  # OAuth token
            return True, "Valid GitHub OAuth token format"
        elif token.startswith('ghu_') and len(token) == 40:  # User-to-server token
            return True, "Valid GitHub user-to-server token format"
        elif token.startswith('ghs_') and len(token) == 40:  # Server-to-server token
            return True, "Valid GitHub server-to-server token format"
        elif len(token) == 40 and all(c in '0123456789abcdef' for c in token):
            return True, "Valid legacy GitHub token format"
        else:
            return False, "Invalid GitHub token format"
    
    @classmethod
    def validate_profile_name(cls, profile: str) -> Tuple[bool, str]:
        """Validate security profile name"""
        allowed_profiles = ['minimal', 'webapp', 'internal', 'cloud', 'standard', 'heavy']
        
        if profile not in allowed_profiles:
            return False, f"Invalid profile '{profile}'. Allowed profiles: {', '.join(allowed_profiles)}"
        
        return True, f"Valid profile: {profile}"
    
    @classmethod
    def validate_security_mode(cls, mode: str) -> Tuple[bool, str]:
        """Validate security mode name"""
        allowed_modes = ['hardened', 'honeypot', 'stealth', 'pentest']
        
        if mode not in allowed_modes:
            return False, f"Invalid security mode '{mode}'. Allowed modes: {', '.join(allowed_modes)}"
        
        return True, f"Valid security mode: {mode}"
    
    @classmethod
    def sanitize_input(cls, user_input: str, input_type: str = 'general') -> str:
        """Sanitize user input based on type"""
        if not isinstance(user_input, str):
            user_input = str(user_input)
        
        # Remove null bytes and control characters
        sanitized = user_input.replace('\x00', '').replace('\r', '').replace('\n', ' ')
        
        # Limit length
        max_lengths = {
            'username': 32,
            'port': 5,
            'ssh_key': 4096,
            'github_token': 50,
            'profile': 20,
            'mode': 20,
            'general': 1000
        }
        
        max_len = max_lengths.get(input_type, max_lengths['general'])
        if len(sanitized) > max_len:
            sanitized = sanitized[:max_len]
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, sanitized, re.IGNORECASE):
                raise ValidationError(f"Input contains potentially dangerous pattern: {pattern}")
        
        return sanitized.strip()
    
    @classmethod
    def validate_file_path(cls, file_path: str, allowed_dirs: Optional[List[str]] = None) -> Tuple[bool, str]:
        """Validate file path for security"""
        try:
            path = Path(file_path).resolve()
        except Exception:
            return False, "Invalid file path"
        
        # Check for directory traversal
        if '..' in file_path:
            return False, "Directory traversal detected in path"
        
        # Check against allowed directories
        if allowed_dirs:
            allowed = False
            for allowed_dir in allowed_dirs:
                try:
                    allowed_path = Path(allowed_dir).resolve()
                    if path.is_relative_to(allowed_path):
                        allowed = True
                        break
                except Exception:
                    continue
            
            if not allowed:
                return False, f"Path must be within allowed directories: {', '.join(allowed_dirs)}"
        
        # Check filename
        filename = path.name
        if not cls.SAFE_FILENAME_PATTERN.match(filename):
            return False, "Filename contains unsafe characters"
        
        return True, "Valid file path"
    
    @classmethod
    def validate_system_requirements(cls) -> Dict[str, Any]:
        """Validate system requirements and dependencies"""
        results = {
            'os': {'valid': False, 'message': ''},
            'user': {'valid': False, 'message': ''},
            'python': {'valid': False, 'message': ''},
            'dependencies': {'valid': False, 'message': '', 'missing': []},
            'permissions': {'valid': False, 'message': ''}
        }
        
        # Check OS
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read()
            
            if 'kali' in os_info.lower() or 'debian' in os_info.lower() or 'ubuntu' in os_info.lower():
                results['os'] = {'valid': True, 'message': 'Compatible Linux distribution detected'}
            else:
                results['os'] = {'valid': False, 'message': 'Unsupported Linux distribution (Kali/Debian/Ubuntu recommended)'}
        except Exception:
            results['os'] = {'valid': False, 'message': 'Unable to determine OS'}
        
        # Check user permissions
        if os.geteuid() == 0:
            results['user'] = {'valid': True, 'message': 'Running with root privileges'}
        else:
            results['user'] = {'valid': False, 'message': 'Root privileges required'}
        
        # Check Python version
        import sys
        if sys.version_info >= (3, 6):
            results['python'] = {'valid': True, 'message': f'Python {sys.version_info.major}.{sys.version_info.minor} - Compatible'}
        else:
            results['python'] = {'valid': False, 'message': 'Python 3.6+ required'}
        
        # Check dependencies
        required_commands = ['ufw', 'systemctl', 'curl', 'wget', 'ssh-keygen']
        missing = []
        
        for cmd in required_commands:
            try:
                result = subprocess.run(['which', cmd], capture_output=True, text=True)
                if result.returncode != 0:
                    missing.append(cmd)
            except Exception:
                missing.append(cmd)
        
        if missing:
            results['dependencies'] = {
                'valid': False, 
                'message': f'Missing required commands: {", ".join(missing)}',
                'missing': missing
            }
        else:
            results['dependencies'] = {'valid': True, 'message': 'All required dependencies found', 'missing': []}
        
        # Check permissions on key directories
        try:
            test_dirs = ['/var/log', '/etc']
            for test_dir in test_dirs:
                if not os.access(test_dir, os.W_OK):
                    results['permissions'] = {'valid': False, 'message': f'No write access to {test_dir}'}
                    break
            else:
                results['permissions'] = {'valid': True, 'message': 'Sufficient file system permissions'}
        except Exception:
            results['permissions'] = {'valid': False, 'message': 'Unable to check file system permissions'}
        
        return results

class InputSanitizer:
    """Helper class for input sanitization"""
    
    @staticmethod
    def escape_shell_arg(arg: str) -> str:
        """Escape argument for safe shell usage"""
        import shlex
        return shlex.quote(str(arg))
    
    @staticmethod
    def filter_alphanumeric(text: str, allow_spaces: bool = False) -> str:
        """Filter to alphanumeric characters only"""
        pattern = r'[^a-zA-Z0-9\s]' if allow_spaces else r'[^a-zA-Z0-9]'
        return re.sub(pattern, '', text)
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalize file path"""
        return str(Path(path).resolve())

# Quick validation functions for common use cases
def quick_validate(input_value: str, input_type: str) -> bool:
    """Quick validation function"""
    validator_map = {
        'username': SecurityValidator.validate_username,
        'ssh_port': SecurityValidator.validate_ssh_port,
        'ssh_key': SecurityValidator.validate_ssh_public_key,
        'github_token': SecurityValidator.validate_github_token,
        'profile': SecurityValidator.validate_profile_name,
        'security_mode': SecurityValidator.validate_security_mode
    }
    
    validator = validator_map.get(input_type)
    if validator:
        valid, message = validator(input_value)
        return valid
    
    return True  # Unknown type, assume valid

def validate_all_inputs(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate all configuration inputs"""
    results = {}
    
    # Validate each field
    validators = {
        'USER_NAME': ('username', SecurityValidator.validate_username),
        'SSH_PORT': ('ssh_port', SecurityValidator.validate_ssh_port),
        'PUBKEY': ('ssh_key', SecurityValidator.validate_ssh_public_key),
        'GITHUB_TOKEN': ('github_token', SecurityValidator.validate_github_token),
        'PROFILE': ('profile', SecurityValidator.validate_profile_name)
    }
    
    for field, (field_type, validator) in validators.items():
        if field in config_data:
            valid, message = validator(config_data[field])
            results[field] = {
                'valid': valid,
                'message': message,
                'sanitized': SecurityValidator.sanitize_input(config_data[field], field_type)
            }
    
    return results