#!/usr/bin/env python3
"""
KaliForge II - Comprehensive Security Monitoring System
Monitors: System resources, Security events, Security posture compliance
"""

import os
import sys
import time
import psutil
import subprocess
import json
import threading
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import curses

class SecurityMonitor:
    """Comprehensive security monitoring dashboard"""
    
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.running = True
        self.update_interval = 3.0  # seconds
        
        # Initialize colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Good/Safe
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Warning
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Critical/Danger
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Headers
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Normal text
        curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Highlight
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_RED)     # Critical alert
        
        # Data storage
        self.system_metrics = {}
        self.security_events = []
        self.security_alerts = []
        self.compliance_status = {}
        self.service_status = {}
        
        # Security-focused services to monitor
        self.critical_services = [
            'ssh', 'ufw', 'fail2ban', 'auditd', 'rsyslog', 
            'apparmor', 'systemd-resolved', 'cron'
        ]
        
        # Security event sources
        self.log_files = {
            'auth_log': '/var/log/auth.log',
            'ufw_log': '/var/log/ufw.log', 
            'fail2ban_log': '/var/log/fail2ban.log',
            'audit_log': '/var/log/audit/audit.log',
            'kern_log': '/var/log/kern.log'
        }
        
        # Track log file positions for incremental reading
        self.log_positions = {log: 0 for log in self.log_files.keys()}
        
        # Security baselines and compliance checks
        self.security_checks = {
            'ssh_config': self._check_ssh_security,
            'firewall_status': self._check_firewall_status,
            'user_accounts': self._check_user_accounts,
            'file_permissions': self._check_critical_permissions,
            'network_services': self._check_network_services,
            'system_updates': self._check_system_updates,
            'password_policy': self._check_password_policy,
            'audit_config': self._check_audit_config
        }
        
        # Current view mode
        self.view_mode = 'overview'  # overview, system, events, compliance
        
    def start_monitoring(self):
        """Start background monitoring threads"""
        # System monitoring thread
        system_thread = threading.Thread(target=self._system_monitoring_loop, daemon=True)
        system_thread.start()
        
        # Security event monitoring thread  
        events_thread = threading.Thread(target=self._security_events_loop, daemon=True)
        events_thread.start()
        
        # Compliance monitoring thread (slower updates)
        compliance_thread = threading.Thread(target=self._compliance_monitoring_loop, daemon=True)
        compliance_thread.start()
    
    def _system_monitoring_loop(self):
        """Monitor system resources with security context"""
        while self.running:
            try:
                # Basic system metrics
                self.system_metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': psutil.cpu_percent(interval=0.1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_percent': psutil.disk_usage('/').percent,
                    'load_avg': os.getloadavg(),
                    'process_count': len(psutil.pids()),
                    'network_connections': len(psutil.net_connections()),
                    'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
                }
                
                # Security-relevant system checks
                self._check_suspicious_processes()
                self._check_network_connections()
                self._update_service_status()
                
            except Exception as e:
                self._add_security_alert('SYSTEM_ERROR', f'System monitoring error: {str(e)}', 'ERROR')
            
            time.sleep(self.update_interval)
    
    def _security_events_loop(self):
        """Monitor security events from log files"""
        while self.running:
            try:
                self._monitor_auth_events()
                self._monitor_firewall_events() 
                self._monitor_fail2ban_events()
                self._monitor_audit_events()
                
            except Exception as e:
                self._add_security_alert('EVENT_ERROR', f'Event monitoring error: {str(e)}', 'ERROR')
            
            time.sleep(2.0)  # More frequent for security events
    
    def _compliance_monitoring_loop(self):
        """Monitor security compliance and configuration drift"""
        while self.running:
            try:
                for check_name, check_func in self.security_checks.items():
                    result = check_func()
                    self.compliance_status[check_name] = {
                        'timestamp': datetime.now().isoformat(),
                        'status': result['status'],
                        'message': result['message'],
                        'details': result.get('details', {}),
                        'risk_level': result.get('risk_level', 'LOW')
                    }
                    
                    # Generate alerts for compliance failures
                    if result['status'] != 'COMPLIANT':
                        self._add_security_alert(
                            'COMPLIANCE_VIOLATION',
                            f'{check_name}: {result["message"]}',
                            result.get('risk_level', 'MEDIUM')
                        )
                
            except Exception as e:
                self._add_security_alert('COMPLIANCE_ERROR', f'Compliance check error: {str(e)}', 'ERROR')
            
            time.sleep(30.0)  # Compliance checks every 30 seconds
    
    def _check_suspicious_processes(self):
        """Check for suspicious or security-relevant processes"""
        suspicious_found = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                # Check for suspicious process names
                suspicious_patterns = [
                    r'nc|netcat', r'nmap', r'masscan', r'zmap',
                    r'metasploit|msfconsole', r'sqlmap', r'gobuster',
                    r'nikto', r'dirb', r'wfuzz', r'hydra', r'john'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, proc_name):
                        suspicious_found.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': ' '.join(proc_info['cmdline'][:3]) if proc_info['cmdline'] else '',
                            'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat()
                        })
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if suspicious_found:
            self._add_security_alert(
                'SUSPICIOUS_PROCESS',
                f'Found {len(suspicious_found)} suspicious processes',
                'MEDIUM'
            )
        
        self.system_metrics['suspicious_processes'] = suspicious_found
    
    def _check_network_connections(self):
        """Monitor network connections for suspicious activity"""
        connections = []
        external_connections = 0
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                connections.append({
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status,
                    'pid': conn.pid
                })
                
                # Count external connections (not localhost)
                if conn.raddr and not conn.raddr.ip.startswith(('127.', '192.168.', '10.', '172.')):
                    external_connections += 1
        
        self.system_metrics['network_connections_detail'] = connections
        self.system_metrics['external_connections'] = external_connections
        
        # Alert on many external connections
        if external_connections > 10:
            self._add_security_alert(
                'HIGH_NETWORK_ACTIVITY',
                f'{external_connections} external network connections active',
                'MEDIUM'
            )
    
    def _update_service_status(self):
        """Update status of security-critical services"""
        for service in self.critical_services:
            try:
                # Check if service is active
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True, text=True, timeout=5
                )
                active = result.returncode == 0 and result.stdout.strip() == 'active'
                
                # Check if service is enabled
                result = subprocess.run(
                    ['systemctl', 'is-enabled', service],
                    capture_output=True, text=True, timeout=5
                )
                enabled = result.returncode == 0 and result.stdout.strip() == 'enabled'
                
                self.service_status[service] = {
                    'active': active,
                    'enabled': enabled,
                    'status': 'active' if active else 'inactive',
                    'last_check': datetime.now().isoformat()
                }
                
                # Alert on critical service failures
                if not active and service in ['ufw', 'fail2ban', 'ssh']:
                    self._add_security_alert(
                        'CRITICAL_SERVICE_DOWN',
                        f'Critical security service {service} is not active',
                        'CRITICAL'
                    )
                    
            except Exception as e:
                self.service_status[service] = {
                    'active': False,
                    'enabled': False,
                    'status': 'error',
                    'error': str(e),
                    'last_check': datetime.now().isoformat()
                }
    
    def _monitor_auth_events(self):
        """Monitor authentication events from auth.log"""
        auth_log = self.log_files['auth_log']
        if not os.path.exists(auth_log):
            return
        
        try:
            with open(auth_log, 'r') as f:
                f.seek(self.log_positions['auth_log'])
                new_lines = f.readlines()
                self.log_positions['auth_log'] = f.tell()
            
            for line in new_lines:
                line = line.strip()
                
                # Failed SSH login attempts
                if 'Failed password' in line or 'authentication failure' in line:
                    self._add_security_event('AUTH_FAILURE', line, 'HIGH')
                
                # Successful SSH logins
                elif 'Accepted password' in line or 'Accepted publickey' in line:
                    self._add_security_event('AUTH_SUCCESS', line, 'INFO')
                
                # Invalid users
                elif 'Invalid user' in line:
                    self._add_security_event('INVALID_USER', line, 'HIGH')
                
                # Root login attempts
                elif 'root' in line and ('Failed password' in line or 'Invalid user' in line):
                    self._add_security_event('ROOT_ACCESS_ATTEMPT', line, 'CRITICAL')
                
                # Multiple failed attempts
                elif 'maximum authentication attempts exceeded' in line:
                    self._add_security_event('BRUTE_FORCE_ATTEMPT', line, 'CRITICAL')
                    
        except Exception as e:
            pass  # Log file might be rotated or locked
    
    def _monitor_firewall_events(self):
        """Monitor UFW firewall events"""
        ufw_log = self.log_files['ufw_log']
        if not os.path.exists(ufw_log):
            return
            
        try:
            with open(ufw_log, 'r') as f:
                f.seek(self.log_positions['ufw_log'])
                new_lines = f.readlines()
                self.log_positions['ufw_log'] = f.tell()
            
            blocked_count = 0
            for line in new_lines:
                if '[UFW BLOCK]' in line:
                    blocked_count += 1
                    # Only alert on first few blocks to avoid spam
                    if blocked_count <= 5:
                        self._add_security_event('FIREWALL_BLOCK', line, 'MEDIUM')
            
            if blocked_count > 0:
                self.system_metrics['firewall_blocks'] = blocked_count
                
        except Exception as e:
            pass
    
    def _monitor_fail2ban_events(self):
        """Monitor fail2ban events"""
        fail2ban_log = self.log_files['fail2ban_log']
        if not os.path.exists(fail2ban_log):
            return
            
        try:
            with open(fail2ban_log, 'r') as f:
                f.seek(self.log_positions['fail2ban_log'])
                new_lines = f.readlines()
                self.log_positions['fail2ban_log'] = f.tell()
            
            for line in new_lines:
                if 'Ban' in line:
                    self._add_security_event('IP_BANNED', line, 'HIGH')
                elif 'Unban' in line:
                    self._add_security_event('IP_UNBANNED', line, 'MEDIUM')
                    
        except Exception as e:
            pass
    
    def _monitor_audit_events(self):
        """Monitor audit events (if auditd is available)"""
        audit_log = self.log_files['audit_log']
        if not os.path.exists(audit_log):
            return
            
        try:
            with open(audit_log, 'r') as f:
                f.seek(self.log_positions['audit_log'])
                new_lines = f.readlines()
                self.log_positions['audit_log'] = f.tell()
            
            for line in new_lines:
                # Look for security-relevant audit events
                if any(keyword in line for keyword in ['SYSCALL', 'USER_LOGIN', 'USER_AUTH']):
                    # Parse basic audit event (simplified)
                    if 'denied' in line.lower() or 'failed' in line.lower():
                        self._add_security_event('AUDIT_DENIAL', line[:100], 'MEDIUM')
                        
        except Exception as e:
            pass
    
    def _add_security_event(self, event_type: str, message: str, severity: str):
        """Add a security event to the events list"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'message': message,
            'severity': severity
        }
        
        self.security_events.append(event)
        
        # Keep only last 100 events
        if len(self.security_events) > 100:
            self.security_events.pop(0)
        
        # Generate alert for high/critical events
        if severity in ['HIGH', 'CRITICAL']:
            self._add_security_alert(event_type, message, severity)
    
    def _add_security_alert(self, alert_type: str, message: str, severity: str):
        """Add a security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': severity
        }
        
        self.security_alerts.append(alert)
        
        # Keep only last 50 alerts
        if len(self.security_alerts) > 50:
            self.security_alerts.pop(0)
    
    # Security compliance check functions
    def _check_ssh_security(self) -> Dict[str, Any]:
        """Check SSH configuration security"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                ssh_config = f.read()
            
            issues = []
            
            if 'PasswordAuthentication yes' in ssh_config:
                issues.append('Password authentication enabled')
            
            if 'PermitRootLogin yes' in ssh_config:
                issues.append('Root login permitted')
            
            if 'Port 22' in ssh_config or not re.search(r'Port\s+\d+', ssh_config):
                issues.append('Using default SSH port 22')
            
            if issues:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': f'SSH security issues: {", ".join(issues)}',
                    'risk_level': 'HIGH',
                    'details': {'issues': issues}
                }
            else:
                return {
                    'status': 'COMPLIANT',
                    'message': 'SSH configuration secure',
                    'risk_level': 'LOW'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Cannot check SSH config: {str(e)}',
                'risk_level': 'MEDIUM'
            }
    
    def _check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall configuration"""
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
            
            if 'Status: active' not in result.stdout:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': 'UFW firewall is not active',
                    'risk_level': 'CRITICAL'
                }
            
            # Check for default deny policy
            if 'Default: deny (incoming)' not in result.stdout:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': 'UFW not configured with default deny policy',
                    'risk_level': 'HIGH'
                }
            
            return {
                'status': 'COMPLIANT',
                'message': 'Firewall active with secure configuration',
                'risk_level': 'LOW'
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Cannot check firewall: {str(e)}',
                'risk_level': 'HIGH'
            }
    
    def _check_user_accounts(self) -> Dict[str, Any]:
        """Check for suspicious user accounts"""
        try:
            with open('/etc/passwd', 'r') as f:
                passwd_entries = f.readlines()
            
            issues = []
            user_count = 0
            
            for line in passwd_entries:
                fields = line.strip().split(':')
                if len(fields) >= 3:
                    username = fields[0]
                    uid = int(fields[2])
                    shell = fields[6] if len(fields) > 6 else ''
                    
                    # Count non-system users
                    if uid >= 1000 and uid < 65534:
                        user_count += 1
                    
                    # Check for users with shell access
                    if uid >= 1000 and shell.endswith(('bash', 'sh', 'zsh')):
                        if username not in ['ubuntu', 'kali']:  # Common legitimate users
                            issues.append(f'User {username} has shell access')
            
            if user_count > 5:
                issues.append(f'Many user accounts found: {user_count}')
            
            if issues:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': f'User account issues: {", ".join(issues[:2])}',
                    'risk_level': 'MEDIUM',
                    'details': {'issues': issues, 'user_count': user_count}
                }
            else:
                return {
                    'status': 'COMPLIANT',
                    'message': f'User accounts look normal ({user_count} users)',
                    'risk_level': 'LOW'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Cannot check users: {str(e)}',
                'risk_level': 'MEDIUM'
            }
    
    def _check_critical_permissions(self) -> Dict[str, Any]:
        """Check permissions on critical files"""
        critical_files = {
            '/etc/passwd': '644',
            '/etc/shadow': '640',
            '/etc/ssh/sshd_config': '600',
            '/etc/sudoers': '440'
        }
        
        issues = []
        
        for file_path, expected_perms in critical_files.items():
            try:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    actual_perms = oct(stat_info.st_mode)[-3:]
                    
                    if actual_perms != expected_perms:
                        issues.append(f'{file_path}: {actual_perms} (expected {expected_perms})')
                        
            except Exception:
                issues.append(f'{file_path}: cannot check permissions')
        
        if issues:
            return {
                'status': 'NON_COMPLIANT',
                'message': f'Permission issues: {len(issues)} files',
                'risk_level': 'HIGH',
                'details': {'issues': issues}
            }
        else:
            return {
                'status': 'COMPLIANT', 
                'message': 'Critical file permissions correct',
                'risk_level': 'LOW'
            }
    
    def _check_network_services(self) -> Dict[str, Any]:
        """Check for unnecessary network services"""
        try:
            listening_ports = []
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN:
                    listening_ports.append(conn.laddr.port)
            
            # Check for common unnecessary services
            suspicious_ports = [
                21,    # FTP
                23,    # Telnet  
                25,    # SMTP
                110,   # POP3
                143,   # IMAP
                443,   # HTTPS (might be unnecessary)
                993,   # IMAPS
                995    # POP3S
            ]
            
            found_suspicious = [port for port in suspicious_ports if port in listening_ports]
            
            if found_suspicious:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': f'Unnecessary services on ports: {", ".join(map(str, found_suspicious))}',
                    'risk_level': 'MEDIUM',
                    'details': {'suspicious_ports': found_suspicious, 'all_ports': listening_ports}
                }
            else:
                return {
                    'status': 'COMPLIANT',
                    'message': f'Network services look reasonable ({len(listening_ports)} ports)',
                    'risk_level': 'LOW'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Cannot check network services: {str(e)}',
                'risk_level': 'MEDIUM'
            }
    
    def _check_system_updates(self) -> Dict[str, Any]:
        """Check for available system updates"""
        try:
            result = subprocess.run(
                ['apt', 'list', '--upgradable'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                upgradable_lines = result.stdout.strip().split('\n')
                update_count = len([line for line in upgradable_lines if '/' in line]) - 1  # Exclude header
                
                if update_count > 20:
                    return {
                        'status': 'NON_COMPLIANT',
                        'message': f'{update_count} updates available (many)',
                        'risk_level': 'HIGH'
                    }
                elif update_count > 0:
                    return {
                        'status': 'NON_COMPLIANT',
                        'message': f'{update_count} updates available',
                        'risk_level': 'MEDIUM'
                    }
                else:
                    return {
                        'status': 'COMPLIANT',
                        'message': 'System is up to date',
                        'risk_level': 'LOW'
                    }
            else:
                return {
                    'status': 'ERROR',
                    'message': 'Cannot check for updates',
                    'risk_level': 'MEDIUM'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Update check failed: {str(e)}',
                'risk_level': 'MEDIUM'
            }
    
    def _check_password_policy(self) -> Dict[str, Any]:
        """Check password policy configuration"""
        try:
            issues = []
            
            # Check /etc/login.defs for password aging
            if os.path.exists('/etc/login.defs'):
                with open('/etc/login.defs', 'r') as f:
                    login_defs = f.read()
                
                if 'PASS_MAX_DAYS\t99999' in login_defs:
                    issues.append('Password never expires')
                
                if 'PASS_MIN_LEN\t5' in login_defs or 'PASS_MIN_LEN 5' in login_defs:
                    issues.append('Minimum password length too short')
            
            # Check for pam_pwquality
            pam_common_password = '/etc/pam.d/common-password'
            if os.path.exists(pam_common_password):
                with open(pam_common_password, 'r') as f:
                    pam_config = f.read()
                
                if 'pam_pwquality' not in pam_config:
                    issues.append('Password quality checking not enabled')
            
            if issues:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': f'Password policy issues: {", ".join(issues[:2])}',
                    'risk_level': 'MEDIUM',
                    'details': {'issues': issues}
                }
            else:
                return {
                    'status': 'COMPLIANT',
                    'message': 'Password policy configured',
                    'risk_level': 'LOW'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Cannot check password policy: {str(e)}',
                'risk_level': 'MEDIUM'
            }
    
    def _check_audit_config(self) -> Dict[str, Any]:
        """Check audit daemon configuration"""
        try:
            # Check if auditd is running
            if 'auditd' not in self.service_status or not self.service_status['auditd']['active']:
                return {
                    'status': 'NON_COMPLIANT',
                    'message': 'Audit daemon not running',
                    'risk_level': 'MEDIUM'
                }
            
            # Check for basic audit rules
            result = subprocess.run(['auditctl', '-l'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                rules = result.stdout
                if len(rules.strip()) < 10:  # Very few or no rules
                    return {
                        'status': 'NON_COMPLIANT',
                        'message': 'Audit rules not configured',
                        'risk_level': 'MEDIUM'
                    }
                else:
                    return {
                        'status': 'COMPLIANT',
                        'message': 'Audit system configured',
                        'risk_level': 'LOW'
                    }
            else:
                return {
                    'status': 'ERROR',
                    'message': 'Cannot check audit configuration',
                    'risk_level': 'MEDIUM'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Audit check failed: {str(e)}',
                'risk_level': 'MEDIUM'
            }

    def draw_dashboard(self):
        """Draw the security monitoring dashboard"""
        self.stdscr.clear()
        
        # Title and current time
        title = f"KaliForge II Security Monitor - {self.view_mode.upper()}"
        self.stdscr.addstr(0, 0, title, curses.color_pair(4) | curses.A_BOLD)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.stdscr.addstr(0, self.width - len(current_time) - 1, current_time, curses.color_pair(5))
        except curses.error:
            pass
        
        # Draw content based on view mode
        if self.view_mode == 'overview':
            self._draw_overview()
        elif self.view_mode == 'system':
            self._draw_system_details()
        elif self.view_mode == 'events':
            self._draw_security_events()
        elif self.view_mode == 'compliance':
            self._draw_compliance_status()
        
        # Instructions
        instructions = "1:Overview 2:System 3:Events 4:Compliance Q:Quit R:Refresh C:Clear"
        try:
            self.stdscr.addstr(self.height - 1, 0, instructions[:self.width-1], curses.color_pair(6))
        except curses.error:
            pass
        
        self.stdscr.refresh()
    
    def _draw_overview(self):
        """Draw overview dashboard with key metrics"""
        y = 2
        
        # System status section
        self.stdscr.addstr(y, 0, "SYSTEM STATUS", curses.color_pair(4) | curses.A_BOLD)
        y += 1
        
        if self.system_metrics:
            cpu_pct = self.system_metrics.get('cpu_percent', 0)
            mem_pct = self.system_metrics.get('memory_percent', 0)
            disk_pct = self.system_metrics.get('disk_percent', 0)
            
            cpu_color = self._get_status_color(cpu_pct, 70, 90)
            mem_color = self._get_status_color(mem_pct, 80, 90) 
            disk_color = self._get_status_color(disk_pct, 85, 95)
            
            self.stdscr.addstr(y, 0, f"CPU: {cpu_pct:5.1f}%", cpu_color)
            self.stdscr.addstr(y, 15, f"Memory: {mem_pct:5.1f}%", mem_color)
            self.stdscr.addstr(y, 32, f"Disk: {disk_pct:5.1f}%", disk_color)
            
            # Suspicious processes
            susp_procs = len(self.system_metrics.get('suspicious_processes', []))
            if susp_procs > 0:
                self.stdscr.addstr(y, 48, f"Suspicious processes: {susp_procs}", curses.color_pair(3))
            
        y += 2
        
        # Service status section
        self.stdscr.addstr(y, 0, "SECURITY SERVICES", curses.color_pair(4) | curses.A_BOLD)
        y += 1
        
        services_per_row = 4
        service_names = list(self.service_status.keys())
        for i in range(0, len(service_names), services_per_row):
            row_services = service_names[i:i+services_per_row]
            x = 0
            for service in row_services:
                status_info = self.service_status[service]
                active = status_info.get('active', False)
                color = curses.color_pair(1) if active else curses.color_pair(3)
                symbol = "●" if active else "○"
                
                service_text = f"{symbol}{service}"
                try:
                    self.stdscr.addstr(y, x, service_text, color)
                except curses.error:
                    pass
                x += 18
            y += 1
        
        y += 1
        
        # Recent security alerts
        self.stdscr.addstr(y, 0, f"RECENT ALERTS ({len(self.security_alerts)})", curses.color_pair(4) | curses.A_BOLD)
        y += 1
        
        recent_alerts = self.security_alerts[-6:] if self.security_alerts else []
        for alert in reversed(recent_alerts):
            if y >= self.height - 2:
                break
                
            severity = alert.get('severity', 'INFO')
            message = alert.get('message', '')
            timestamp = alert.get('timestamp', '')
            
            # Get short timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime("%H:%M:%S")
            except:
                time_str = "??:??:??"
            
            # Color based on severity
            if severity == 'CRITICAL':
                color = curses.color_pair(7) | curses.A_BOLD  # Red background
            elif severity in ['HIGH', 'ERROR']:
                color = curses.color_pair(3)
            elif severity in ['MEDIUM', 'WARNING']:
                color = curses.color_pair(2)
            else:
                color = curses.color_pair(5)
            
            # Truncate message
            max_msg_len = self.width - 20
            if len(message) > max_msg_len:
                message = message[:max_msg_len-3] + "..."
            
            try:
                self.stdscr.addstr(y, 0, f"{time_str} {severity[:4]:4} {message}", color)
            except curses.error:
                pass
            y += 1
        
        # Compliance summary
        if self.compliance_status:
            y += 1
            self.stdscr.addstr(y, 0, "COMPLIANCE STATUS", curses.color_pair(4) | curses.A_BOLD)
            y += 1
            
            compliant = sum(1 for status in self.compliance_status.values() if status['status'] == 'COMPLIANT')
            total = len(self.compliance_status)
            non_compliant = total - compliant
            
            comp_color = curses.color_pair(1) if non_compliant == 0 else curses.color_pair(3)
            self.stdscr.addstr(y, 0, f"Compliant: {compliant}/{total}", comp_color)
            
            if non_compliant > 0:
                self.stdscr.addstr(y, 20, f"Issues: {non_compliant}", curses.color_pair(3))
    
    def _draw_system_details(self):
        """Draw detailed system information"""
        y = 2
        
        if not self.system_metrics:
            self.stdscr.addstr(y, 0, "No system data available", curses.color_pair(5))
            return
        
        # Detailed system metrics
        self.stdscr.addstr(y, 0, "DETAILED SYSTEM METRICS", curses.color_pair(4) | curses.A_BOLD)
        y += 2
        
        metrics = self.system_metrics
        
        # Resource usage with bars
        cpu_pct = metrics.get('cpu_percent', 0)
        mem_pct = metrics.get('memory_percent', 0)
        disk_pct = metrics.get('disk_percent', 0)
        
        self._draw_metric_with_bar(y, 0, "CPU Usage", cpu_pct, "%", 70, 90)
        y += 1
        self._draw_metric_with_bar(y, 0, "Memory Usage", mem_pct, "%", 80, 90)
        y += 1
        self._draw_metric_with_bar(y, 0, "Disk Usage", disk_pct, "%", 85, 95)
        y += 2
        
        # Load average
        load_avg = metrics.get('load_avg', [0, 0, 0])
        self.stdscr.addstr(y, 0, f"Load Average: {load_avg[0]:.2f} {load_avg[1]:.2f} {load_avg[2]:.2f}", curses.color_pair(5))
        y += 1
        
        # Process and connection counts
        proc_count = metrics.get('process_count', 0)
        conn_count = metrics.get('network_connections', 0)
        ext_conn = metrics.get('external_connections', 0)
        
        self.stdscr.addstr(y, 0, f"Processes: {proc_count}", curses.color_pair(5))
        self.stdscr.addstr(y, 20, f"Network Connections: {conn_count} (External: {ext_conn})", curses.color_pair(5))
        y += 2
        
        # Suspicious processes
        susp_procs = metrics.get('suspicious_processes', [])
        if susp_procs:
            self.stdscr.addstr(y, 0, f"SUSPICIOUS PROCESSES ({len(susp_procs)})", curses.color_pair(3) | curses.A_BOLD)
            y += 1
            
            for proc in susp_procs[:5]:  # Show first 5
                if y >= self.height - 2:
                    break
                proc_info = f"PID {proc['pid']}: {proc['name']} {proc.get('cmdline', '')[:40]}"
                try:
                    self.stdscr.addstr(y, 2, proc_info[:self.width-4], curses.color_pair(2))
                except curses.error:
                    pass
                y += 1
    
    def _draw_security_events(self):
        """Draw security events log"""
        y = 2
        
        self.stdscr.addstr(y, 0, f"SECURITY EVENTS ({len(self.security_events)})", curses.color_pair(4) | curses.A_BOLD)
        y += 2
        
        # Show recent events
        recent_events = self.security_events[-15:] if self.security_events else []
        
        for event in reversed(recent_events):
            if y >= self.height - 2:
                break
            
            event_type = event.get('type', 'UNKNOWN')
            message = event.get('message', '')
            timestamp = event.get('timestamp', '')
            severity = event.get('severity', 'INFO')
            
            # Get short timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime("%H:%M:%S")
            except:
                time_str = "??:??:??"
            
            # Color based on severity
            if severity == 'CRITICAL':
                color = curses.color_pair(3) | curses.A_BOLD
            elif severity == 'HIGH':
                color = curses.color_pair(3)
            elif severity == 'MEDIUM':
                color = curses.color_pair(2)
            else:
                color = curses.color_pair(5)
            
            # Format and truncate
            max_msg_len = self.width - 25
            if len(message) > max_msg_len:
                message = message[:max_msg_len-3] + "..."
            
            event_line = f"{time_str} {event_type[:12]:12} {message}"
            
            try:
                self.stdscr.addstr(y, 0, event_line, color)
            except curses.error:
                pass
            y += 1
    
    def _draw_compliance_status(self):
        """Draw security compliance status"""
        y = 2
        
        self.stdscr.addstr(y, 0, "SECURITY COMPLIANCE CHECKS", curses.color_pair(4) | curses.A_BOLD)
        y += 2
        
        if not self.compliance_status:
            self.stdscr.addstr(y, 0, "No compliance data available", curses.color_pair(5))
            return
        
        for check_name, status_info in self.compliance_status.items():
            if y >= self.height - 2:
                break
            
            status = status_info.get('status', 'UNKNOWN')
            message = status_info.get('message', '')
            risk_level = status_info.get('risk_level', 'LOW')
            
            # Status symbol and color
            if status == 'COMPLIANT':
                symbol = "✓"
                color = curses.color_pair(1)
            elif status == 'NON_COMPLIANT':
                symbol = "✗"
                color = curses.color_pair(3) if risk_level in ['HIGH', 'CRITICAL'] else curses.color_pair(2)
            else:  # ERROR
                symbol = "?"
                color = curses.color_pair(2)
            
            # Format check name
            display_name = check_name.replace('_', ' ').title()
            
            try:
                self.stdscr.addstr(y, 0, f"{symbol} {display_name:20} {message[:50]}", color)
            except curses.error:
                pass
            y += 1
    
    def _draw_metric_with_bar(self, y: int, x: int, label: str, value: float, unit: str, warn_thresh: float, crit_thresh: float):
        """Draw a metric with a progress bar"""
        color = self._get_status_color(value, warn_thresh, crit_thresh)
        
        # Label and value
        text = f"{label:15} {value:6.1f}{unit}"
        self.stdscr.addstr(y, x, text, color)
        
        # Progress bar
        bar_width = 20
        bar_x = x + 25
        filled_width = int(bar_width * min(value / 100.0, 1.0))
        
        try:
            bar = "█" * filled_width + "░" * (bar_width - filled_width)
            self.stdscr.addstr(y, bar_x, bar, color)
        except curses.error:
            pass
    
    def _get_status_color(self, value: float, warning_threshold: float, critical_threshold: float):
        """Get color based on value and thresholds"""
        if value >= critical_threshold:
            return curses.color_pair(3)  # Red
        elif value >= warning_threshold:
            return curses.color_pair(2)  # Yellow
        else:
            return curses.color_pair(1)  # Green
    
    def handle_input(self):
        """Handle keyboard input"""
        self.stdscr.nodelay(True)
        
        try:
            key = self.stdscr.getch()
            if key != -1:
                if key == ord('q') or key == ord('Q'):
                    return False
                elif key == ord('1'):
                    self.view_mode = 'overview'
                elif key == ord('2'):
                    self.view_mode = 'system'
                elif key == ord('3'):
                    self.view_mode = 'events'
                elif key == ord('4'):
                    self.view_mode = 'compliance'
                elif key == ord('r') or key == ord('R'):
                    # Force refresh
                    pass
                elif key == ord('c') or key == ord('C'):
                    # Clear alerts and events
                    self.security_alerts.clear()
                    self.security_events.clear()
        except curses.error:
            pass
        
        return True
    
    def run(self):
        """Main monitoring loop"""
        self.start_monitoring()
        
        try:
            while self.running:
                self.draw_dashboard()
                
                if not self.handle_input():
                    break
                
                time.sleep(0.5)  # UI refresh rate
                
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False

def main():
    """Main function for standalone security monitoring"""
    def run_security_monitor(stdscr):
        monitor = SecurityMonitor(stdscr)
        monitor.run()
    
    curses.wrapper(run_security_monitor)

if __name__ == "__main__":
    main()