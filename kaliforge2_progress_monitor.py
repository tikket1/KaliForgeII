#!/usr/bin/env python3
"""
KaliForge II Progress Monitor
Real-time progress tracking for parallel GitHub downloads and system operations
"""

import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ProgressUpdate:
    """Individual progress update data"""
    download_id: str
    status: str
    progress: str
    message: str
    timestamp: str

@dataclass
class ProgressSummary:
    """Overall progress summary"""
    total: int
    completed: int
    failed: int
    in_progress: int
    
    @property
    def completion_percentage(self) -> float:
        return (self.completed / self.total * 100) if self.total > 0 else 0.0

class KaliForgeProgressMonitor:
    """
    Real-time progress monitoring for KaliForge II operations
    """
    
    def __init__(self, progress_file: str = "/tmp/kaliforge2_download_progress.json"):
        self.progress_file = Path(progress_file)
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.update_callbacks: list[Callable[[Dict[str, Any]], None]] = []
        self.last_update_time = 0
        
    def add_update_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add a callback function to be called on progress updates"""
        self.update_callbacks.append(callback)
        
    def remove_update_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Remove a callback function"""
        if callback in self.update_callbacks:
            self.update_callbacks.remove(callback)
    
    def get_current_progress(self) -> Dict[str, Any]:
        """Get the current progress data"""
        try:
            if not self.progress_file.exists():
                return {
                    "downloads": {},
                    "summary": {"total": 0, "completed": 0, "failed": 0, "in_progress": 0},
                    "error": "Progress file not found"
                }
            
            with open(self.progress_file, 'r') as f:
                data = json.load(f)
                
            # Add calculated fields
            if 'summary' in data:
                data['summary']['completion_percentage'] = (
                    data['summary']['completed'] / data['summary']['total'] * 100
                    if data['summary']['total'] > 0 else 0.0
                )
                
            return data
            
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            return {
                "downloads": {},
                "summary": {"total": 0, "completed": 0, "failed": 0, "in_progress": 0},
                "error": f"Failed to read progress: {str(e)}"
            }
    
    def get_progress_summary(self) -> ProgressSummary:
        """Get a structured progress summary"""
        data = self.get_current_progress()
        summary_data = data.get('summary', {})
        
        return ProgressSummary(
            total=summary_data.get('total', 0),
            completed=summary_data.get('completed', 0),
            failed=summary_data.get('failed', 0),
            in_progress=summary_data.get('in_progress', 0)
        )
    
    def get_active_downloads(self) -> Dict[str, ProgressUpdate]:
        """Get currently active downloads"""
        data = self.get_current_progress()
        downloads = data.get('downloads', {})
        
        active = {}
        for download_id, info in downloads.items():
            if info.get('status') in ['starting', 'downloading']:
                active[download_id] = ProgressUpdate(
                    download_id=download_id,
                    status=info.get('status', 'unknown'),
                    progress=info.get('progress', '0'),
                    message=info.get('message', ''),
                    timestamp=info.get('timestamp', '')
                )
        
        return active
    
    def get_completed_downloads(self) -> Dict[str, ProgressUpdate]:
        """Get completed downloads"""
        data = self.get_current_progress()
        downloads = data.get('downloads', {})
        
        completed = {}
        for download_id, info in downloads.items():
            if info.get('status') == 'completed':
                completed[download_id] = ProgressUpdate(
                    download_id=download_id,
                    status=info.get('status', 'unknown'),
                    progress=info.get('progress', '100'),
                    message=info.get('message', ''),
                    timestamp=info.get('timestamp', '')
                )
        
        return completed
    
    def get_failed_downloads(self) -> Dict[str, ProgressUpdate]:
        """Get failed downloads"""
        data = self.get_current_progress()
        downloads = data.get('downloads', {})
        
        failed = {}
        for download_id, info in downloads.items():
            if info.get('status') == 'failed':
                failed[download_id] = ProgressUpdate(
                    download_id=download_id,
                    status=info.get('status', 'unknown'),
                    progress=info.get('progress', '0'),
                    message=info.get('message', ''),
                    timestamp=info.get('timestamp', '')
                )
        
        return failed
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.monitoring:
            try:
                if self.progress_file.exists():
                    # Check if file was modified
                    current_mtime = self.progress_file.stat().st_mtime
                    if current_mtime > self.last_update_time:
                        self.last_update_time = current_mtime
                        
                        # Get current progress and notify callbacks
                        progress_data = self.get_current_progress()
                        for callback in self.update_callbacks:
                            try:
                                callback(progress_data)
                            except Exception as e:
                                # Don't let callback errors crash the monitor
                                print(f"Progress callback error: {e}")
                
                time.sleep(0.5)  # Check twice per second
                
            except Exception as e:
                print(f"Progress monitor error: {e}")
                time.sleep(1)
    
    def start_monitoring(self):
        """Start real-time progress monitoring"""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop real-time progress monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
            self.monitor_thread = None
    
    def wait_for_completion(self, timeout: Optional[int] = None) -> bool:
        """
        Wait for all downloads to complete
        Returns True if all completed successfully, False if timeout or failures
        """
        start_time = time.time()
        
        while True:
            summary = self.get_progress_summary()
            
            # Check if all downloads are done (completed or failed)
            if summary.total > 0 and summary.in_progress == 0:
                return summary.failed == 0  # True if no failures
            
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                return False
                
            time.sleep(1)
    
    def print_progress_report(self):
        """Print a detailed progress report to console"""
        data = self.get_current_progress()
        
        print("\n" + "="*60)
        print("📊 KaliForge II Download Progress Report")
        print("="*60)
        
        if 'error' in data:
            print(f"❌ Error: {data['error']}")
            return
        
        summary = data.get('summary', {})
        total = summary.get('total', 0)
        completed = summary.get('completed', 0)
        failed = summary.get('failed', 0)
        in_progress = summary.get('in_progress', 0)
        completion_pct = summary.get('completion_percentage', 0.0)
        
        print(f"📈 Overall Progress: {completed}/{total} ({completion_pct:.1f}%)")
        print(f"✅ Completed: {completed}")
        print(f"⏳ In Progress: {in_progress}")
        print(f"❌ Failed: {failed}")
        
        # Show active downloads
        active = self.get_active_downloads()
        if active:
            print(f"\n🔄 Active Downloads ({len(active)}):")
            for download_id, update in active.items():
                progress_bar = self._create_progress_bar(update.progress)
                print(f"  • {download_id}: {progress_bar} {update.message}")
        
        # Show recent completions (last 3)
        completed_downloads = self.get_completed_downloads()
        if completed_downloads:
            recent_completed = list(completed_downloads.items())[-3:]
            print(f"\n✅ Recently Completed ({len(recent_completed)}):")
            for download_id, update in recent_completed:
                print(f"  • {download_id}: {update.message}")
        
        # Show failures if any
        failed_downloads = self.get_failed_downloads()
        if failed_downloads:
            print(f"\n❌ Failed Downloads ({len(failed_downloads)}):")
            for download_id, update in failed_downloads.items():
                print(f"  • {download_id}: {update.message}")
        
        print("="*60)
    
    def _create_progress_bar(self, progress: str, width: int = 20) -> str:
        """Create a visual progress bar"""
        try:
            pct = float(progress)
            filled = int(pct / 100 * width)
            bar = "█" * filled + "░" * (width - filled)
            return f"[{bar}] {pct:>5.1f}%"
        except (ValueError, TypeError):
            return f"[{'░' * width}] {progress}"

# Convenience functions for external scripts
def get_progress_monitor(progress_file: str = "/tmp/kaliforge2_download_progress.json") -> KaliForgeProgressMonitor:
    """Get a progress monitor instance"""
    return KaliForgeProgressMonitor(progress_file)

def print_progress_summary():
    """Quick function to print current progress summary"""
    monitor = get_progress_monitor()
    monitor.print_progress_report()

# CLI interface
if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="KaliForge II Progress Monitor")
    parser.add_argument("--file", "-f", default="/tmp/kaliforge2_download_progress.json",
                       help="Progress file to monitor")
    parser.add_argument("--watch", "-w", action="store_true",
                       help="Watch progress in real-time")
    parser.add_argument("--report", "-r", action="store_true",
                       help="Show detailed progress report")
    parser.add_argument("--wait", "-W", type=int, metavar="TIMEOUT",
                       help="Wait for completion with optional timeout")
    parser.add_argument("--json", "-j", action="store_true",
                       help="Output raw JSON data")
    
    args = parser.parse_args()
    
    monitor = KaliForgeProgressMonitor(args.file)
    
    if args.json:
        print(json.dumps(monitor.get_current_progress(), indent=2))
    elif args.report:
        monitor.print_progress_report()
    elif args.watch:
        print("👀 Watching progress (Ctrl+C to exit)...")
        
        def print_update(data):
            sys.stdout.write("\033[2J\033[H")  # Clear screen and go to top
            summary = data.get('summary', {})
            total = summary.get('total', 0)
            completed = summary.get('completed', 0)
            in_progress = summary.get('in_progress', 0)
            pct = summary.get('completion_percentage', 0.0)
            
            print(f"📊 Downloads: {completed}/{total} ({pct:.1f}%) - Active: {in_progress}")
            
            # Show active downloads
            downloads = data.get('downloads', {})
            for download_id, info in downloads.items():
                if info.get('status') in ['starting', 'downloading']:
                    progress = info.get('progress', '0')
                    message = info.get('message', '')
                    progress_bar = monitor._create_progress_bar(progress, 30)
                    print(f"  {download_id}: {progress_bar}")
                    print(f"    {message}")
        
        monitor.add_update_callback(print_update)
        monitor.start_monitoring()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping progress monitor...")
            monitor.stop_monitoring()
    elif args.wait is not None:
        print(f"⏳ Waiting for downloads to complete (timeout: {args.wait}s)...")
        success = monitor.wait_for_completion(args.wait)
        if success:
            print("✅ All downloads completed successfully!")
            sys.exit(0)
        else:
            print("❌ Timeout or failures occurred")
            sys.exit(1)
    else:
        # Default: show current summary
        print_progress_summary()