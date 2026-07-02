import os
import sys
import json
import re
import subprocess
import threading
import time
from database import DatabaseManager
from notifier import Notifier, load_config

def is_wsl():
    """Detects if running under Windows Subsystem for Linux (WSL)."""
    if sys.platform == "linux":
        try:
            with open("/proc/version", "r") as f:
                if "microsoft" in f.read().lower():
                    return True
        except Exception:
            pass
    return False

def is_windows():
    """Detects if running natively on Windows."""
    return sys.platform == "win32"

class USBWatcher:
    def __init__(self, db_manager: DatabaseManager, notifier: Notifier, callback_event=None):
        self.db = db_manager
        self.notifier = notifier
        self.callback_event = callback_event
        self.running = False
        self.thread = None
        self.connected_devices = {}  # Keep track of instance_id -> device_info

    def get_connected_usb_devices(self):
        """Retrieves a list of currently connected USB devices from the host OS."""
        if is_windows() or is_wsl():
            # Query Windows PnP devices
            powershell_cmd = "powershell.exe" if is_wsl() else "powershell"
            ps_script = (
                "Get-PnpDevice -PresentOnly | "
                "Where-Object { $_.InstanceId -like '*USB\\VID*' } | "
                "Select-Object Status, Class, FriendlyName, InstanceId | "
                "ConvertTo-Json"
            )
            try:
                # We use -NoProfile to speed up execution
                res = subprocess.run(
                    [powershell_cmd, "-NoProfile", "-Command", ps_script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=8
                )
                if res.returncode == 0:
                    stdout_clean = res.stdout.strip()
                    if not stdout_clean:
                        return []
                    data = json.loads(stdout_clean)
                    if isinstance(data, dict):
                        return [data]
                    elif isinstance(data, list):
                        return data
                return []
            except Exception as e:
                # If command fails (e.g. powershell.exe not found in WSL path), log or fallback
                return []
        elif sys.platform == "linux":
            # Native Linux fallback: Read from /sys/bus/usb/devices
            devices = []
            base_dir = "/sys/bus/usb/devices"
            if not os.path.exists(base_dir):
                return []
            for name in os.listdir(base_dir):
                path = os.path.join(base_dir, name)
                try:
                    vendor_path = os.path.join(path, "idVendor")
                    product_path = os.path.join(path, "idProduct")
                    if os.path.exists(vendor_path) and os.path.exists(product_path):
                        with open(vendor_path, "r") as f:
                            vid = f.read().strip()
                        with open(product_path, "r") as f:
                            pid = f.read().strip()
                        serial = ""
                        serial_path = os.path.join(path, "serial")
                        if os.path.exists(serial_path):
                            with open(serial_path, "r") as f:
                                serial = f.read().strip()
                        
                        friendly_name = "USB Device"
                        prod_name_path = os.path.join(path, "product")
                        if os.path.exists(prod_name_path):
                            with open(prod_name_path, "r") as f:
                                friendly_name = f.read().strip()
                        
                        # Normalize format to look like Windows Instance ID
                        # E.g. USB\VID_045E&PID_0023\123456
                        normalized_instance_id = f"USB\\VID_{vid.upper()}&PID_{pid.upper()}\\{serial if serial else name}"
                        devices.append({
                            "Status": "OK",
                            "Class": "USB",
                            "FriendlyName": friendly_name,
                            "InstanceId": normalized_instance_id
                        })
                except Exception:
                    continue
            return devices
        else:
            # Fallback for other OS / tests
            return []

    @staticmethod
    def parse_instance_id(instance_id):
        """Extracts VID, PID, and Serial/Instance details from the device InstanceId."""
        # Pattern: USB\VID_xxxx&PID_yyyy... followed by backslash and serial/instance id
        pattern = r"USB\\VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})(?:&[^\\]+)?\\([^\s]+)"
        match = re.match(pattern, instance_id)
        if match:
            return match.group(1).upper(), match.group(2).upper(), match.group(3).upper()
        return None

    def block_device(self, instance_id):
        """Attempts to disable the device on the Windows host."""
        if not (is_windows() or is_wsl()):
            return False, "Device blocking is only supported on Windows hosts."
        
        powershell_cmd = "powershell.exe" if is_wsl() else "powershell"
        # We need to escape single quotes in instance_id if any, and call Disable-PnpDevice
        ps_script = f"Disable-PnpDevice -InstanceId '{instance_id}' -Confirm:$false"
        try:
            # Run PowerShell command to disable the device.
            # Must run as Admin on Windows. If running as non-admin in WSL or CMD,
            # this command will fail with an authorization error. We catch and report this.
            res = subprocess.run(
                [powershell_cmd, "-NoProfile", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            if res.returncode == 0:
                return True, "Device successfully blocked/disabled."
            else:
                err_msg = res.stderr.strip()
                if "PermissionDenied" in err_msg or "Access is denied" in err_msg or "SecurityError" in err_msg:
                    return False, "Access Denied: Running as Administrator is required to block devices."
                return False, f"Failed to block device: {err_msg}"
        except Exception as e:
            return False, f"Error executing block command: {str(e)}"

    def unblock_device(self, instance_id):
        """Attempts to enable a previously disabled device on the Windows host."""
        if not (is_windows() or is_wsl()):
            return False, "Device enabling is only supported on Windows hosts."
        
        powershell_cmd = "powershell.exe" if is_wsl() else "powershell"
        ps_script = f"Enable-PnpDevice -InstanceId '{instance_id}' -Confirm:$false"
        try:
            res = subprocess.run(
                [powershell_cmd, "-NoProfile", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            if res.returncode == 0:
                return True, "Device successfully unblocked/enabled."
            else:
                err_msg = res.stderr.strip()
                if "PermissionDenied" in err_msg or "Access is denied" in err_msg or "SecurityError" in err_msg:
                    return False, "Access Denied: Running as Administrator is required to unblock devices."
                return False, f"Failed to unblock device: {err_msg}"
        except Exception as e:
            return False, f"Error executing unblock command: {str(e)}"

    def start(self):
        """Starts the background USB monitoring thread."""
        if self.running:
            return
        self.running = True
        
        # Populate initial connected devices without logging them as insertions
        initial_devices = self.get_connected_usb_devices()
        for dev in initial_devices:
            iid = dev.get("InstanceId")
            if iid:
                self.connected_devices[iid] = dev

        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the background USB monitoring thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _monitor_loop(self):
        """Main loop checking for USB insertions and removals."""
        while self.running:
            config = load_config()
            enable_blocking = config.get("enable_blocking", False)

            current_devices = self.get_connected_usb_devices()
            current_ids = set()
            
            # Map of current devices
            current_dev_map = {}
            for dev in current_devices:
                iid = dev.get("InstanceId")
                if iid:
                    current_ids.add(iid)
                    current_dev_map[iid] = dev

            # Detect insertions
            for iid in current_ids:
                if iid not in self.connected_devices:
                    # Device inserted!
                    dev = current_dev_map[iid]
                    parsed = self.parse_instance_id(iid)
                    
                    if parsed:
                        vid, pid, serial = parsed
                        fingerprint = self.db.generate_fingerprint(vid, pid, serial)
                        db_device = self.db.get_trusted_device(fingerprint)
                        
                        friendly_name = dev.get("FriendlyName", "Unknown Device")
                        device_class = dev.get("Class", "USB")

                        # Determine if device is trusted
                        is_trusted = False
                        is_explicit_blocked = False
                        if db_device:
                            if db_device["status"] == "trusted":
                                is_trusted = True
                            elif db_device["status"] == "blocked":
                                is_explicit_blocked = True

                        status_str = "trusted" if is_trusted else ("blocked" if is_explicit_blocked else "unknown")

                        action_taken = "allowed"
                        block_status_msg = ""
                        
                        # Block if untrusted and blocking is enabled OR if explicitly blocked in db
                        should_block = (not is_trusted and enable_blocking) or is_explicit_blocked
                        
                        if should_block:
                            # Attempt block
                            success, msg = self.block_device(iid)
                            if success:
                                action_taken = "blocked"
                                block_status_msg = " [Blocked successfully]"
                            else:
                                action_taken = "block_failed"
                                block_status_msg = f" [Block failed: {msg}]"
                        else:
                            # Standard notification / email alert if unknown and blocking disabled
                            if not is_trusted:
                                action_taken = "alerted"

                        # Log to DB
                        self.db.log_event("insert", vid, pid, serial, status_str, action_taken)

                        # Trigger callback
                        if self.callback_event:
                            self.callback_event(
                                event_type="insert",
                                name=friendly_name,
                                vid=vid,
                                pid=pid,
                                serial=serial,
                                fingerprint=fingerprint,
                                status=status_str,
                                action=action_taken,
                                block_msg=block_status_msg
                            )

                        # Send email alert if not trusted
                        if not is_trusted:
                            self._send_email_alert_async(friendly_name, vid, pid, serial, fingerprint, status_str, action_taken + block_status_msg)

                    self.connected_devices[iid] = dev

            # Detect removals
            removed_ids = []
            for iid in list(self.connected_devices.keys()):
                if iid not in current_ids:
                    # Device removed!
                    dev = self.connected_devices[iid]
                    parsed = self.parse_instance_id(iid)
                    if parsed:
                        vid, pid, serial = parsed
                        fingerprint = self.db.generate_fingerprint(vid, pid, serial)
                        friendly_name = dev.get("FriendlyName", "Unknown Device")
                        
                        # Log to DB
                        self.db.log_event("remove", vid, pid, serial, "unknown", "logged")

                        # Trigger callback
                        if self.callback_event:
                            self.callback_event(
                                event_type="remove",
                                name=friendly_name,
                                vid=vid,
                                pid=pid,
                                serial=serial,
                                fingerprint=fingerprint,
                                status="",
                                action="logged",
                                block_msg=""
                            )
                    removed_ids.append(iid)

            for iid in removed_ids:
                del self.connected_devices[iid]

            time.sleep(1.5)

    def _send_email_alert_async(self, name, vid, pid, serial, fingerprint, status, action):
        """Spawns a thread to send an email alert without blocking the watcher loop."""
        thread = threading.Thread(
            target=self._send_email_alert_sync,
            args=(name, vid, pid, serial, fingerprint, status, action),
            daemon=True
        )
        thread.start()

    def _send_email_alert_sync(self, name, vid, pid, serial, fingerprint, status, action):
        """Assembles HTML and sends the security email alert."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        subject = f"⚠️ SECURITY ALERT: Unauthorized USB Insertion Detected"
        
        # Determine styling depending on action taken
        action_color = "#dc3545" if "blocked" in action else "#ffc107"
        
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="background-color: #fff; border: 2px solid #dc3545; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto;">
                    <h2 style="color: #dc3545; margin-top: 0; border-bottom: 2px solid #dc3545; padding-bottom: 10px;">⚠️ USB Insertion Security Alert</h2>
                    <p style="font-size: 15px;">An <strong>unauthorized USB device</strong> has been inserted into the monitored workstation.</p>
                    
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr style="background-color: #f8f9fa;">
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold; width: 30%;">Device Name:</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6;">{name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Vendor ID (VID):</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6;">{vid}</td>
                        </tr>
                        <tr style="background-color: #f8f9fa;">
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Product ID (PID):</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6;">{pid}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Serial Number:</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6;">{serial}</td>
                        </tr>
                        <tr style="background-color: #f8f9fa;">
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Fingerprint:</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-family: monospace; font-size: 12px; word-break: break-all;">{fingerprint}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Workstation Time:</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6;">{timestamp}</td>
                        </tr>
                        <tr style="background-color: #f8f9fa;">
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Device Status:</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6; text-transform: uppercase; font-weight: bold; color: #6c757d;">{status}</td>
                        </tr>
                        <tr style="background-color: #fff;">
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">Action Taken:</td>
                            <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold; color: {action_color};">{action}</td>
                        </tr>
                    </table>

                    <p style="font-size: 14px;">If this device is trusted, log into the USB Trust Manager console and execute the following command to trust it: <br>
                    <code style="background-color: #f1f3f5; padding: 4px 6px; border-radius: 4px; font-family: monospace;">trust {fingerprint}</code></p>
                    
                    <hr style="border: 0; border-top: 1px solid #dee2e6; margin: 20px 0;">
                    <p style="font-size: 11px; color: #777; text-align: center;">USB Trust Manager Daemon System Alert</p>
                </div>
            </body>
        </html>
        """
        self.notifier.send_email_alert(subject, html)
