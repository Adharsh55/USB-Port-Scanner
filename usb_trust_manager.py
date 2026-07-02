import os
import sys
import argparse
import random
import cmd
import time
from database import DatabaseManager
from notifier import Notifier, load_config, save_config
from watcher import USBWatcher, is_wsl, is_windows

# Enable ANSI colors on Windows if possible
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        # ENABLE_PROCESSED_OUTPUT = 0x0001
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# Terminal Colors
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"

BANNERS = [
    f"""
{C_RED}    _   _ ____  ____    _____                    _
   | | | / ___|| __ )  |_   _| __ _   _ ___  ___| |_
   | | | \\___ \\|  _ \\    | || '__| | | / __|/ _ \\ __|
   | |_| |___) | |_) |   | || |  | |_| \\__ \\  __/ |_
    \\___/|____/|____/    |_||_|   \\__,_|___/\\___|\\__|{C_RESET}
              {C_CYAN}USB Device Trust Manager (Windows/WSL){C_RESET}
    """,
    f"""
{C_GREEN}        _.._
      .' .-'`
     /  /      {C_BOLD}USB-TRUST{C_RESET}{C_GREEN}
     |  |     _.._
     \\  \\   .' .-'`
      `._`./  /
         `|  |
          \\  \\
           `._`{C_RESET}     {C_MAGENTA}Interactive Security Interface{C_RESET}
    """,
    f"""
{C_YELLOW}        .---.
       /     \\
       \\__   /        ___ ___ ___
         /  /        / __/ __/ __|
        /  /        | (_ \\__ \\__ \\
       /  /          \\___|___/___/
      /  /_____
     /_________\\{C_RESET}  {C_BLUE}USB Forensic Defense Engine{C_RESET}
    """
]

def format_table(headers, rows):
    """Formats and returns a text table with columns aligned."""
    if not rows:
        return "No records found."
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))
            
    header_str = " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * widths[i] for i in range(len(headers)))
    
    output = [header_str, separator]
    for row in rows:
        row_str = " | ".join(str(val).ljust(widths[i]) for i, val in enumerate(row))
        output.append(row_str)
    return "\n".join(output)

class TrustShell(cmd.Cmd):
    intro = ""
    prompt = f"{C_BOLD}usb-trust > {C_RESET}"

    def __init__(self, db_manager: DatabaseManager, notifier: Notifier, watcher: USBWatcher):
        super().__init__()
        self.db = db_manager
        self.notifier = notifier
        self.watcher = watcher
        self.session_devices = []  # Keeps track of query-listed devices for short-index matching

    def preloop(self):
        """Displays banner and statistics prior to launching CLI."""
        self.print_banner()

    def print_banner(self):
        banner = random.choice(BANNERS)
        print(banner)
        
        # Calculate stats
        trusted_cnt = len([d for d in self.db.list_trusted_devices() if d["status"] == "trusted"])
        blocked_cnt = len([d for d in self.db.list_trusted_devices() if d["status"] == "blocked"])
        events_cnt = len(self.db.get_event_logs(1000))
        
        config = load_config()
        blocking_str = f"{C_GREEN}enabled{C_RESET}" if config.get("enable_blocking") else f"{C_YELLOW}disabled (alert-only){C_RESET}"
        monitoring_str = f"{C_GREEN}active{C_RESET}" if self.watcher.running else f"{C_RED}stopped{C_RESET}"
        
        # Display engine stats
        print(f"       =[ {C_BOLD}usb-trust v1.0.0{C_RESET}                               ]")
        print(f"   +-- --=[ {C_CYAN}{trusted_cnt}{C_RESET} trusted devices | {C_RED}{blocked_cnt}{C_RESET} explicitly blocked        ]")
        print(f"   +-- --=[ {C_CYAN}{events_cnt}{C_RESET} events logged in database                   ]")
        print(f"   +-- --=[ Engine: {monitoring_str} | Blocking: {blocking_str}     ]")
        print()

    def update_prompt(self):
        status = "active" if self.watcher.running else "stopped"
        color = C_GREEN if self.watcher.running else C_RED
        self.prompt = f"{C_BOLD}usb-trust({color}{status}{C_RESET}{C_BOLD}) > {C_RESET}"

    # --- CLI Commands ---

    def do_banner(self, arg):
        """Prints a random splash banner and statistics."""
        self.print_banner()

    def do_status(self, arg):
        """Displays system status, configuration settings, and database info."""
        config = load_config()
        print(f"{C_BOLD}--- System Status ---{C_RESET}")
        print(f"Host Environment   : {'WSL (Linux Windows Subsystem)' if is_wsl() else 'Native Windows' if is_windows() else 'Other Linux/Unix'}")
        print(f"Database Path      : {os.path.abspath(self.db.db_path)}")
        print(f"Watcher Engine     : {'RUNNING' if self.watcher.running else 'STOPPED'}")
        print(f"Blocking Mode      : {'ENABLED (will disable unauthorized USBs)' if config.get('enable_blocking') else 'DISABLED (alerts only)'}")
        print(f"Email Alerts       : {'ENABLED' if config.get('enable_email_alerts') else 'DISABLED'}")
        if config.get('enable_email_alerts'):
            print(f"  SMTP Server      : {config.get('smtp_server')}:{config.get('smtp_port')}")
            print(f"  SMTP User        : {config.get('smtp_user')}")
            print(f"  Recipient Email  : {config.get('recipient_email')}")
        print()

    def do_monitor(self, arg):
        """Starts or stops the background USB watcher engine.
Usage: monitor [start|stop]"""
        args = arg.strip().split()
        if not args:
            state = "running" if self.watcher.running else "stopped"
            print(f"Watcher engine is currently {C_BOLD}{state}{C_RESET}.")
            print("Usage: monitor [start|stop]")
            return

        action = args[0].lower()
        if action == "start":
            if self.watcher.running:
                print("Watcher engine is already running.")
            else:
                self.watcher.start()
                print(f"{C_GREEN}[*] Watcher engine started in the background.{C_RESET}")
        elif action == "stop":
            if not self.watcher.running:
                print("Watcher engine is already stopped.")
            else:
                self.watcher.stop()
                print(f"{C_YELLOW}[*] Watcher engine stopped.{C_RESET}")
        else:
            print("Invalid argument. Use: monitor start or monitor stop")
        self.update_prompt()

    def do_list(self, arg):
        """Lists devices.
Usage: list [trusted|connected|all]
Default list mode is 'connected'."""
        args = arg.strip().split()
        mode = args[0].lower() if args else "connected"

        if mode == "trusted":
            devices = self.db.list_trusted_devices()
            headers = ["#", "Fingerprint", "VID:PID", "Serial", "Name", "Status", "Trusted At"]
            rows = []
            self.session_devices = []
            for idx, dev in enumerate(devices, 1):
                self.session_devices.append(dev)
                rows.append([
                    idx,
                    dev["fingerprint"][:12] + "...",
                    f"{dev['vid']}:{dev['pid']}",
                    dev["serial"],
                    dev["name"],
                    dev["status"].upper(),
                    dev["created_at"]
                ])
            print(f"\n{C_BOLD}--- Trusted Devices Database ---{C_RESET}")
            print(format_table(headers, rows))
            print()

        elif mode == "connected":
            print(f"[*] Querying connected devices on host (please wait)...")
            connected = self.watcher.get_connected_usb_devices()
            headers = ["#", "Class", "Friendly Name", "VID:PID", "Serial", "Trust Status"]
            rows = []
            self.session_devices = []
            
            for idx, dev in enumerate(connected, 1):
                iid = dev.get("InstanceId", "")
                parsed = self.watcher.parse_instance_id(iid)
                if parsed:
                    vid, pid, serial = parsed
                    fingerprint = self.db.generate_fingerprint(vid, pid, serial)
                    db_dev = self.db.get_trusted_device(fingerprint)
                    
                    status = "UNKNOWN"
                    color = C_YELLOW
                    if db_dev:
                        if db_dev["status"] == "trusted":
                            status = "TRUSTED"
                            color = C_GREEN
                        elif db_dev["status"] == "blocked":
                            status = "BLOCKED"
                            color = C_RED
                    
                    # Store in session memory for easy cmd actions
                    session_entry = {
                        "vid": vid,
                        "pid": pid,
                        "serial": serial,
                        "instance_id": iid,
                        "fingerprint": fingerprint,
                        "name": dev.get("FriendlyName")
                    }
                    self.session_devices.append(session_entry)
                    
                    rows.append([
                        idx,
                        dev.get("Class", "USB"),
                        dev.get("FriendlyName", "Unknown"),
                        f"{vid}:{pid}",
                        serial,
                        f"{color}{status}{C_RESET}"
                    ])
            print(f"\n{C_BOLD}--- Currently Connected USB Devices ---{C_RESET}")
            print(format_table(headers, rows))
            print(f"{C_BLUE}Note: You can trust or block these devices using their '#' index (e.g., 'trust 1'){C_RESET}\n")

        elif mode == "all":
            # Lists both trusted in database and currently connected
            self.do_list("trusted")
            self.do_list("connected")
        else:
            print("Invalid list mode. Use: list trusted, list connected, or list all")

    def _resolve_device_arg(self, arg):
        """Helper to resolve a user argument into a (vid, pid, serial, instance_id, fingerprint) tuple.
        Supports session index lookup or full fingerprint/serial lookup."""
        if not arg:
            return None
        
        # Try checking if it's an integer index in session memory
        try:
            idx = int(arg) - 1
            if 0 <= idx < len(self.session_devices):
                dev = self.session_devices[idx]
                return (
                    dev.get("vid"),
                    dev.get("pid"),
                    dev.get("serial"),
                    dev.get("instance_id"),
                    dev.get("fingerprint"),
                    dev.get("name", "USB Device")
                )
            else:
                print(f"{C_RED}[-] Index out of range. Check 'list connected' or 'list trusted' for indices.{C_RESET}")
                return None
        except ValueError:
            # Not an index, treat as a fingerprint or serial
            target = arg.strip()
            
            # Check if it matches a trusted device fingerprint or serial in DB
            all_db = self.db.list_trusted_devices()
            for dev in all_db:
                if dev["fingerprint"] == target or dev["serial"].upper() == target.upper() or dev["fingerprint"].startswith(target):
                    # We don't have the active instance_id from DB, but we can reconstruct or search connected
                    # Let's search connected for instance_id
                    iid = ""
                    for conn in self.watcher.get_connected_usb_devices():
                        c_iid = conn.get("InstanceId", "")
                        c_parsed = self.watcher.parse_instance_id(c_iid)
                        if c_parsed:
                            c_vid, c_pid, c_serial = c_parsed
                            c_fp = self.db.generate_fingerprint(c_vid, c_pid, c_serial)
                            if c_fp == dev["fingerprint"]:
                                iid = c_iid
                                break
                    return (dev["vid"], dev["pid"], dev["serial"], iid, dev["fingerprint"], dev["name"])
            
            # Check if it matches a connected device serial
            for dev in self.session_devices:
                if dev["serial"].upper() == target.upper() or dev["fingerprint"] == target:
                    return (dev["vid"], dev["pid"], dev["serial"], dev["instance_id"], dev["fingerprint"], dev["name"])

            print(f"{C_RED}[-] Device not found with index, fingerprint or serial: '{target}'{C_RESET}")
            return None

    def do_trust(self, arg):
        """Trusts a USB device. If currently blocked, it will attempt to unblock it.
Usage: trust <index_or_fingerprint_or_serial> [custom name]"""
        args = arg.strip().split(maxsplit=1)
        if not args:
            print("Usage: trust <index_or_fingerprint_or_serial> [custom name]")
            return

        device_info = self._resolve_device_arg(args[0])
        if not device_info:
            return

        vid, pid, serial, instance_id, fingerprint, default_name = device_info
        custom_name = args[1] if len(args) > 1 else default_name

        # Save as trusted in DB
        self.db.add_trusted_device(vid, pid, serial, custom_name)
        print(f"{C_GREEN}[+] Device Trusted: {custom_name} (VID: {vid}, PID: {pid}){C_RESET}")
        print(f"    Fingerprint: {fingerprint}")
        
        # If the device is connected, attempt to unblock/enable it
        if instance_id:
            print(f"[*] Re-enabling device on host system...")
            success, msg = self.watcher.unblock_device(instance_id)
            if success:
                print(f"{C_GREEN}[+] Device enabled successfully.{C_RESET}")
                self.db.log_event("unblock", vid, pid, serial, "trusted", "allowed")
            else:
                print(f"{C_YELLOW}[!] Note: {msg}{C_RESET}")

    def do_untrust(self, arg):
        """Removes a USB device from the trusted database.
Usage: untrust <index_or_fingerprint_or_serial>"""
        if not arg:
            print("Usage: untrust <index_or_fingerprint_or_serial>")
            return

        device_info = self._resolve_device_arg(arg.strip())
        if not device_info:
            return

        vid, pid, serial, instance_id, fingerprint, name = device_info
        
        self.db.remove_device(fingerprint)
        print(f"{C_YELLOW}[*] Device removed from trusted database: {name}{C_RESET}")
        print(f"    Fingerprint: {fingerprint}")
        
        # If blocking is active and device is connected, disable it
        config = load_config()
        if instance_id and config.get("enable_blocking"):
            print(f"[*] Blocking device on host system as it is no longer trusted...")
            success, msg = self.watcher.block_device(instance_id)
            if success:
                print(f"{C_RED}[+] Device disabled successfully.{C_RESET}")
                self.db.log_event("block", vid, pid, serial, "unknown", "blocked")
            else:
                print(f"{C_YELLOW}[!] Note: {msg}{C_RESET}")

    def do_block(self, arg):
        """Manually blocks/disables a USB device and marks it as explicitly blocked in the DB.
Usage: block <index_or_fingerprint_or_serial>"""
        if not arg:
            print("Usage: block <index_or_fingerprint_or_serial>")
            return

        device_info = self._resolve_device_arg(arg.strip())
        if not device_info:
            return

        vid, pid, serial, instance_id, fingerprint, name = device_info
        
        # Add or update in DB with blocked status
        self.db.add_trusted_device(vid, pid, serial, name)
        self.db.update_device_status(fingerprint, "blocked")
        print(f"{C_RED}[+] Device marked as EXPLICITLY BLOCKED in database: {name}{C_RESET}")
        
        if instance_id:
            print(f"[*] Disabling device on host system...")
            success, msg = self.watcher.block_device(instance_id)
            if success:
                print(f"{C_RED}[+] Device disabled successfully.{C_RESET}")
                self.db.log_event("block", vid, pid, serial, "blocked", "blocked")
            else:
                print(f"{C_YELLOW}[!] Note: {msg}{C_RESET}")
        else:
            print(f"[*] Note: Device is not currently connected. It will be blocked automatically upon insertion.")

    def do_unblock(self, arg):
        """Unblocks a USB device, setting its status back to trusted and enabling it.
Usage: unblock <index_or_fingerprint_or_serial>"""
        # Equivalent to trust
        self.do_trust(arg)

    def do_logs(self, arg):
        """Displays recent USB insertion/removal event logs.
Usage: logs [limit] (default: 20)"""
        limit = 20
        if arg:
            try:
                limit = int(arg)
            except ValueError:
                print("Invalid limit parameter. Using default of 20.")

        logs = self.db.get_event_logs(limit)
        headers = ["ID", "Timestamp", "Event", "VID:PID", "Serial", "Status At Time", "Action Taken"]
        rows = []
        for log in logs:
            event_color = C_GREEN if log["event_type"] == "insert" else C_YELLOW
            action_color = C_RED if "block" in log["action_taken"] else (C_GREEN if log["action_taken"] == "allowed" else C_YELLOW)
            rows.append([
                log["id"],
                log["timestamp"],
                f"{event_color}{log['event_type'].upper()}{C_RESET}",
                f"{log['vid']}:{log['pid']}",
                log["serial"],
                log["status_at_time"].upper(),
                f"{action_color}{log['action_taken'].upper()}{C_RESET}"
            ])
        
        print(f"\n{C_BOLD}--- Device Event History Logs ---{C_RESET}")
        print(format_table(headers, rows))
        print()

    def do_config(self, arg):
        """Views or updates application configurations (Blocking, SMTP, Alerts).
Usage:
  config show                   - Displays current configuration options
  config set <key> <value>      - Sets a configuration key
  config wizard                 - Launch interactive email configuration helper
  config test-email             - Sends a verification email to test SMTP settings
"""
        args = arg.strip().split()
        if not args:
            print("Usage: config [show|set|wizard|test-email]")
            return

        subcmd = args[0].lower()
        config = load_config()

        if subcmd == "show":
            print(f"\n{C_BOLD}--- Settings & Configuration ---{C_RESET}")
            for k, v in config.items():
                val_str = f"{C_GREEN}{v}{C_RESET}" if v is True else f"{C_RED}{v}{C_RESET}" if v is False else str(v)
                print(f"  {k.ljust(22)}: {val_str}")
            print()

        elif subcmd == "set":
            if len(args) < 3:
                print("Usage: config set <key> <value>")
                return
            key = args[1].lower()
            val_raw = args[2]

            if key not in config:
                print(f"{C_RED}[-] Unknown configuration key: {key}{C_RESET}")
                return

            # Type conversion
            if isinstance(config[key], bool):
                val = val_raw.lower() in ("true", "1", "yes", "on")
            elif isinstance(config[key], int):
                try:
                    val = int(val_raw)
                except ValueError:
                    print("Value must be an integer.")
                    return
            else:
                val = val_raw

            config[key] = val
            save_config(config)
            print(f"{C_GREEN}[*] Config updated: {key} => {val}{C_RESET}")

        elif subcmd == "wizard":
            print(f"\n{C_CYAN}--- SMTP Email Alert Setup Wizard ---{C_RESET}")
            print("Press Enter to keep current values listed in brackets.\n")
            
            smtp_server = input(f"SMTP Server [{config['smtp_server']}]: ").strip() or config['smtp_server']
            smtp_port_raw = input(f"SMTP Port [{config['smtp_port']}]: ").strip()
            smtp_port = int(smtp_port_raw) if smtp_port_raw else config['smtp_port']
            smtp_user = input(f"SMTP User (Sender Email) [{config['smtp_user']}]: ").strip() or config['smtp_user']
            smtp_password = input(f"SMTP App Password [{'*'*8 if config['smtp_password'] else ''}]: ").strip() or config['smtp_password']
            recipient_email = input(f"Recipient Email [{config['recipient_email']}]: ").strip() or config['recipient_email']
            
            enable_raw = input("Enable Email Alerts? (yes/no) [yes]: ").strip().lower()
            enable_email_alerts = enable_raw not in ("no", "n", "false", "0")

            config.update({
                "smtp_server": smtp_server,
                "smtp_port": smtp_port,
                "smtp_user": smtp_user,
                "smtp_password": smtp_password,
                "recipient_email": recipient_email,
                "enable_email_alerts": enable_email_alerts
            })
            save_config(config)
            print(f"\n{C_GREEN}[*] SMTP Settings successfully updated.{C_RESET}")
            
            test_now = input("Would you like to send a test email now? (yes/no) [yes]: ").strip().lower()
            if test_now not in ("no", "n", "false", "0"):
                self.do_config("test-email")

        elif subcmd == "test-email":
            print(f"[*] Sending test email to {config.get('recipient_email')}...")
            success, msg = self.notifier.send_test_email()
            if success:
                print(f"{C_GREEN}[+] {msg}{C_RESET}")
            else:
                print(f"{C_RED}[-]{msg}{C_RESET}")
        else:
            print("Unknown configuration subcommand. Use: show, set, wizard, or test-email")

    def do_exit(self, arg):
        """Stops the monitoring engine and exits the shell."""
        print("[*] Stopping USB watcher daemon...")
        self.watcher.stop()
        print("Goodbye!")
        return True

    def do_quit(self, arg):
        """Stops the monitoring engine and exits the shell."""
        return self.do_exit(arg)

    # --- Live Events Display Callback ---
    def handle_watcher_event(self, event_type, name, vid, pid, serial, fingerprint, status, action, block_msg):
        """Callback to print real-time USB notifications directly into the console."""
        # Clean current line (in case prompt is written) and display alert
        sys.stdout.write('\r\033[K') # Clear line
        if event_type == "insert":
            if "block" in action:
                print(f"\n{C_RED}{C_BOLD}[⚠️ ALERT] Unauthorized USB Device Blocked!{C_RESET}")
                print(f"  Device   : {name}")
                print(f"  VID:PID  : {vid}:{pid}")
                print(f"  Serial   : {serial}")
                print(f"  Details  : {C_RED}{action.upper()}{C_RESET} {block_msg}")
            else:
                print(f"\n{C_YELLOW}{C_BOLD}[🔔 ALERT] Unknown USB Device Inserted!{C_RESET}")
                print(f"  Device   : {name}")
                print(f"  VID:PID  : {vid}:{pid}")
                print(f"  Serial   : {serial}")
                print(f"  Details  : {C_YELLOW}{action.upper()}{C_RESET} {block_msg}")
        elif event_type == "remove":
            print(f"\n{C_BLUE}[ℹ️ INFO] USB Device Removed:{C_RESET} {name} (VID: {vid}, PID: {pid})")
            
        print()
        # Redraw prompt
        sys.stdout.write(self.prompt)
        sys.stdout.flush()


def run_daemon_mode(db_manager, notifier, watcher):
    """Runs the script as a background monitoring daemon that logs to stdout."""
    print(f"[*] Starting USB Trust Manager in daemon mode.")
    print(f"[*] Logs will write to database and stdout.")
    
    def log_callback(event_type, name, vid, pid, serial, fingerprint, status, action, block_msg):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        if event_type == "insert":
            print(f"[{timestamp}] INSERT | {name} | {vid}:{pid} | Serial: {serial} | Status: {status} | Action: {action} {block_msg}")
        elif event_type == "remove":
            print(f"[{timestamp}] REMOVE | {name} | {vid}:{pid} | Serial: {serial}")

    watcher.callback_event = log_callback
    watcher.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping daemon engine...")
        watcher.stop()
        print("[*] Daemon stopped.")


def main():
    parser = argparse.ArgumentParser(description="USB Device Trust Manager (Windows/WSL)")
    parser.add_argument("--daemon", action="store_true", help="Run in non-interactive daemon mode directly logging to stdout")
    parser.add_argument("--db", default="usb_trust.db", help="Path to SQLite database file")
    args = parser.parse_args()

    db_manager = DatabaseManager(args.db)
    notifier = Notifier()
    watcher = USBWatcher(db_manager, notifier)

    if args.daemon:
        run_daemon_mode(db_manager, notifier, watcher)
    else:
        # Standard interactive Metasploit-like shell mode
        shell = TrustShell(db_manager, notifier, watcher)
        # Register callback to show live events on CLI
        watcher.callback_event = shell.handle_watcher_event
        # Auto-start watcher in interactive shell
        watcher.start()
        shell.update_prompt()
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print("\n[*] Interrupt detected, exiting...")
            watcher.stop()


if __name__ == '__main__':
    main()
