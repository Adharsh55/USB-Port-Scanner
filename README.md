# USB Device Trust Manager ⭐⭐⭐⭐⭐

A command-line security utility designed for Windows that monitors, catalogs, and manages trust permissions for USB devices plugged into your system. Built to run natively in Windows terminals or from Windows Subsystem for Linux (WSL) as a standard command-line command. It provides a Metasploit-like interactive terminal console interface.

## 🚀 Key Features

*   **Real-time Insertion & Removal Detection**: Monitors the system bus for newly inserted USB devices.
*   **Device Fingerprinting**: Generates unique SHA-256 fingerprints based on Device Vendor ID (VID), Product ID (PID), and Serial Number/Instance Identifier.
*   **Trusted/Blocked SQLite Database**: Maintains a local trusted-devices registry.
*   **Active Hardware Blocking**: Automatically disables unauthorized USB devices immediately upon insertion (requires Administrator privileges).
*   **Event Logging**: Tracks historical log entries for insertion, removal, blocks, and authorisations.
*   **Email Security Alerts**: Sends SMTP email alerts (HTML formatted) to a security administrator when an unknown/untrusted USB device is inserted.
*   **Metasploit-like Interactive Shell**: A retro-style, interactive console interface with random terminal banners, colored outputs, command-line routing, and simple numeric index selection (e.g. `trust 1` or `block 1`).

---

## 🛠️ Requirements & Setup

1.  **Python 3.6+** must be installed on your Windows host or inside your WSL instance.
2.  **PowerShell** (available natively on Windows) is used to poll connected devices via WMI/CIM interfaces and enable/disable drivers.
3.  **Administrator Rights (Optional but Recommended)**:
    *   To utilize the **active blocking/disabling** feature, you *must* run the terminal (CMD, PowerShell, or WSL bash) as an **Administrator**.
    *   Without admin rights, the tool will function in **alert-only** mode (monitoring, logging, and emailing notifications without actively turning off the hardware).

### Quick Start (Interactive Console)
Run the script using python:
```bash
python usb_trust_manager.py
```

### Daemon Mode (Silent Logger)
To run the manager as a background log stream to stdout without the interactive shell:
```bash
python usb_trust_manager.py --daemon
```

---

## 💻 Running inside WSL

This tool is specifically designed to run seamlessly from a Linux terminal inside WSL. When launched in WSL, it automatically detects the environment and forwards commands directly to the host's Windows WMI engine by calling the `powershell.exe` executable inside Windows.

To make it callable from anywhere in your WSL command line, you can create a simple alias or shell script:

1. Add the following alias to your `~/.bashrc` or `~/.zshrc`:
   ```bash
   alias usb-trust="python3 /mnt/d/ssd\ port/usb_trust_manager.py"
   ```
2. Reload your shell: `source ~/.bashrc`.
3. Launch it using: `usb-trust`.

*Note: Make sure your WSL terminal is running within a Windows Terminal session launched as **Administrator** if you wish to enable driver blocking.*

---

## ⚙️ Interactive Commands Reference

Once the interactive shell starts (`usb-trust >`), the following commands are available:

| Command | Description |
| :--- | :--- |
| **`help`** / **`?`** | Lists all available console commands with quick descriptions. |
| **`status`** | Displays the current operating status (watcher active, db path, blocking mode, and SMTP config). |
| **`monitor [start\|stop]`** | Starts or stops the background USB polling watcher thread. |
| **`list [connected\|trusted\|all]`** | Lists devices. `connected` shows present devices with an index number. `trusted` displays database records. |
| **`trust <#\|fingerprint>`** | Authorizes a device by index or fingerprint, saving it to database. If currently blocked, it will re-enable the device. |
| **`untrust <#\|fingerprint>`** | Removes a device from the trusted database. If blocking is active, it disables the device. |
| **`block <#\|fingerprint>`** | Manually blocks a connected device and flags it as explicitly blocked in the database. |
| **`logs [limit]`** | Displays insertion and removal history logs. |
| **`config show`** | Prints all active settings from `config.json`. |
| **`config set <key> <val>`** | Modifies a specific setting (e.g. `config set enable_blocking True`). |
| **`config wizard`** | Launches an interactive setup utility for configuring email SMTP alert credentials. |
| **`config test-email`** | Sends a test email to the configured recipient to check SMTP connectivity. |
| **`banner`** | Displays a random Metasploit ascii banner and live statistics. |
| **`exit`** / **`quit`** | Stops background threads and exits the console cleanly. |

---

## 📧 Configuring Email Notifications (SMTP)

To configure email alerts on unknown device insertion:
1. Run the interactive setup:
   ```bash
   usb-trust > config wizard
   ```
2. Enter your SMTP details (e.g. Server: `smtp.gmail.com`, Port: `587`, SMTP User: `your-email@gmail.com`).
3. Use a secure App Password generated from your email account (like Gmail App Passwords) for authentication.
4. Save settings and send a verification test email.
