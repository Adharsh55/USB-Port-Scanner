import sqlite3
import os
import hashlib
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path="usb_trust.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initializes the SQLite tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Trusted Devices Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusted_devices (
                    fingerprint TEXT PRIMARY KEY,
                    vid TEXT,
                    pid TEXT,
                    serial TEXT,
                    name TEXT,
                    status TEXT DEFAULT 'trusted',
                    created_at TEXT
                )
            """)
            
            # Event Logs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    vid TEXT,
                    pid TEXT,
                    serial TEXT,
                    fingerprint TEXT,
                    status_at_time TEXT,
                    action_taken TEXT
                )
            """)
            conn.commit()

    @staticmethod
    def generate_fingerprint(vid, pid, serial):
        """Generates a unique SHA-256 fingerprint for a device."""
        unique_string = f"{vid.strip().upper()}:{pid.strip().upper()}:{serial.strip().upper()}"
        return hashlib.sha256(unique_string.encode('utf-8')).hexdigest()

    def get_trusted_device(self, fingerprint):
        """Retrieves a trusted device by its fingerprint."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT fingerprint, vid, pid, serial, name, status, created_at FROM trusted_devices WHERE fingerprint = ?", (fingerprint,))
            row = cursor.fetchone()
            if row:
                return {
                    "fingerprint": row[0],
                    "vid": row[1],
                    "pid": row[2],
                    "serial": row[3],
                    "name": row[4],
                    "status": row[5],
                    "created_at": row[6]
                }
            return None

    def add_trusted_device(self, vid, pid, serial, name=""):
        """Adds a device to the trusted list or updates its status to trusted."""
        fingerprint = self.generate_fingerprint(vid, pid, serial)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO trusted_devices (fingerprint, vid, pid, serial, name, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'trusted', ?)
            """, (fingerprint, vid.upper(), pid.upper(), serial.upper(), name, created_at))
            conn.commit()
        return fingerprint

    def update_device_status(self, fingerprint, status):
        """Updates the status of a device (e.g. 'trusted', 'blocked')."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE trusted_devices SET status = ? WHERE fingerprint = ?", (status, fingerprint))
            conn.commit()

    def remove_device(self, fingerprint):
        """Removes a device from the trusted database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM trusted_devices WHERE fingerprint = ?", (fingerprint,))
            conn.commit()

    def list_trusted_devices(self):
        """Returns all trusted/blocked devices in the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT fingerprint, vid, pid, serial, name, status, created_at FROM trusted_devices")
            rows = cursor.fetchall()
            devices = []
            for r in rows:
                devices.append({
                    "fingerprint": r[0],
                    "vid": r[1],
                    "pid": r[2],
                    "serial": r[3],
                    "name": r[4],
                    "status": r[5],
                    "created_at": r[6]
                })
            return devices

    def log_event(self, event_type, vid, pid, serial, status_at_time, action_taken):
        """Logs a USB event (insertion, removal, block, etc.)."""
        fingerprint = self.generate_fingerprint(vid, pid, serial)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO event_logs (timestamp, event_type, vid, pid, serial, fingerprint, status_at_time, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, event_type, vid.upper(), pid.upper(), serial.upper(), fingerprint, status_at_time, action_taken))
            conn.commit()

    def get_event_logs(self, limit=50):
        """Retrieves recent event logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, event_type, vid, pid, serial, fingerprint, status_at_time, action_taken 
                FROM event_logs 
                ORDER BY id DESC 
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            logs = []
            for r in rows:
                logs.append({
                    "id": r[0],
                    "timestamp": r[1],
                    "event_type": r[2],
                    "vid": r[3],
                    "pid": r[4],
                    "serial": r[5],
                    "fingerprint": r[6],
                    "status_at_time": r[7],
                    "action_taken": r[8]
                })
            return logs
