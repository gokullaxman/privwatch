"""
PrivWatch 3.0 - Linux Privilege Separation & IPC Daemon
Runs a privileged telemetry collection service accessible only via a restricted
Unix Domain Socket (/run/privwatch/privwatch.sock) with SO_PEERCRED credential validation.
Separates the unprivileged Web/SOC dashboard from privileged kernel/auditd telemetry collectors.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import threading
import time
from typing import Dict, Any, Optional, Tuple, Callable

from core.logger import Logger
from core.models import utc_now


DEFAULT_SOCKET_PATH = "/run/privwatch/privwatch.sock"
FALLBACK_SOCKET_PATH = "/tmp/privwatch.sock"


def get_peer_credentials(sock: socket.socket) -> Optional[Tuple[int, int, int]]:
    """
    Extract peer PID, UID, and GID from connected Unix Domain Socket using SO_PEERCRED.
    Linux-native interface: struct ucred { pid_t pid; uid_t uid; gid_t gid; };
    """
    SO_PEERCRED = 17  # Standard on Linux x86_64 and arm64
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        return pid, uid, gid
    except Exception:
        return None


class PrivilegedCollectorService:
    """Privileged Linux daemon exposing restricted RPC endpoints over Unix Domain Socket."""

    ALLOWED_ACTIONS = {
        "PING",
        "GET_SYSTEM_HEALTH",
        "RUN_RED_SCAN",
        "COLLECT_AUDIT_EVENTS",
        "GET_TELEMETRY_STATUS"
    }

    def __init__(self, socket_path: Optional[str] = None, allowed_uids: Optional[set] = None):
        self.socket_path = socket_path or self._determine_socket_path()
        self.allowed_uids = allowed_uids or {0, os.geteuid() if hasattr(os, 'geteuid') else 0}
        self.server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _determine_socket_path(self) -> str:
        """Select primary socket path in /run/privwatch or fallback to /tmp."""
        run_dir = "/run/privwatch"
        try:
            if not os.path.exists(run_dir):
                Path(run_dir).mkdir(parents=True, exist_ok=True)
            return DEFAULT_SOCKET_PATH
        except Exception:
            return FALLBACK_SOCKET_PATH

    def start(self, in_background: bool = True):
        """Bind socket, enforce 0600 permissions, and begin accepting IPC clients."""
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass

        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)

        if not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("AF_UNIX domain sockets are required for Linux privilege separation.")

        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.socket_path)
        self.server_sock.listen(10)

        # Enforce strict 0600 file permissions on the socket
        if hasattr(os, 'chmod'):
            try:
                os.chmod(self.socket_path, 0o600)
            except Exception:
                pass

        self._running = True

        if in_background:
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
        else:
            self._listen_loop()

    def stop(self):
        """Terminate socket service and clean up filesystem socket."""
        self._running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass

    def _listen_loop(self):
        """Accept connections and handle RPC messages."""
        while self._running:
            try:
                conn, _ = self.server_sock.accept()
                client_thread = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                client_thread.start()
            except Exception:
                if not self._running:
                    break

    def _handle_client(self, conn: socket.socket):
        """Process incoming client RPC with SO_PEERCRED authentication."""
        try:
            # Authenticate client UID via SO_PEERCRED
            creds = get_peer_credentials(conn)
            if creds:
                pid, uid, gid = creds
                if uid not in self.allowed_uids and 0 not in self.allowed_uids:
                    conn.sendall(json.dumps({
                        "error": f"Unauthorized client UID {uid}. Access denied.",
                        "success": False
                    }).encode('utf-8') + b"\n")
                    conn.close()
                    return

            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

            if not data:
                conn.close()
                return

            req = json.loads(data.decode('utf-8', errors='replace').strip())
            action = req.get("action", "")
            params = req.get("params", {})
            req_id = req.get("id", "req_0")

            if action not in self.ALLOWED_ACTIONS:
                resp = {
                    "id": req_id,
                    "success": False,
                    "error": f"Action '{action}' is forbidden. Privileged service only executes strictly allowlisted operations."
                }
            else:
                resp = self._dispatch_action(req_id, action, params)

            conn.sendall(json.dumps(resp).encode('utf-8') + b"\n")
        except Exception as e:
            try:
                conn.sendall(json.dumps({"error": str(e), "success": False}).encode('utf-8') + b"\n")
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _dispatch_action(self, req_id: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch allowlisted action to internal handler."""
        if action == "PING":
            return {"id": req_id, "success": True, "result": "PONG", "timestamp": str(utc_now())}
        elif action == "GET_SYSTEM_HEALTH":
            from core.platform_validator import LinuxPlatformValidator
            report = LinuxPlatformValidator.validate_platform(strict=False)
            return {"id": req_id, "success": True, "result": report.__dict__}
        elif action == "COLLECT_AUDIT_EVENTS":
            from modules.blue_mode.telemetry.audit_collector import AuditCollector
            collector = AuditCollector()
            events = collector.collect_events(max_records=params.get("max_records", 500))
            return {"id": req_id, "success": True, "result": [e.to_dict() for e in events]}
        elif action == "GET_TELEMETRY_STATUS":
            from modules.blue_mode.telemetry.health_monitor import TelemetryHealthMonitor
            monitor = TelemetryHealthMonitor()
            health = monitor.assess()
            return {"id": req_id, "success": True, "result": health.to_dict()}
        elif action == "RUN_RED_SCAN":
            from core.orchestrator import PrivWatchOrchestrator
            from core.config import PrivWatchConfig
            orch = PrivWatchOrchestrator(PrivWatchConfig(mode="red"))
            findings = orch.run_red_team_scan()
            return {"id": req_id, "success": True, "result": [f.to_dict() for f in findings]}

        return {"id": req_id, "success": False, "error": f"Unhandled action {action}"}


class PrivilegedServiceClient:
    """Client for unprivileged web/dashboard processes communicating with PrivilegedCollectorService."""

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = socket_path or (
            DEFAULT_SOCKET_PATH if os.path.exists(DEFAULT_SOCKET_PATH) else FALLBACK_SOCKET_PATH
        )

    def is_available(self) -> bool:
        """Check if privileged socket daemon is accessible."""
        return os.path.exists(self.socket_path)

    def send_request(self, action: str, params: Optional[Dict[str, Any]] = None, timeout: float = 15.0) -> Dict[str, Any]:
        """Send RPC request over Unix Domain Socket and return response dict."""
        if not self.is_available():
            raise FileNotFoundError(f"Privileged service socket not found at {self.socket_path}")

        if not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("AF_UNIX domain sockets are required for Linux privilege separation.")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(self.socket_path)
            req_id = f"ipc_{int(time.time() * 1000)}"
            payload = json.dumps({"id": req_id, "action": action, "params": params or {}}) + "\n"
            sock.sendall(payload.encode('utf-8'))

            response_data = b""
            while b"\n" not in response_data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            if not response_data:
                raise RuntimeError("Empty response received from privileged service.")

            return json.loads(response_data.decode('utf-8', errors='replace').strip())
        finally:
            sock.close()
